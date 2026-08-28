# 07 — n8n Workflow: The 42-Node Orchestration

> The workflow `version-rapport` is the orchestration core of the platform.
> It runs on the **VM SOC** (`pc1-soc`, `100.64.0.11`, port `5678`) and
> implements the full alert lifecycle — from Wazuh webhook reception to
> Active Response execution and rollback.
>
> The workflow JSON is shipped in the repository at
> `n8n/version-rapport.json` and can be imported directly into any n8n
> instance (UI → Workflows → Import from File).

---

## 1. Global structure — 7 logical blocks

| Block | Purpose | Trigger | Output |
|---|---|---|---|
| **B1 — Ingestion** | receive alert, assign `correlation_id`, persist, push to queue | webhook `wazuh-alerts` | message in `wazuh-enriched-alerts` + row in `alerts` |
| **B2 — CTI enrichment** | push IOCs to MISP, lookup OpenCTI | RabbitMQ Trigger | enriched context for the IA |
| **B3 — Reconciliation** | read pending pre-blocks by `correlation_id` | after B5 | reconciliation decision (confirm / rollback / none) |
| **B4 — Fast path** | pre-block IP and/or port when level ≥ 12 | extracted alert | `block-ip600` / `block-port600` + pending action |
| **B5 — IA decision** | call the AI layer (VM AI) | enriched context | structured JSON verdict |
| **B6 — Confirm / rollback** | act on the IA verdict | reconciliation | confirm / rollback / no-op |
| **B7 — IA actions + forensics** | execute IA-decided blocks and collect evidence | decision + traceability | iptables rule + `/tmp/evidence_<epoch>/` |

The workflow handles **parallel fast + slow paths**: a critical alert
triggers B4 immediately (pre-blocking) **and** B2/B5 concurrently (full
analysis), which then meet at B3 for reconciliation.

---

## 2. Credentials required

The workflow expects the following n8n credentials to be configured before
activation:

| Credential type | Purpose |
|---|---|
| `httpBasicAuth` | Wazuh Manager REST API (`100.64.0.11:55000`) — used by every `Get Wazuh Token*` node |
| `rabbitmq` | RabbitMQ AMQP (`100.64.0.11:5672`) |
| `postgres` | PostgreSQL `socdb` (`100.64.0.11:5432`) |
| `sshPrivateKey` (`id_n8n`) | SSH to VM SOC for Ansible playbook execution |
| TheHive bearer token | case create / update / close on `100.64.0.11:9000` |
| MISP bearer token | IOC push to `100.64.0.13:443` |
| OpenCTI bearer token | GraphQL lookup on `100.64.0.13:8080` |

No credential is shipped in the repository (`.env.example` + n8n UI
configuration only).

---

## 3. Block B1 — Ingestion

| Node | Type | Role |
|---|---|---|
| `wazuh-alerts` | Webhook | Receives alert JSON from Wazuh Manager (level ≥ 6) |
| `RabbitMQ` | RabbitMQ | Publishes to durable queue `wazuh-enriched-alerts` |
| `RabbitMQ Trigger` | RabbitMQ Trigger | Consumes the queue (sequential, `parallelMessages: 1`) |
| `Extract Alert` | Code | Normalizes the payload (handles Wazuh variations) and assigns a `correlation_id` |
| `Alerts - Insert` | PostgreSQL | `INSERT INTO alerts ... ON CONFLICT (correlation_id) DO NOTHING` |

Key JavaScript snippet — `Extract Alert` (robust parsing + correlation_id):

```js
let payload = raw;
if (raw.body && raw.body.rule)           payload = raw.body;
else if (raw.rule)                       payload = raw;
else if (raw.message && raw.message.rule) payload = raw.message;
else if (typeof raw.message === 'string') {
  try { payload = JSON.parse(raw.message); } catch (e) {}
}

payload.correlation_id = payload.correlation_id
  || (Date.now() + '-' + Math.random().toString(36).substring(2, 10));

return [{ json: { body: payload } }];
```

The `correlation_id` is the red thread of traceability: it travels through
every downstream node and is persisted in both `alerts` and
`pending_actions` (see [10-postgresql.md](10-postgresql.md)).

---

## 4. Block B2 — CTI enrichment

Runs in parallel with B4 (fast path) on the extracted alert:

| Node | Type | Role |
|---|---|---|
| `HTTP Request misp` | HTTP POST | Pushes IOCs (`ip-src`, `ip-dst`, full log) to `100.64.0.13:443/events/add` |
| `HTTP Request opencti` | HTTP POST | GraphQL query on `100.64.0.13:8080/graphql` for `stixCyberObservables` |
| `Merge` | Merge | Joins MISP and OpenCTI responses |
| `Code` (consolidation) | Code | Produces `wazuh_alert`, `threat_intelligence`, `correlation_summary` |

Consolidation logic (excerpt):

```js
const totalMatches = (mispData.attributes?.length || 0)
                   + (openctiData.indicators?.length || 0);
let preliminary_verdict = totalMatches > 0 ? "intel_found" : "no_intel";
```

The enriched payload is forwarded both to the AI layer (B5) and to the
fast-path evaluation (B4).

---

## 5. Block B3 — Reconciliation

| Node | Type | Role |
|---|---|---|
| `Postgres - Lookup Pending Actions` | PostgreSQL | `SELECT * FROM pending_actions WHERE correlation_id = $1 AND status = 'pending'` |
| `Reconciliation Logic` | Code | Decides confirm / rollback / no-op **per action** |

**Critical setting**: the `Reconciliation Logic` node runs in
**Run Once for All Items** mode (not the default `Each Item`). This
allows it to see all pending rows of a single alert at once and take an
independent decision per action (e.g. confirm the IP block but rollback
the port block on the same alert).

Reconciliation logic (excerpt):

```js
const texte = `${ai.verdict || ''} ${ai.classification || ''} ${ai.recommendation || ''}`.toLowerCase();
const isFalsePositive =
  texte.includes('false_positive') || texte.includes('false positive') ||
  texte.includes('faux positif')   || texte.includes('legitimate');

return pendingRows.map(row => ({
  json: {
    ...combineResult,
    has_pending_action: true,
    pending_action: row,
    reconciliation_decision: isFalsePositive ? 'rollback' : 'confirm'
  }
}));
```

---

## 6. Block B4 — Fast path (pre-blocking)

Two parallel sub-branches handle IP and port:

### 6.1 IP branch
| Node | Role |
|---|---|
| `IF - Critical Rule Level (>=12)` | gate: level ≥ 12 |
| `Build Preemptive Action` | prepare AR payload (`block-ip600`) |
| `Get Wazuh Token` | Bearer token for Wazuh API |
| `Wazuh Active Response - Block IP` | `PUT /active-response` → agent executes `block-ip.sh` |
| `Create Hive Case - Provisional` | TheHive case tagged `pending-ai-review` |
| `Postgres - Insert Pending Action` | row with `status = pending` |

### 6.2 Port branch
| Node | Role |
|---|---|
| `Check Port Criticality` | tests `ruleLevel ≥ 12 && dstPort ∈ critical list` (22, 23, 445, 3389, 5432, 6379, 9200, 27017…) |
| `IF - Critical Port (Level>=12 AND Port Critical)` | gate |
| `Build Preemptive Port Action` | prepare `block-port600`, target stored as `ip:port` |
| `Get Wazuh Token (Port)` | Bearer token |
| `Wazuh Active Response - Block Port` | `PUT /active-response` → agent executes `block-port.sh` |
| `Create Hive Case - Provisional (Port)` | TheHive case |
| `Postgres - Insert Pending Port Action` | row `BLOCK_PORT`, `status = pending` |

A single alert can thus create **two** pending rows thanks to the
`UNIQUE(correlation_id, action_type)` constraint on `pending_actions`.

---

## 7. Block B5 — IA decision

| Node | Type | Role |
|---|---|---|
| `HTTP Request llama` | HTTP POST | Calls `http://100.64.0.14:8000/qualifier-alerte` (VM AI) |
| `Combine Result` | Code | Parses the JSON verdict (tolerant of markdown fences) |
| `Routeur Agent IA` | Code | Converts the IA verdict into an executable actions array |
| `Switch décision IA` | Switch | Routes to the right downstream branch |

The AI layer (VM AI, `100.64.0.14`) is **out of scope** of this
repository — it only exposes the synchronous endpoint above and returns a
structured verdict:

```json
{
  "classification": "Critical",
  "attack_type": "SSH Brute Force",
  "mitre_tactic": "T1110",
  "confidence_score": 95,
  "reasoning": "...",
  "automated_action": {
    "execute": true,
    "actions": [
      { "action_type": "BLOCK_IP",   "target": "198.51.100.55" },
      { "action_type": "BLOCK_PORT", "target": "198.51.100.55", "port": 22 }
    ]
  }
}
```

The `Routeur Agent IA` node normalizes both the new `actions[]` format and
the legacy single `action_type` for backward compatibility.

---

## 8. Block B6 — Confirm / rollback

After `IF - Was Preemptive Action Taken` and
`Switch - AI Verdict on Preemptive Action`:

### 8.1 Confirm branch
| Node | Role |
|---|---|
| `Postgres - Mark Confirmed` | `UPDATE pending_actions SET status='confirmed', confirmed_at=NOW()` |
| `Hive - Update Case (Confirmed)` | adds tag `confirmed-by-ai` to the provisional case |
| `Run Forensics Playbook` | Ansible SSH → `collect_forensics.yml` (see [09](09-ansible-forensics.md)) |

### 8.2 Rollback branch
| Node | Role |
|---|---|
| `Build Rollback AR Payload` | picks the right command: `unblock-ip0` or `unblock-port0` (parsed from `ip:port` target) |
| `Get Wazuh Token2` | Bearer token |
| `Wazuh Active Response - Unblock (Rollback)` | `PUT /active-response` → agent executes the unblock script |
| `Postgres - Mark Rolled Back` | `UPDATE pending_actions SET status='rolled_back', rollback_reason='AI verdict: false positive'` |
| `Hive - Close Case (False Positive)` | closes TheHive case with `resolutionStatus=FalsePositive`, tag `rolled-back` |

Rollback payload builder (excerpt):

```js
if (row.action_type === 'BLOCK_PORT') {
  const [ip, port] = String(row.target).split(':');
  command = 'unblock-port0';
  args    = [ip, port];
} else {
  command = 'unblock-ip0';
  args    = [row.target];
}
```

---

## 9. Block B7 — IA actions + forensics

When the AI verdict recommends a block and **no pre-emptive action was
taken** (slow path), B7 applies the action fresh:

| Node | Role |
|---|---|
| `IF - AI Decided Block IP` | gate on `actions_to_execute[].type === 'block_ip'` |
| `Get Wazuh Token1` | Bearer token |
| `Wazuh Active Response - Block IP1` | AR call (`block-ip600`) |
| `Alerts - Log AI Block IP` | appends `AI_BLOCK:<ip> \| HIVE_CASE:<id>` to `alerts.action_executed` |
| `IF - AI Decided Block Port` | gate on `actions_to_execute[].type === 'block_port'` |
| `Get Wazuh Token (Port AI)` | Bearer token |
| `Wazuh Active Response - Block Port1` | AR call (`block-port600`) |
| `Alerts - Log AI Block Port` | appends `AI_BLOCK_PORT:<ip>:<port> \| HIVE_CASE:<id>` |
| `Run Forensics Playbook1` | Ansible SSH, **after** the traceability nodes |

The forensics nodes are deliberately placed **after** the
`Alerts - Log AI Block IP/Port` nodes: this guarantees the global state
is stable before evidence collection begins (see
[09-ansible-forensics.md](09-ansible-forensics.md)).

---

## 10. Queue configuration — sequential processing

The RabbitMQ Trigger node sets `parallelMessages: 1`. Consequence:
alerts are processed **one at a time**, which avoids:

- concurrent writes to `pending_actions` and `alerts`;
- race conditions between a block and a rollback on the same IP;
- duplicate executions of the Active Response scripts.

The upstream RabbitMQ queue (`wazuh-enriched-alerts`) absorbs bursts
during attacks; the downstream sequential processing preserves data
integrity.

---

## 11. Validation

After import:

1. Configure the credentials (see §2).
2. Activate the workflow.
3. Send a test payload:

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<id> \
  -H 'Content-Type: application/json' \
  -d @tests/scenarios/scenario1-level15.json
```

Expected execution trace in n8n:

- B1: webhook → RabbitMQ → Trigger → `Alerts - Insert` ✓
- B4 (fast path): `IF - Critical Rule Level` → `Wazuh AR - Block IP` + `Insert Pending Action` ✓
- B2 + B5: MISP/OpenCTI + IA call in parallel ✓
- B3: `Lookup Pending Actions` → `Reconciliation Logic` (1 row) ✓
- B6: `Mark Confirmed` + `Hive - Update Case` + `Run Forensics Playbook` ✓

Full scenario matrix: [11-tests-validation.md](11-tests-validation.md).