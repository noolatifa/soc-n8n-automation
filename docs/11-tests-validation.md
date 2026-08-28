# 11 — Validation: Scenarios, curl Injection & Multi-Source Proofs

> The platform was validated through controlled, reproducible tests. Rather
> than launching real attacks (which introduces randomness and
> non-reproducibility), JSON payloads are injected directly into the n8n
> webhook via `curl`. This gives total control over the alert fields (level,
> source IP, port, description) and allows any scenario to be replayed
> identically at any time.

---

## 1. Methodology

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<webhook-id> \
  -H 'Content-Type: application/json' \
  -d '<payload>'
```

The injected payload mimics exactly what the Wazuh Manager would push to the
webhook for a real alert above level 6. From that point, the entire pipeline
runs (RabbitMQ, CTI enrichment, IA, Active Response, PostgreSQL, TheHive).

Proofs are collected from **five independent sources**:
1. `iptables -L INPUT -n` on the monitored VM (firewall state)
2. `/var/log/auth.log` on the monitored VM (system-level sudo trace)
3. `/var/ossec/logs/active-responses.log` (Wazuh agent trace)
4. PostgreSQL `alerts` / `pending_actions` tables
5. TheHive cases (open / closed / rolled back)

This multi-source traceability guarantees that an action cannot be "claimed"
by one layer without being confirmed by the others.

---

## 2. Scenario 1 — Slow flow, medium-severity alert (level 9)

**Goal**: validate the full pipeline (CTI → IA → decision → action) for a
non-critical alert that does not trigger the Fast Path.

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<webhook-id> \
  -H 'Content-Type: application/json' \
  -d '{
    "alert": {
      "id": "slow-flow-test-001",
      "rule": {
        "id": "5712",
        "level": 9,
        "description": "SSHD: brute force attack"
      },
      "data": { "srcip": "12.13.14.15" },
      "agent": { "id": "005", "name": "vulnerable-machine-linux" },
      "timestamp": "2026-08-13T18:00:00.000Z"
    }
  }'
```

**Expected**: no pre-blocking (level < 12). Full analysis by the IA layer,
followed by an IA-decided action (if any) and a TheHive case.

**Proofs**: `alerts` row with `ai_classification` populated;
`pending_actions` row with `status = confirmed` (if the IA recommended a
block); TheHive case tagged `confirmed-by-ai`.

---

## 3. Scenario 2 — Fast Path, critical alert (level 15) with port

**Goal**: validate the Fast Path pre-blocking on both IP **and** port, and the
subsequent IA confirmation.

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<webhook-id> \
  -H 'Content-Type: application/json' \
  -d '{
    "alert": {
      "id": "manual-block-test-002",
      "rule": {
        "id": "5712",
        "level": 15,
        "description": "SSH brute force attempt from port 54321 to port 22"
      },
      "data": {
        "srcip": "203.0.113.99",
        "srcport": 54321,
        "dstport": 22
      },
      "agent": { "id": "005", "name": "vulnerable-machine-linux" },
      "timestamp": "2026-08-12T17:00:00.000Z"
    }
  }'
```

**Expected (in less than 1 second)**:
- `iptables -I INPUT -s 203.0.113.99 -j DROP`
- `iptables -I INPUT -s 203.0.113.99 -p tcp --dport 22 -j DROP`
- Two rows in `pending_actions` with `status = pending`, same `correlation_id`

**Then (after IA analysis)**: the IA confirms, both rows move to
`status = confirmed`, the TheHive case is tagged `confirmed-by-ai`, and the
Ansible forensics playbook runs.

**Proofs**:
```bash
# On the monitored VM
sudo iptables -L INPUT -n | grep 203.0.113.99
# DROP all -- 203.0.113.99 0.0.0.0/0
# DROP tcp -- 203.0.113.99 0.0.0.0/0 tcp dpt:22

sudo grep "iptables -I" /var/log/auth.log | tail -5
```

```sql
-- On the VM SOC
SELECT a.correlation_id, a.src_ip, p.action_type, p.target, p.status
FROM alerts a
JOIN pending_actions p ON p.correlation_id = a.correlation_id
WHERE a.src_ip = '203.0.113.99';
-- → 2 rows, both confirmed
```

---

## 4. Scenario 3 — IP-only block

Same structure as Scenario 2 but with a description that targets only the IP
(no specific port). Result: one `BLOCK_IP` row in `pending_actions`, one
`iptables` rule, one TheHive case.

---

## 5. Scenario 4 — Port-only block

An alert where the IP is otherwise legitimate but a single service is
abused. Result: one `BLOCK_PORT` row with `target = <ip>:<port>`, one
targeted `iptables` rule. The rest of the traffic from that IP is unaffected.

---

## 6. Scenario 5 — Correlated multi-action on one alert

The payload of Scenario 2 is reused. The `UNIQUE(correlation_id, action_type)`
constraint on `pending_actions` allows **two** different action types for the
same alert, while forbidding duplicates of the same type.

```sql
SELECT a.correlation_id, a.src_ip, p.action_type, p.target, p.status
FROM alerts a
JOIN pending_actions p ON p.correlation_id = a.correlation_id
WHERE a.correlation_id = '<id-from-scenario-2>';
```

Result:

```text
 correlation_id            | src_ip         | action_type | target              | status
---------------------------+----------------+-------------+---------------------+-----------
 1787081965919-jzup6nri    | 203.0.113.99   | BLOCK_IP    | 203.0.113.99        | confirmed
 1787081965919-jzup6nri    | 203.0.113.99   | BLOCK_PORT  | 203.0.113.99:22     | confirmed
```

This is the concrete proof that the correlation mechanism scales correctly
to multi-action alerts.

---

## 7. Scenario 6 — False positive & rollback (triple proof)

**Goal**: trigger a pre-block via the Fast Path, then have the IA classify the
alert as a false positive, and verify that the block is **actually removed**
at all four levels.

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<webhook-id> \
  -H 'Content-Type: application/json' \
  -d '{
    "alert": {
      "rule": {
        "id": "100002",
        "level": 15,
        "description": "Authorized Vulnerability Scanner (Qualys) from internal IT department"
      },
      "data": { "srcip": "10.0.0.50" },
      "agent": { "id": "005", "name": "vulnerable-machine-linux" },
      "timestamp": "2026-08-12T14:00:00.000Z"
    }
  }'
```

The Fast Path immediately blocks `10.0.0.50`. The IA then classifies the
alert as a false positive (legitimate internal scanner). The rollback branch
fires.

### Four independent proofs

**Proof 1 — PostgreSQL**:
```sql
SELECT status, rollback_reason, rolled_back_at
FROM pending_actions
WHERE target = '10.0.0.50' ORDER BY id DESC LIMIT 1;
-- status = rolled_back
-- rollback_reason = AI verdict: false positive
```

**Proof 2 — System journal** (on the monitored VM):
```bash
sudo grep "iptables -D" /var/log/auth.log | tail -1
# COMMAND=/usr/sbin/iptables -D INPUT -s 10.0.0.50 -j DROP
```

**Proof 3 — TheHive**:
```bash
curl -X GET "http://100.64.0.11:9002/api/v1/case/<case-id>" \
  -H "Authorization: Bearer <thehive-token>"
# status = Resolved
# resolutionStatus = FalsePositive
# tags contain "rolled-back"
```

**Proof 4 — iptables** (on the monitored VM):
```bash
sudo iptables -L INPUT -n | grep 10.0.0.50
# (no output — rule is gone)
```

The rollback is considered complete only when **all four proofs agree**. Any
disagreement triggers a manual-alert tag on the TheHive case.

---

## 8. Multi-source traceability — what is validated

Across all six scenarios, the following redundancy is confirmed:

| Source | What it records |
|---|---|
| Wazuh agent logs (`active-responses.log`) | script invocation + parameters |
| Wazuh Manager logs | centralized AR journal |
| System journal (`auth.log`) | sudo invocation of `iptables` (independent of the app) |
| PostgreSQL `pending_actions` | action state machine (`pending` → `confirmed` / `rolled_back`) |
| PostgreSQL `alerts` | alert history + IA verdict + executed action |
| TheHive | case lifecycle (Open → InProgress → Resolved + `resolutionStatus`) |
| `dashboard_ro` user (read-only) | independent audit read path |

This deliberate redundancy guarantees that the state of any alert can be
reconstructed from **any** source, even if one layer fails.

---

## 9. Reproducibility

Every scenario in this document can be replayed with the exact same `curl`
command. The same `correlation_id` mechanism prevents a replay from
duplicating rows in `alerts` (UNIQUE constraint), while still exercising the
entire downstream pipeline. This makes the test suite safe to run as a
regression check after any workflow evolution.

## 10. Beyond curl: real attacks produce the same result

The `curl` payloads shown throughout this document were used to test and
validate the n8n workflow in a controlled, reproducible way. However, the
platform reacts identically to **real** attacks: a genuine Nmap scan, an
actual SSH brute force, or a real Sysmon-detected reverse shell will
generate the same Suricata EVE / Wazuh alert, flow through the same webhook,
be queued in the same RabbitMQ topic, be enriched by the same CTI sources,
be classified by the same Dual-Engine, and ultimately trigger the same
Active Response + rollback chain.

The curl-based testing methodology was chosen for the documentation because
it guarantees reproducibility; it does not imply any limitation of the
platform itself.