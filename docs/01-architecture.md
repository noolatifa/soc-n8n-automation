# 01 — Global Architecture

> **Repository scope**: SOC infrastructure, detection (Suricata / Sysmon), SIEM (Wazuh),
> orchestration (n8n), automated response (Active Response + rollback), forensics
> (Ansible) and the PostgreSQL data model.
>
> The AI layer (qualification API `/qualifier-alerte`, Ollama model, dashboard) is
> developed and documented separately. **This repository contains no AI code.**

---

## 1. VM topology

The platform runs on **five virtual machines** interconnected through a Tailscale
overlay network. The work was carried out as two independent workstreams on
separate VMs: the SOAR infrastructure (VMs SOC, CTI and monitored endpoints) on
one side, and the AI layer (VM AI) on the other.

| VM | Hostname | Tailscale IP | Role | Stack |
|---|---|---|---|---|
| VM SOC | `pc1-soc` | `100.64.0.11` | Central orchestration | Docker: Wazuh, n8n, RabbitMQ, PostgreSQL, TheHive, Cortex |
| VM CTI | `pc3-threat-intel` | `100.64.0.13` | Threat intelligence | Docker: MISP, OpenCTI + MISP/MITRE/AbuseIPDB connectors |
| Monitored VM (Linux) | `vulnerable-machine-linux` | `100.64.0.20` | Monitored endpoint | Wazuh agent, Suricata, iptables |
| Monitored VM (Windows) | — | — | Monitored endpoint | Wazuh agent + Sysmon |
| VM AI | `pc-windows-ai` | `100.64.0.14` | AI layer (out of scope) | FastAPI, Ollama, Flask, Redis |

```
[monitored VM Linux]  Suricata + Wazuh agent ──1514──► [VM SOC] Wazuh Manager
[monitored VM Win.]   Sysmon   + Wazuh agent ──1514──►        │ webhook
                                                              ▼
[VM CTI] MISP / OpenCTI ◄──443/8080── n8n (42 nodes) ──► RabbitMQ
                                                              │
                  Fast path (level ≥ 12) ─ block-ip600 / block-port600
                  AI reconciliation      ─ confirm / rollback (unblock-ip0 / unblock-port0)
                  Forensics              ─ Ansible SSH → /tmp/evidence_<epoch>/
                                                              │
                                                              ▼
                           PostgreSQL (alerts, pending_actions) + TheHive
                                                              ▲
[VM AI] FastAPI :8000 ── AI verdict ──────────────────────────┘
```

---

## 2. Alert lifecycle — the 7 logical blocks of the n8n workflow

| Block | Purpose | Key n8n nodes |
|---|---|---|
| **B1 — Ingestion** | webhook → queue → trigger → extraction + `correlation_id` + insert into `alerts` | `wazuh-alerts`, `RabbitMQ`, `RabbitMQ Trigger`, `Extract Alert`, `Alerts - Insert` |
| **B2 — CTI enrichment** | push IOCs to MISP + lookup OpenCTI in parallel | `HTTP Request misp` (`/events/add`), `HTTP Request opencti` (GraphQL), `Merge`, `Code` |
| **B3 — Reconciliation** | read `pending` actions by `correlation_id` | `Postgres - Lookup Pending Actions`, `Reconciliation Logic` (**Run Once for All Items**) |
| **B4 — Fast path** | immediate blocking when level ≥ 12 (IP) and/or critical port | `IF - Critical Rule Level (>=12)`, `Check Port Criticality`, `Build Preemptive (Port) Action`, `Wazuh AR - Block IP/Port`, `Create Hive Case - Provisional`, `Insert Pending (Port) Action` |
| **B5 — AI decision** | structured verdict from the AI layer | `HTTP Request llama` → `100.64.0.14:8000/qualifier-alerte`, `Combine Result`, `Routeur Agent IA`, `Switch décision IA` |
| **B6 — Confirm / rollback** | confirm or actually undo the blocks | `Switch - AI Verdict`, `Mark Confirmed`, `Build Rollback AR Payload`, `AR - Unblock`, `Mark Rolled Back`, `Hive - Close Case (False Positive)` |
| **B7 — AI actions + forensics** | AI-decided blocks + evidence collection | `IF - AI Decided Block IP/Port`, `Alerts - Log AI Block IP/Port`, `Run Forensics Playbook(1)` |

Full node-by-node description: [07-n8n-workflow.md](07-n8n-workflow.md).

---

## 3. Repository scope

| Layer | Repository |
|---|---|
| Docker Compose stacks (VM SOC + VM CTI) | **this repository** |
| Wazuh (manager, agents, rules, Active Response) | **this repository** |
| Suricata / Sysmon | **this repository** |
| n8n workflow (42 nodes) | **this repository** |
| PostgreSQL `socdb` + `dashboard_ro` | **this repository** |
| Ansible forensics | **this repository** |
| AI API / Dual-Engine / dashboard | separate AI repository |

---

## 4. Documentation index

| Doc | Subject |
|---|---|
| [02](02-reseau-tailscale.md) | Tailscale network, addressing plan, flow matrix |
| [03](03-docker-compose.md) | The two Docker stacks (VM SOC + VM CTI) |
| [04](04-wazuh.md) | Manager, agents, rules, Wazuh → n8n integration |
| [05](05-suricata.md) | Suricata NIDS: install, config, custom rules |
| [06](06-sysmon-windows.md) | Windows agent + Sysmon |
| [07](07-n8n-workflow.md) | The 42-node workflow, blocks B1–B7 |
| [08](08-wazuh-n8n-integration.md) | Custom Wazuh → n8n integration script |
| [09](09-active-response.md) | block/unblock IP+port scripts, rollback |
| [10](10-ansible-forensics.md) | Playbook, sudoers, SSH nodes |
| [11](11-postgresql.md) | Schema, constraints, `dashboard_ro` |
| [12](12-tests-validation.md) | curl scenarios + proofs |