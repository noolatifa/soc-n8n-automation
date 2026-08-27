# 02 — Tailscale Network: Addressing Plan & Flow Matrix

> All nodes of the platform are **virtual machines** interconnected through a
> Tailscale overlay network. Hostnames keep a `pc-*` prefix for historical
> reasons; every node listed below is a VM.

---

## 1. Why Tailscale

- **Encrypted mesh** (WireGuard): end-to-end encryption between all nodes.
- **Flat addressing** in the `100.64.0.0/10` CGNAT range, independent from the
  underlying physical network (`192.168.239.0/24`).
- **Centralized authentication**: node identity is managed by the Tailscale
  control plane, not by per-host SSH keys.
- **Elastic topology**: VMs can be added or removed without re-addressing the
  rest of the platform.

---

## 2. Addressing plan

| VM | Hostname | Tailscale IP | Role |
|---|---|---|---|
| VM SOC | `pc1-soc` | `100.64.0.11` | Wazuh, n8n, RabbitMQ, PostgreSQL, TheHive, Cortex, Ansible |
| VM CTI | `pc3-threat-intel` | `100.64.0.13` | MISP, OpenCTI + MISP/MITRE/AbuseIPDB connectors |
| Monitored VM (Linux) | `vulnerable-machine-linux` | `100.64.0.20` | Wazuh agent, Suricata, iptables (Active Response target) |
| Monitored VM (Windows) | — | internal | Wazuh agent + Sysmon |
| VM AI | `pc-windows-ai` | `100.64.0.14` | AI qualification API (`:8000/qualifier-alerte`) |

On the VM CTI, containers additionally sit on an internal Docker bridge network
`threat-intel-net` (`172.21.0.0/16`), not exposed outside the VM.

---

## 3. Flow matrix

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| Wazuh agents (monitored VMs) | VM SOC (`wazuh.manager`) | 1514, 1515 | TCP | Event upload + agent enrollment |
| Monitored VMs (Syslog) | VM SOC | 514 | UDP | Syslog ingestion |
| Wazuh Manager | VM SOC (n8n webhook `wazuh-alerts`) | 5678 | HTTP | Alert push to n8n |
| n8n | VM SOC (RabbitMQ) | 5672 | AMQP | Publish/consume `wazuh-enriched-alerts` |
| n8n | VM CTI (MISP) | 443 | HTTPS | IOC push (`/events/add`) |
| n8n | VM CTI (OpenCTI) | 8080 | HTTP | GraphQL lookup (`stixCyberObservables`) |
| n8n | VM AI (FastAPI) | 8000 | HTTP | `POST /qualifier-alerte` |
| n8n | VM SOC (TheHive) | 9000 | HTTP | Case create / update / close |
| n8n | VM SOC (Wazuh API) | 55000 | HTTPS | Token + Active Response triggers |
| n8n | VM SOC (PostgreSQL) | 5432 | TCP | `alerts` / `pending_actions` reads & writes |
| n8n (SSH node) | VM SOC host | 22 | SSH | Run `ansible-playbook` (forensics) |
| Ansible (VM SOC) | Monitored VMs | 22 | SSH | Forensics collection (`collect_forensics.yml`) |
| Dashboard access | VM SOC (PostgreSQL) | 5432 | TCP | Read-only (`dashboard_ro`), restricted (see §4) |
| Operators | VM SOC (RabbitMQ Mgmt) | 15672 | HTTP | Queue observability |

---

## 4. Host-level filtering (UFW)

Tailscale encrypts and authenticates the mesh; host firewalls add a second,
per-service layer. Example — PostgreSQL is **not** open to the whole mesh, only
to the VM that needs read access:

```bash
# On VM SOC (100.64.0.11)
sudo ufw allow from 100.64.0.14 to any port 5432 proto tcp
sudo ufw status
```

Combined with the `dashboard_ro` database user (`GRANT SELECT` only), this
gives a least-privilege read path for dashboards without exposing writes.

---

## 5. Validation commands

```bash
# Mesh health (any VM)
tailscale status

# Reachability between VMs
ping -c 2 100.64.0.11   # VM SOC
ping -c 2 100.64.0.13   # VM CTI
ping -c 2 100.64.0.20   # monitored VM (Linux)
ping -c 2 100.64.0.14   # VM AI

# Service-level check from VM SOC
curl -s http://100.64.0.13:8080/graphql -o /dev/null -w "%{http_code}\n"
curl -s http://100.64.0.14:8000/docs -o /dev/null -w "%{http_code}\n"
```

Expected: all pings answer on the Tailscale IPs, and the two `curl` probes
return HTTP 200.