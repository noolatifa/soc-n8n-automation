# 03 — Docker Compose: The Two Stacks

> All server-side services run in containers on two VMs: the **VM SOC**
> (`pc1-soc`, `100.64.0.11`) and the **VM CTI** (`pc3-threat-intel`,
> `100.64.0.13`). 24 containers in total (10 + 14). Monitored endpoints
> (Suricata, Wazuh agents, iptables, Ansible target) stay **native** on their
> VMs by design.

---

## 1. VM SOC stack (`pc1-soc`)

Single Compose file (`~/wazuh-docker/single-node/docker-compose.yml`).

| Service | Image | Ports | Role |
|---|---|---|---|
| `wazuh.manager` | `wazuh/wazuh-manager:4.14.6` | 1514, 1515, 514/udp, 55000 | SIEM manager, Active Response, REST API |
| `wazuh.indexer` | `wazuh/wazuh-indexer:4.14.6` | 9200 | Alert indexing (OpenSearch) |
| `wazuh.dashboard` | `wazuh/wazuh-dashboard:4.14.6` | 443→5601 | Web UI |
| `postgres` | `postgres:16` | 5432 | n8n internal DB + `socdb` (alerts, pending_actions) |
| `n8n` | `docker.n8n.io/n8nio/n8n:latest` | 5678 | Workflow orchestration |
| `rabbitmq` | `rabbitmq:3-management` | 5672, 15672 | Message broker + management UI |
| `elasticsearch` | `elasticsearch:7.17.28` | 9201→9200 | Storage engine for TheHive/Cortex |
| `cassandra` | `cassandra:4.1` | — | TheHive storage |
| `thehive` | `strangebee/thehive:5.7` | 9002→9000 | Incident management |
| `cortex` | `thehiveproject/cortex:3.2.0-1` | 9005→9001 | Observable analysis |

### 1.1 Startup ordering & healthchecks

| Service | Condition | Mechanism |
|---|---|---|
| `n8n` | after `postgres` **healthy** | `pg_isready` |
| `thehive` | after `cassandra` + `elasticsearch` **healthy** | `nodetool status` (UN) / `_cluster/health` |
| `cortex` | after `elasticsearch` **healthy**, `thehive` **started** | same as above |
| `wazuh.dashboard` | after `wazuh.indexer` | — |

### 1.2 Configuration mounts (VM SOC)

- `./config/wazuh_cluster/wazuh_manager.conf` → `/wazuh-config-mount/etc/ossec.conf`
  (contains the `<active-response>` commands `block-ip600`, `block-port600`,
  `unblock-ip0`, `unblock-port0` and the Wazuh→n8n integration)
- `./config/thehive/application.conf`, `./config/cortex/application.conf`
- TLS material for manager/indexer/dashboard under `./config/wazuh_indexer_ssl_certs/`
- Named volumes for Active Response scripts: `wazuh_active_response`,
  `wazuh_integrations`

### 1.3 Persistence (named volumes)

`postgres_data`, `n8n_data`, `rabbitmq_data`, `elasticsearch_data`,
`cassandra_data`, `thehive_data`, `cortex_data`, `wazuh-indexer-data`,
plus the Wazuh/Filebeat volumes (`wazuh_etc`, `wazuh_logs`, `wazuh_queue`,
`wazuh_api_configuration`, `wazuh_var_multigroups`, `wazuh_agentless`,
`wazuh_wodles`, `filebeat_etc`, `filebeat_var`, `wazuh-dashboard-config`,
`wazuh-dashboard-custom`).

### 1.4 Environment (`.env`)

```bash
POSTGRES_USER=...      POSTGRES_PASSWORD=...      POSTGRES_DB=...
RABBITMQ_USER=...      RABBITMQ_PASSWORD=...
N8N_USER=...           N8N_PASSWORD=...           N8N_HOST=...  TZ=...
```

Values are masked in this repository (`.env.example` only).

---

## 2. VM CTI stack (`pc3-threat-intel`)

Single Compose file (`/opt/threat-intel/docker-compose.yml`) on an internal
bridge network `threat-intel-net` (`172.21.0.0/16`).

| Service | Image | Ports | Role |
|---|---|---|---|
| `db` | `mariadb:10.11` | — | MISP database |
| `redis` | `redis:7-alpine` | — | MISP cache |
| `misp-modules` | `ghcr.io/misp/misp-docker/misp-modules:latest` | — | MISP expansion modules |
| `misp-core` | `ghcr.io/misp/misp-docker/misp-core:latest` | 80, 443 | MISP application |
| `opencti-redis` | `redis:7-alpine` | — | OpenCTI cache |
| `opencti-elasticsearch` | `elasticsearch:8.17.6` | 9200 | OpenCTI search engine |
| `opencti-minio` | `minio/minio:latest` | — | Object storage |
| `opencti-rabbitmq` | `rabbitmq:4.1-management` | 15672 | OpenCTI internal bus |
| `opencti-postgres` | `postgres:16-alpine` | — | OpenCTI database |
| `opencti` | `opencti/platform:6.6.13` | 8080 | OpenCTI platform (GraphQL API) |
| `opencti-worker` | `opencti/worker:6.6.13` | — | Async processing |
| `connector-misp` | `opencti/connector-misp:6.6.13` | — | MISP → OpenCTI import (every 30 min) |
| `connector-mitre` | `opencti/connector-mitre:6.6.13` | — | MITRE ATT&CK reference (every 7 days) |
| `connector-abuseipdb-ipblacklist` | `opencti/connector-abuseipdb-ipblacklist:6.6.13` | — | AbuseIPDB blacklist |

### 2.1 Connector tuning (AbuseIPDB)

- score ≥ **75**
- limit **1000** IPs per run
- interval **2 days**

### 2.2 Bind-mounted data (VM CTI)

`/opt/threat-intel/mysql-data`, `redis-data`, `opencti-elasticsearch`,
`opencti-minio`, `opencti-rabbitmq`, `opencti-data` (Postgres).

---

## 3. Operations

```bash
# VM SOC
cd ~/wazuh-docker/single-node
docker compose up -d
docker compose ps          # all services Up / healthy
docker compose logs -f n8n

# VM CTI
cd /opt/threat-intel
docker compose up -d
docker compose ps
```

Post-startup probes:

```bash
curl -sk https://100.64.0.11/            # Wazuh Dashboard (443)
curl -s  http://100.64.0.11:5678         # n8n
curl -s  http://100.64.0.11:15672        # RabbitMQ Management
curl -sk https://100.64.0.13/            # MISP
curl -s  http://100.64.0.13:8080         # OpenCTI
```