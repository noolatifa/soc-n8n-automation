# 04 — Wazuh: SIEM, Agents & Wazuh → n8n Integration

> Wazuh 4.14.6 runs on the **VM SOC** (`pc1-soc`, `100.64.0.11`) as three
> containers: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`.
> Agents are installed **natively** on the monitored VMs.

---

## 1. Stack on the VM SOC

| Container | Ports | Role |
|---|---|---|
| `wazuh.manager` | 1514 (events), 1515 (enrollment), 514/udp (syslog), 55000 (REST API) | Analysis, correlation, Active Response |
| `wazuh.indexer` | 9200 | Alert indexing (OpenSearch) |
| `wazuh.dashboard` | 443 → 5601 | Web UI |

The manager configuration is mounted from the host:
`./config/wazuh_cluster/wazuh_manager.conf` → `/wazuh-config-mount/etc/ossec.conf`.
It contains the `<active-response>` commands (see §5) and the alert forwarding
integration (see §4).

---

## 2. Agents

### 2.1 Linux agent (monitored VM, `100.64.0.20`)

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
WAZUH_MANAGER="100.64.0.11" sudo apt-get install -y wazuh-agent
sudo systemctl enable wazuh-agent --now
```

Enabled modules: log collector, **FIM (syscheck)**, rootcheck, Active Response,
and Suricata EVE ingestion via:

```xml
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```

### 2.2 Windows agent (monitored VM)

 2.2 Windows agent (monitored VM, `100.64.0.21`), plus Sysmon ingestion:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Enrollment uses port **1515**; ongoing communication uses port **1514**.

---

## 3. Rules & alert levels

- Wazuh scores every event from **0 to 15**.
- Forwarding threshold to n8n: **level ≥ 6** (low-noise events never enter the pipeline).
- **10–11**: priority analysis. **12–15**: critical → Fast Path pre-blocking
  (see [08-active-response.md](08-active-response.md)).
- Suricata EVE events and Sysmon events are decoded by dedicated rule sets;
  custom rules live in `local_rules.xml` on the manager.

---

## 4. Wazuh → n8n integration

Each alert above the threshold is pushed as JSON to the n8n webhook
`wazuh-alerts` (`http://100.64.0.11:5678/webhook/<id>`). n8n then publishes the
message into the durable RabbitMQ queue `wazuh-enriched-alerts`, consumed by the
main workflow (see [03](03-docker-compose.md) and [07](07-n8n-workflow.md)).

The coupling is **asynchronous**: Wazuh never waits for n8n; if n8n is down,
messages already published stay in the queue.

---

## 5. Active Response (`ar.conf`)

```text
block-ip600   - block-ip.sh     - timeout 600
unblock-ip0   - unblock-ip.sh   - timeout 0
block-port600 - block-port.sh   - timeout 600
unblock-port0 - unblock-port.sh - timeout 0
```

- `*600` = temporary block, auto-expiring after 600 s.
- `unblock-*0` = immediate removal, used by the **rollback** mechanism.
- Scripts run **on the monitored VM** (iptables), so protection survives a loss
  of connectivity with the SOC. Full script logic in
  [08-active-response.md](08-active-response.md).

---

## 6. Validation

```bash
# On the monitored VM
sudo systemctl status wazuh-agent

# On the VM SOC (dashboard/API)
curl -sk -u <user>:<pass> "https://100.64.0.11:55000/agents?status=active"
```

Expected: both agents (Linux + Windows) report `active`, and Suricata/Sysmon
events appear in the Wazuh Dashboard security events view.git 