# Wazuh → n8n Custom Integration

> This document describes the **custom integration** that forwards Wazuh
> alerts to the n8n webhook. It is the entry point of the entire SOAR
> pipeline: every alert that enters the Blue Team orchestration layer
> first passes through this integration.
>
> Related docs:
> - [04-wazuh.md](04-wazuh.md) — general Wazuh configuration
> - [07-n8n-workflow.md](07-n8n-workflow.md) — what n8n does with the alert
> - `docker/pc1-soc/config/integrations/custom-n8n` — the actual script

---

## 1. Overview

The standard Wazuh integrations (Slack, VirusTotal, PagerDuty…) do not
cover n8n. A **custom integration script** was therefore written and
installed in the Wazuh Manager container so that every alert above a
given threshold is POSTed as JSON to a n8n webhook.

```
Wazuh Manager
     │
     │ alert fires (level >= 6)
     ▼
wazuh-integratord (daemon inside the manager container)
     │
     │ argv: [custom-n8n, /tmp/alert.json, <api_key>, <hook_url>]
     ▼
/var/ossec/integrations/custom-n8n   (Python 3 script)
     │
     │ HTTP POST  { ...alert JSON... }
     ▼
http://n8n:5678/webhook/wazuh-alerts  (n8n webhook node, Docker DNS)
```

The integration is **asynchronous and fire-and-forget**: the manager
never waits for a response from n8n. This guarantees that a slow or
down n8n instance cannot back-pressure the SIEM.

---

## 2. Wazuh side — the `<integration>` block

The integration is declared in the Wazuh Manager configuration file:

```
/var/ossec/etc/ossec.conf   (mounted from the host)
```

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://n8n:5678/webhook/wazuh-alerts</hook_url>
  <level>6</level>
  <alert_format>json</alert_format>
</integration>
```

| Element | Value | Meaning |
|---|---|---|
| `<name>` | `custom-n8n` | The script filename under `/var/ossec/integrations/` (no `.py` extension, Wazuh convention) |
| `<hook_url>` | `http://n8n:5678/webhook/wazuh-alerts` | n8n webhook URL. Uses the **Docker service name** `n8n`, not an IP, because both containers share the `single-node_default` bridge |
| `<level>` | `6` | Only alerts with `rule.level >= 6` are forwarded. Low-noise events (0–5) never leave the manager |
| `<alert_format>` | `json` | The alert file passed to the script is the full JSON alert (not XML) |

The **webhook path** `wazuh-alerts` is the one exposed by the n8n node
named `wazuh-alerts` (see [07-n8n-workflow.md](07-n8n-workflow.md)).

---

## 3. The `custom-n8n` script (full source)

Location inside the manager container:

```
/var/ossec/integrations/custom-n8n
```

```python
#!/var/ossec/framework/python/bin/python3
#
# custom-n8n — Wazuh -> n8n custom integration
# Triggered by wazuh-integratord for every alert with level >= 6
# (see <integration> block in ossec.conf).
#
# Args passed by integratord:
#   argv[1]  path to the temporary alert JSON file
#   argv[2]  API key (unused, kept for Wazuh convention)
#   argv[3]  hook_url (the n8n webhook URL)
#
# Logs: /var/ossec/logs/integrations.log

import sys
import json
import logging
import urllib.request
import urllib.error

logging.basicConfig(
    filename="/var/ossec/logs/integrations.log",
    level=logging.INFO,
    format="%(asctime)s custom-n8n: %(message)s",
)

MIN_LEVEL = 3

def main():
    try:
        alert_file = sys.argv[1]
        webhook_url = sys.argv[3]
    except IndexError:
        logging.error("Missing arguments. Usage: custom-n8n <alert_file> <api_key> <hook_url>")
        sys.exit(1)

    try:
        with open(alert_file, "r") as f:
            alert_json = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read/parse alert file {alert_file}: {e}")
        sys.exit(1)

    rule_level = alert_json.get("rule", {}).get("level", 0)
    if rule_level < MIN_LEVEL:
        logging.info(f"Skipped alert below level {MIN_LEVEL} (level={rule_level})")
        sys.exit(0)

    data = json.dumps(alert_json).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logging.info(
                f"Sent alert rule_id={alert_json.get('rule', {}).get('id')} "
                f"level={rule_level} -> n8n status={resp.status}"
            )
    except urllib.error.HTTPError as e:
        logging.error(f"n8n webhook returned HTTP {e.code}: {e.read()[:300]}")
    except Exception as e:
        logging.error(f"Failed to POST to n8n webhook: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
```

### Design notes

- **Shebang** : `/var/ossec/framework/python/bin/python3` — Python bundled
  with Wazuh (avoids depending on a system Python).
- **Dual threshold** : the declarative `<level>6</level>` is the main
  filter; `MIN_LEVEL = 3` is a safety net inside the script in case the
  declarative threshold is accidentally lowered.
- **No wrapping envelope** : the alert JSON is POSTed **as-is** (the n8n
  `Extract Alert` node handles the various payload shapes — see
  [07-n8n-workflow.md](07-n8n-workflow.md)).
- **10-second timeout** : prevents a hung n8n from piling up pending
  calls in integratord.
- **Error isolation** : every error (file read, JSON parse, HTTP) is
  logged and the script exits without crashing integratord.

---

## 4. Deployment

The script is **not** built into the Wazuh image; it is copied into the
running container after `docker compose up`.

```bash
# On the VM SOC (100.64.0.11)
cd ~/wazuh-docker/single-node

# 1) Copy the script into the manager container
docker cp config/integrations/custom-n8n \
  single-node-wazuh.manager-1:/var/ossec/integrations/custom-n8n

# 2) Permissions: executable, owned by root:wazuh
docker exec single-node-wazuh.manager-1 \
  chmod 750 /var/ossec/integrations/custom-n8n
docker exec single-node-wazuh.manager-1 \
  chown root:wazuh /var/ossec/integrations/custom-n8n

# 3) Restart the manager to reload integratord
docker restart single-node-wazuh.manager-1
```

### Verification

```bash
# Script in place with correct permissions
docker exec single-node-wazuh.manager-1 ls -la /var/ossec/integrations/custom-n8n
# -rwxr-x--- 1 root wazuh ... /var/ossec/integrations/custom-n8n

# integratord is running
docker exec single-node-wazuh.manager-1 ps aux | grep integratord
```

---

## 5. Logging

Every invocation of `custom-n8n` writes one line to

```
/var/ossec/logs/integrations.log
```

### Read the log

```bash
docker exec single-node-wazuh.manager-1 tail -n 50 /var/ossec/logs/integrations.log
```

### Examples

```text
2026-08-30 14:12:01 custom-n8n: Sent alert rule_id=5712 level=9 -> n8n status=200
2026-08-30 14:12:03 custom-n8n: Skipped alert below level 3 (level=2)
2026-08-30 14:12:05 custom-n8n: n8n webhook returned HTTP 500: b'Internal Server Error'
2026-08-30 14:12:07 custom-n8n: Failed to POST to n8n webhook: <urlopen error [Errno 111] Connection refused>
```

| Log line | Meaning |
|---|---|
| `Sent alert rule_id=… -> n8n status=200` | success |
| `Skipped alert below level 3` | safety net fired |
| `n8n webhook returned HTTP …` | n8n answered with a non-2xx |
| `Failed to POST to n8n webhook` | network-level failure |

---

## 6. n8n side — receiving the alert

The webhook node `wazuh-alerts` listens at

```
http://n8n:5678/webhook/wazuh-alerts    (internal, Docker DNS)
http://100.64.0.11:5678/webhook/<id>    (external, for curl tests)
```

It immediately forwards the alert to the `RabbitMQ` node, which publishes
it into the durable queue `wazuh-enriched-alerts`. The `RabbitMQ Trigger`
node then consumes the queue **sequentially** (`parallelMessages: 1`) so
alerts are processed one at a time — see
[07-n8n-workflow.md](07-n8n-workflow.md) §2.

The `Extract Alert` node (first downstream node) is deliberately
tolerant about the payload shape: it handles the alert whether it comes
wrapped in `{alert: …}` (curl tests) or raw (the custom integration).

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No log lines at all | `<level>` too high, or integratord not running | Check `rule.level` in alerts, restart manager |
| `Failed to read/parse alert file` | integratord didn't pass the JSON file | Check `<alert_format>json</alert_format>` |
| `Failed to POST … Connection refused` | n8n container not yet started | Wait for `docker compose ps` to show n8n as `Up` |
| `n8n webhook returned HTTP 404` | Wrong webhook URL or workflow inactive | Activate the `version-rapport` workflow in n8n UI |
| Alerts show in Wazuh but never in n8n | `<name>` mismatch with the script filename | `<name>custom-n8n</name>` must match `/var/ossec/integrations/custom-n8n` exactly (no `.py`) |
| Old alerts appear after restart | RabbitMQ queue `wazuh-enriched-alerts` is durable | Expected — they are drained by the trigger |

---

## 8. End-to-end test

From any host on the Tailscale network:

```bash
curl -s -X POST http://100.64.0.11:5678/webhook/<id> \
  -H 'Content-Type: application/json' \
  -d '{
    "alert": {
      "rule": {"id": "5712", "level": 9, "description": "SSHD: brute force"},
      "data": {"srcip": "12.13.14.15"},
      "agent": {"id": "005", "name": "vulnerable-machine-linux"},
      "timestamp": "2026-08-30T12:00:00.000Z"
    }
  }'
```

Then on the VM SOC:

```bash
docker exec single-node-wazuh.manager-1 tail -n 5 /var/ossec/logs/integrations.log
docker exec single-node-n8n-1         docker logs single-node-n8n-1 --tail 20
docker exec single-node-postgres-1    psql -U n8n -d socdb -c "SELECT correlation_id, src_ip, rule_level FROM alerts ORDER BY id DESC LIMIT 3;"
```

Expected: the curl POST reaches n8n, a row appears in `alerts`, and the
alert enters the rest of the pipeline (CTI enrichment, IA, Fast Path…).