# RAG Dataset Schema

## Format expected by `ingest.py`

The `ingest.py` script reads a JSON file with the following structure:

```json
{
  "alerts": [
    {
      "id": "alert_001",
      "source": "wazuh",
      "agent": "vulnerable-machine-linux",
      "rule": {
        "id": "5712",
        "level": 15,
        "description": "sshd: brute force trying to use the server"
      },
      "data": {
        "srcip": "203.0.113.11",
        "dstport": 22
      },
      "classification": "TRUE_POSITIVE",
      "attack_type": "SSH Brute Force",
      "mitre_tactic": "Credential Access",
      "confidence_score": 90,
      "reasoning": "Repeated failed SSH logins from external IP, classic brute force",
      "automated_action": {
        "execute": true,
        "actions": [
          {
            "action_type": "BLOCK_IP",
            "target": "203.0.113.11"
          }
        ]
      }
    }
  ]
}
```

## Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique alert identifier |
| `source` | string | Alert origin (e.g. `wazuh`) |
| `agent` | string | Source agent name |
| `rule.id` | string | Wazuh rule ID |
| `rule.level` | int | Severity level |
| `rule.description` | string | Rule description |
| `data.srcip` | string | Source IP |
| `data.dstport` | int | Destination port |
| `classification` | string | Verdict (`TRUE_POSITIVE`, `FALSE_POSITIVE`, ...) |
| `attack_type` | string | Identified attack type |
| `mitre_tactic` | string | Associated MITRE ATT&CK tactic |
| `confidence_score` | int | Confidence score (0–100) |
| `reasoning` | string | Justification for the verdict |
| `automated_action` | object | Automated action(s) triggered |

## Production mode

In production, `ingest.py` doesn't read a static JSON file: it fetches validated verdicts directly from PostgreSQL.

```sql
SELECT
  alert_id          AS id,
  source,
  agent_name        AS agent,
  rule_id,
  rule_level,
  rule_description,
  srcip,
  dstport,
  ai_classification AS classification,
  ai_attack_type    AS attack_type,
  mitre_tactic,
  ai_confidence     AS confidence_score,
  reasoning,
  automated_action
FROM alerts
WHERE ai_classification IS NOT NULL
```

This query only pulls alerts that have already been classified by the AI service (`ai_classification IS NOT NULL`), ensuring only validated verdicts feed the RAG dataset.