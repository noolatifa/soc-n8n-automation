# RAG Dataset Schema

## Format attendu par `ingest.py`

Le script `ingest.py` lit un fichier JSON avec la structure suivante :

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

## Champs

| Champ | Type | Description |
|---|---|---|
| `id` | string | Identifiant unique de l'alerte |
| `source` | string | Origine de l'alerte (ex. `wazuh`) |
| `agent` | string | Nom de l'agent source |
| `rule.id` | string | ID de la règle Wazuh |
| `rule.level` | int | Niveau de sévérité |
| `rule.description` | string | Description de la règle |
| `data.srcip` | string | IP source |
| `data.dstport` | int | Port de destination |
| `classification` | string | Verdict (`TRUE_POSITIVE`, `FALSE_POSITIVE`, ...) |
| `attack_type` | string | Type d'attaque identifié |
| `mitre_tactic` | string | Tactique MITRE ATT&CK associée |
| `confidence_score` | int | Score de confiance (0–100) |
| `reasoning` | string | Justification du verdict |
| `automated_action` | object | Action(s) automatisée(s) déclenchée(s) |

## Mode production

En production, `ingest.py` ne lit pas un fichier JSON statique : il récupère les verdicts validés directement depuis PostgreSQL.

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

Cette requête ne remonte que les alertes déjà classifiées par le service IA (`ai_classification IS NOT NULL`), garantissant que seuls des verdicts validés alimentent le dataset RAG.