"""[1] CHUNKING : alerte -> chunk (texte + metadonnees). 1 alerte = 1 chunk naturel."""


def alert_to_chunk(alert: dict):
    d = alert.get("data", {})
    act = alert.get("automated_action", {})
    text = (
        f"Source: {alert.get('source', '-')} | "
        f"Rule {alert['rule']['id']} (level {alert['rule']['level']}): {alert['rule']['description']} | "
        f"srcip={d.get('srcip', '-')} dstport={d.get('dstport', '-')} dstip={d.get('dstip', '-')} "
        f"file={d.get('file', '-')} command={d.get('command', '-')}\n"
        f"Verdict: {alert['classification']} | {alert['attack_type']} | "
        f"MITRE {alert['mitre_tactic']} | conf {alert['confidence_score']} | "
        f"execute={act.get('execute', False)}\n"
        f"Reasoning: {alert['reasoning']}"
    )
    meta = {
        "classification": alert["classification"],
        "attack_type": alert["attack_type"],
        "mitre_tactic": alert["mitre_tactic"],
        "confidence_score": alert["confidence_score"],
        "execute": act.get("execute", False),
    }
    return text, meta


def alert_to_query(alert: dict) -> str:
    """Texte de requete, meme forme que les chunks indexes."""
    d = alert.get("data", {})
    return (f"Rule: {alert.get('rule', {}).get('description', '')} "
            f"(level {alert.get('rule', {}).get('level', 0)}) "
            f"srcip={d.get('srcip', '-')} dstport={d.get('dstport', '-')}")