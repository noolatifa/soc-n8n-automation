"""[4]-[6] : query embedding + retrieval + contexte pour le prompt."""
from .rag import chunker, embedder, store


def get_context(alert: dict, k: int = 3) -> str:
    query = chunker.alert_to_query(alert)     # [1] chunking requete
    vec = embedder.embed_one(query)           # [4] query embedding
    res = store.search(vec, k)                # [5] retrieval top 3
    lines = []
    for doc, meta in zip(res["documents"][0], res["metadatas"][0]):
        lines.append(
            f"- {meta['classification']} | {meta['attack_type']} | MITRE {meta['mitre_tactic']} "
            f"| conf {meta['confidence_score']} | execute={meta['execute']} "
            f"| {doc.split('Reasoning: ')[-1][:120]}")
    return "Similar past alerts:\n" + "\n".join(lines)