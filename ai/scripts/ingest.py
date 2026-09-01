"""[0]->[3] : raw data -> chunking -> embedding -> vector store."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.rag import chunker, embedder, store

with open(os.path.join(os.path.dirname(__file__), "..", "data", "sample_alerts.json")) as f:
    data = json.load(f)                                        # [0] RAW DATA

for a in data["alerts"]:
    text, meta = chunker.alert_to_chunk(a)                     # [1] CHUNKING
    vec = embedder.embed_one(text)                             # [2] EMBEDDING
    store.add([a["id"]], [vec], [text], [meta])                # [3] VECTOR STORE

print(f"Ingested {len(data['alerts'])} alerts into ChromaDB")