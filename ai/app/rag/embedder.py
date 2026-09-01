"""[2]/[4] EMBEDDING : texte -> vecteur via Ollama (nomic-embed-text)."""
import json
import os
import urllib.request

from dotenv import load_dotenv
load_dotenv()

MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")


def embed_one(text: str):
    payload = {"model": MODEL, "prompt": text}
    req = urllib.request.Request(
        f"{URL}/api/embeddings",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["embedding"]