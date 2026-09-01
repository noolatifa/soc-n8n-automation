# AI Layer (Under Development)

> ! Work in progress. For the stable Blue Team layer (Wazuh, n8n, Docker), see the [`main`](../../tree/main) branch.

This branch contains the AI qualification agent for the SOC pipeline. It receives enriched alerts from n8n (Wazuh + MISP + OpenCTI) and uses a local LLM to return a structured verdict: True/False Positive, MITRE tactic, reasoning, and automated actions.

### How it works

1. n8n sends an enriched alert to `POST /qualifier-alerte`
2. The service retrieves similar past alerts from ChromaDB (RAG)
3. Qwen2.5:7b analyzes the alert + context + threat intelligence
4. Returns a verdict JSON that n8n can route (block IP, create TheHive case, log to PostgreSQL)

### Current Status

- FastAPI service — working
- Local LLM (Ollama + Qwen2.5:7b) — working
- RAG memory (ChromaDB + nomic-embed-text) — working
- n8n verdict contract (verdict / analysis_context / recommendation) — working

### Quick Start

```powershell
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/ingest.py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Testing

Test with a sample payload:

```powershell
$body = Get-Content tests\n8n_payload_example.json -Raw
$result = Invoke-RestMethod -Uri http://127.0.0.1:8000/qualifier-alerte -Method Post -Body $body -ContentType "application/json"
$result | ConvertTo-Json -Depth 10
```

Expected output:

```json
{
  "verdict": "TRUE_POSITIVE",
  "confidence_score": 90,
  "attack_type": "SSH Brute Force",
  "mitre_tactic": "T1110 - Brute Force",
  "analysis_context": "SSH brute force from external IP, MISP auto-created by pipeline",
  "reasoning": "High rule level + external IP + classic pattern",
  "recommendation": "Block the source IP at the firewall level",
  "automated_action": {
    "execute": true,
    "actions": [
      {"action_type": "BLOCK_IP", "target": "198.51.100.55"},
      {"action_type": "BLOCK_PORT", "target": "198.51.100.55", "port": 22}
    ]
  }
}
```

### Project Structure

```
ai/
├── app/
│   ├── main.py          # FastAPI endpoints + n8n payload parsing
│   ├── prompt.py        # System prompt (classification rules, IP rules)
│   ├── schemas.py       # Pydantic models (verdict contract)
│   ├── llm.py           # Ollama client
│   └── rag/             # RAG pipeline
│       ├── chunker.py   # Alert → chunk
│       ├── embedder.py  # Text → vector
│       └── store.py     # ChromaDB storage + retrieval
├── scripts/
│   └── ingest.py        # Ingest dataset into ChromaDB
├── data/
│   └── SCHEMA.md        # Dataset format documentation
└── tests/
    └── n8n_payload_example.json
```

### RAG Dataset

See [`data/SCHEMA.md`](data/SCHEMA.md) for the dataset format used by `ingest.py`.