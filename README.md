# AI Layer (Under Development)

> ! Work in progress. For the stable Blue Team layer (Wazuh, n8n, Docker), see the [`main`](../../tree/main) branch.

This branch contains the AI qualification agent for the SOC pipeline. It receives enriched alerts and uses a local LLM to return a structured verdict (True/False Positive, MITRE tactic, automated actions).

### Current Status

- FastAPI service (`/qualifier-alerte`) — working
- Local LLM integration (Ollama + Qwen2.5 7b) — working
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

### Architecture

```
n8n (Wazuh + MISP + OpenCTI)
    ↓ POST /qualifier-alerte
FastAPI + RAG + Ollama
    ↓ verdict JSON
n8n (block iptables + TheHive + PostgreSQL)
```

### RAG Dataset

See [`data/SCHEMA.md`](data/SCHEMA.md) for the dataset format used by `ingest.py`.