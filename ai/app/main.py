import json
import os

from fastapi import FastAPI

from . import llm
from .schemas import Verdict

app = FastAPI(title="SOC AI Layer")

SYSTEM_PROMPT = """You are a senior SOC analyst agent.
Analyze the security alert and decide if it is a TRUE POSITIVE or FALSE POSITIVE.
Return STRICT JSON only with keys:
classification, attack_type, mitre_tactic, confidence_score (0-100), reasoning,
automated_action: {execute: bool, actions: [{action_type: "BLOCK_IP"|"BLOCK_PORT", target, port}]}
Rules: recommend blocking only for high-confidence true positives.
Never recommend blocking internal/private IPs (10.x, 192.168.x, 100.64.x, 172.16-31.x)."""


@app.get("/health")
def health():
    return {"status": "ok", "backend": os.getenv("LLM_BACKEND", "ollama")}


@app.post("/qualifier-alerte", response_model=Verdict)
def qualifier_alerte(payload: dict):
    raw = llm.chat(SYSTEM_PROMPT, json.dumps(payload))
    try:
        data = json.loads(raw)
    except Exception:
        data = json.loads(raw.split("```json")[-1].split("```")[0])
    return Verdict(**data)