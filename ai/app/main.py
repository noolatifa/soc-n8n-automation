import json
import os
from typing import Union, List, Any

from fastapi import FastAPI, Body

from . import llm
from . import rag
from .schemas import Verdict
from .prompt import SYSTEM_PROMPT  # ← import depuis prompt.py

app = FastAPI(title="SOC AI Layer")


def _normalize(payload: Any) -> dict:
    """Accepte array n8n OU dict direct -> retourne un dict item."""
    if isinstance(payload, list):
        return payload[0] if payload else {}
    return payload if isinstance(payload, dict) else {}


def _extract_alert(item: dict) -> dict:
    """Extrait l'alerte Wazuh quel que soit le wrapper."""
    try:
        a = item.get("wazuh_alert", {}).get("full_raw", {}).get("alert", {})
        if a:
            return a
    except Exception:
        pass
    a = item.get("alert")
    if isinstance(a, dict):
        return a
    return item


def _summarize_ti(item: dict) -> str:
    ti = item.get("threat_intelligence", {})
    if not ti:
        return "- threat_intelligence: absent from payload"

    misp = ti.get("misp", {})
    opencti = ti.get("opencti", {})
    corr = item.get("correlation_summary", {})
    lines = []

    if misp.get("found"):
        ev = misp.get("event", {})
        tags = [t.get("name") for t in ev.get("Tag", [])]
        lines.append(f"- MISP found=true (event {ev.get('id')}, info: {ev.get('info')}, tags: {tags})")
        for a in misp.get("attributes", []):
            lines.append(f"  - attribute: type={a.get('type')} | category={a.get('category')} "
                         f"| to_ids={a.get('to_ids')} | value={a.get('value')}")
    else:
        lines.append("- MISP found=false")

    if opencti.get("found"):
        lines.append(f"- OpenCTI found=true ({len(opencti.get('indicators', []))} indicators)")
    else:
        lines.append("- OpenCTI found=false")

    if corr:
        lines.append(f"- correlation: matches={corr.get('total_matches')} "
                     f"preliminary={corr.get('preliminary_verdict')}")
    return "\n".join(lines)

@app.get("/health")
def health():
    return {"status": "ok", "backend": os.getenv("LLM_BACKEND", "ollama")}


@app.post("/qualifier-alerte", response_model=Verdict)
def qualifier_alerte(payload: Union[list, dict] = Body(...)):
    item = _normalize(payload)
    alert = _extract_alert(item)

    try:
        ctx = rag.get_context(alert)
    except Exception:
        ctx = "No similar past alerts found."

    ti = _summarize_ti(item)
    # ti = item.get("threat_intelligence", {})
    # if not ti:
    #     ti_str = "- threat_intelligence: absent from payload"
    # else:
    #     ti_str = f"Full threat intelligence:\n{json.dumps(ti, indent=2)}"



    user_prompt = (
        f"{ctx}\n\n"
        f"Threat intelligence:\n{ti}\n\n"
        f"Current alert to analyze:\n{json.dumps(alert, indent=2)}"
    )
    
#     user_prompt = (
#     f"{ctx}\n\n"
#     f"{ti_str}\n\n"
#     f"Current alert to analyze:\n{json.dumps(alert, indent=2)}"
# )

    raw = llm.chat(SYSTEM_PROMPT, user_prompt)
    try:
        data = json.loads(raw)
    except Exception:
        data = json.loads(raw.split("```json")[-1].split("```")[0])
    return Verdict(**data)