from pydantic import BaseModel
from typing import List, Optional


class Action(BaseModel):
    action_type: str            # BLOCK_IP | BLOCK_PORT
    target: str
    port: Optional[int] = None
    scope: Optional[str] = None


class AutomatedAction(BaseModel):
    execute: bool = False
    actions: List[Action] = []


class Verdict(BaseModel):
    classification: str
    attack_type: str = "unknown"
    mitre_tactic: str = "unknown"
    confidence_score: int = 0
    reasoning: str = ""
    automated_action: AutomatedAction = AutomatedAction()