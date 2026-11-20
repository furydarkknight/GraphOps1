"""
Hunt Pattern Registry & Base Interfaces for GraphOps.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import networkx as nx


class HuntLead(BaseModel):
    id: str
    rule_code: str
    attack_id: str
    tactic: str
    title: str
    score: float  # 0.0 to 100.0
    severity: str
    nodes_involved: List[str]
    edges_involved: List[Dict[str, Any]]
    evidence: str
    mitigation_suggestion: str


class BaseHuntRule:
    rule_code: str = "HUNT-BASE"
    attack_id: str = "T0000"
    tactic: str = "generic"
    title: str = "Base Hunt Rule"
    severity: str = "MEDIUM"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        raise NotImplementedError
