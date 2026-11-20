"""
Candidate Containment Action Models & Disruption Costs for GraphOps.
"""

from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel


class ActionType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    REVOKE_TOKEN = "REVOKE_TOKEN"
    BLOCK_EDGE = "BLOCK_EDGE"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"


class ContainmentAction(BaseModel):
    action_id: str
    action_type: ActionType
    target: str
    target_type: str
    target_label: str
    disruption_cost: float
    expected_benefit: float
    description: str
    soar_command: str


# Baseline business disruption costs (1 - 100 scale)
ACTION_BASE_COSTS: Dict[ActionType, float] = {
    ActionType.BLOCK_EDGE: 5.0,
    ActionType.ROTATE_CREDENTIALS: 10.0,
    ActionType.REVOKE_TOKEN: 12.0,
    ActionType.DISABLE_ACCOUNT: 20.0,
    ActionType.ISOLATE_HOST: 25.0,
}
