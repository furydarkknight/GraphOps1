"""
Hunt Runner for GraphOps.
Dispatches graph pattern matching across registered hunt rules.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import HuntLead
from app.hunts.lateral_movement import LateralMovementHunt
from app.hunts.credential_reuse import CredentialReuseHunt
from app.hunts.rare_process import RareProcessHunt
from app.hunts.beaconing import BeaconingHunt
from app.hunts.fan_out import FanOutHunt
from app.hunts.cross_community import CrossCommunityHunt
from app.hunts.cloud_abuse import CloudAbuseHunt


ALL_HUNTS = [
    LateralMovementHunt(),
    CredentialReuseHunt(),
    RareProcessHunt(),
    BeaconingHunt(),
    FanOutHunt(),
    CrossCommunityHunt(),
    CloudAbuseHunt(),
]


def run_all_hunts(
    G: nx.DiGraph,
    requested_rule_codes: Optional[List[str]] = None,
    parameters: Optional[Dict[str, Any]] = None
) -> List[HuntLead]:
    """
    Executes hunt patterns and returns leads sorted by descending risk score.
    """
    leads: List[HuntLead] = []

    for hunter in ALL_HUNTS:
        if requested_rule_codes and hunter.rule_code not in requested_rule_codes:
            continue
        try:
            results = hunter.run(G, parameters=parameters)
            leads.extend(results)
        except Exception as e:
            print(f"Error executing hunt {hunter.rule_code}: {e}")

    # Rank by score descending
    leads.sort(key=lambda x: x.score, reverse=True)
    return leads
