"""
Hunt Rule: Outbound Fan-Out Spike / Subnet Sweep (MITRE ATT&CK T1046).
Detects assets rapidly connecting to an anomalous count of unique destinations in the graph.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class FanOutHunt(BaseHuntRule):
    rule_code = "HUNT-FO-001"
    attack_id = "T1046"
    tactic = "discovery"
    title = "High Fan-Out Reconnaissance Spike"
    severity = "MEDIUM"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []
        threshold = (parameters or {}).get("fan_out_threshold", 12)

        for u in G.nodes():
            # Count distinct targets connected to
            targets = [v for _, v, d in G.out_edges(u, data=True) if d.get("type") == "CONNECTED_TO"]
            unique_targets = list(set(targets))

            if len(unique_targets) >= threshold:
                score = min(90.0, 60.0 + (len(unique_targets) * 2.0))
                evidence = (
                    f"Asset '{u}' initiated network connections to {len(unique_targets)} distinct endpoints "
                    f"indicating active subnet enumeration or port scanning behavior."
                )
                sample_edges = [
                    {"source": u, "target": t, "type": "CONNECTED_TO"}
                    for t in unique_targets[:10]
                ]
                leads.append(HuntLead(
                    id=f"LEAD-FO-{len(leads)+1:03d}",
                    rule_code=self.rule_code,
                    attack_id=self.attack_id,
                    tactic=self.tactic,
                    title=f"Fan-Out Spike: {u} ({len(unique_targets)} targets)",
                    score=score,
                    severity="HIGH" if score >= 80 else "MEDIUM",
                    nodes_involved=[u] + unique_targets[:15],
                    edges_involved=sample_edges,
                    evidence=evidence,
                    mitigation_suggestion=f"Deploy microsegmentation ACLs restricting '{u}' from indiscriminate internal network probing."
                ))

        return leads
