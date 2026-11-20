"""
Hunt Rule: Lateral Movement Chains (MITRE ATT&CK T1021.001 / T1021.002).
Detects multi-hop traversals connecting entry hosts through pivots toward high-value servers.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class LateralMovementHunt(BaseHuntRule):
    rule_code = "HUNT-LM-001"
    attack_id = "T1021.001"
    tactic = "lateral-movement"
    title = "Lateral Movement Chain Toward High-Value Asset"
    severity = "HIGH"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []
        crown_jewels = [n for n, d in G.nodes(data=True) if d.get("is_crown_jewel") or d.get("criticality", 0) >= 9]

        # Subgraph of lateral movement connection edges
        lm_edges = [
            (u, v) for u, v, d in G.edges(data=True)
            if d.get("type") in ["CONNECTED_TO", "LOGGED_IN"] and not str(v).startswith("domain:")
        ]
        subG = G.edge_subgraph(lm_edges)

        # Find paths of length >= 2 leading to crown jewels
        for target in crown_jewels:
            for source in subG.nodes():
                if source == target:
                    continue
                # If source is a workstation or low criticality host
                s_data = G.nodes.get(source, {})
                if s_data.get("criticality", 5) <= 5:
                    if nx.has_path(subG, source, target):
                        try:
                            # Shortest lateral path
                            path = nx.shortest_path(subG, source, target)
                            if len(path) >= 3:  # At least 2 hops: e.g. WS -> Pivot -> DC
                                score = min(98.0, 75.0 + (len(path) * 5.0))
                                hop_str = " -> ".join([G.nodes.get(n, {}).get("label", n) for n in path])
                                evidence = (
                                    f"Detected {len(path)-1}-hop lateral movement chain from entry asset '{source}' "
                                    f"to crown jewel '{target}' via path: [{hop_str}]."
                                )
                                path_edges = []
                                for i in range(len(path) - 1):
                                    e_data = G.get_edge_data(path[i], path[i+1]) or {}
                                    path_edges.append({
                                        "source": path[i],
                                        "target": path[i+1],
                                        "type": e_data.get("type", "CONNECTED_TO"),
                                        "timestamp": e_data.get("timestamp")
                                    })

                                leads.append(HuntLead(
                                    id=f"LEAD-LM-{len(leads)+1:03d}",
                                    rule_code=self.rule_code,
                                    attack_id=self.attack_id,
                                    tactic=self.tactic,
                                    title=f"Lateral Movement: {source} to {target}",
                                    score=score,
                                    severity="CRITICAL" if G.nodes.get(target, {}).get("is_crown_jewel") else "HIGH",
                                    nodes_involved=path,
                                    edges_involved=path_edges,
                                    evidence=evidence,
                                    mitigation_suggestion=f"Immediately isolate pivot node '{path[1]}' and revoke session tokens for intermediate hosts."
                                ))
                                if len(leads) >= 10:
                                    break
                        except Exception:
                            pass
            if len(leads) >= 10:
                break

        return leads
