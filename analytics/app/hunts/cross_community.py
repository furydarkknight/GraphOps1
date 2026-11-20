"""
Hunt Rule: Cross-Community Boundary Violation (Louvain Community Analysis / MITRE ATT&CK T1484).
Detects unexpected edges traversing between segregated network communities.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class CrossCommunityHunt(BaseHuntRule):
    rule_code = "HUNT-CC-001"
    attack_id = "T1484"
    tactic = "lateral-movement"
    title = "Cross-Community Network Boundary Crossing"
    severity = "LOW"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []

        if len(G) < 6:
            return leads

        # Compute Louvain / greedy modularity communities on undirected projection
        try:
            UG = G.to_undirected()
            communities = list(nx.community.greedy_modularity_communities(UG))
            node_community_map = {}
            for idx, comm in enumerate(communities):
                for node in comm:
                    node_community_map[node] = idx
        except Exception:
            return leads

        cross_edges = []
        for u, v, d in G.edges(data=True):
            c_u = node_community_map.get(u)
            c_v = node_community_map.get(v)
            if c_u is not None and c_v is not None and c_u != c_v:
                # If target is crown jewel or high criticality
                v_data = G.nodes.get(v, {})
                if v_data.get("is_crown_jewel") or v_data.get("criticality", 0) >= 8:
                    cross_edges.append((u, v, c_u, c_v, d))

        for u, v, c_u, c_v, d in cross_edges[:5]:
            evidence = (
                f"Cross-community edge detected from community #{c_u} (asset '{u}') to community #{c_v} (crown jewel '{v}'). "
                f"Relationship type: {d.get('type')}. Violates standard zero-trust segmentation zones."
            )
            leads.append(HuntLead(
                id=f"LEAD-CC-{len(leads)+1:03d}",
                rule_code=self.rule_code,
                attack_id=self.attack_id,
                tactic=self.tactic,
                title=f"Cross-Community Traverse: {u} -> {v}",
                score=78.0,
                severity="MEDIUM",
                nodes_involved=[u, v],
                edges_involved=[{"source": u, "target": v, "type": d.get("type"), "timestamp": d.get("timestamp")}],
                evidence=evidence,
                mitigation_suggestion=f"Verify firewall policy between network zone #{c_u} and core zone #{c_v}."
            ))

        return leads
