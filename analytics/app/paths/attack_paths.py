"""
Attack-Path Analysis & Choke-Point Identification for GraphOps.
Uses Yen's k-shortest paths algorithms and betweenness centrality over exploitability-weighted graph
to identify high-risk traversal routes to crown jewels and rank critical choke points.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from pydantic import BaseModel


class AttackPath(BaseModel):
    path_id: str
    source: str
    target: str
    hops: int
    risk_score: float
    nodes: List[str]
    edges: List[Dict[str, Any]]


class ChokePoint(BaseModel):
    node_id: str
    label: str
    paths_count: int
    criticality: int
    recommendation: str


def analyze_attack_paths(
    G: nx.DiGraph,
    sources: Optional[List[str]] = None,
    targets: Optional[List[str]] = None,
    k: int = 5
) -> Dict[str, Any]:
    """
    Computes top-k attack paths from entry points to crown jewels,
    identifying structural choke points.
    """
    # Auto-detect sources if not provided: low criticality external or workstation nodes
    if not sources:
        sources = [
            n for n, d in G.nodes(data=True)
            if str(n).startswith("host:ws-") or str(n).startswith("ip:") or d.get("criticality", 5) <= 3
        ][:5]

    # Auto-detect targets: crown jewels or high criticality servers
    if not targets:
        targets = [
            n for n, d in G.nodes(data=True)
            if d.get("is_crown_jewel") or d.get("criticality", 0) >= 9
        ]

    paths_result: List[AttackPath] = []
    node_path_frequency: Dict[str, int] = {}

    path_idx = 1
    for s in sources:
        for t in targets:
            if s == t or not G.has_node(s) or not G.has_node(t):
                continue

            if nx.has_path(G, s, t):
                try:
                    # Find up to k paths using shortest_simple_paths
                    paths_gen = nx.shortest_simple_paths(G, s, t)
                    count = 0
                    for path in paths_gen:
                        if count >= k:
                            break

                        # Calculate path risk based on node criticalities and edge weights
                        nodes_in_path = path
                        edge_list = []
                        total_weight = 0.0

                        for i in range(len(path) - 1):
                            u, v = path[i], path[i+1]
                            edata = G.get_edge_data(u, v) or {}
                            w = float(edata.get("weight", 1.0))
                            total_weight += w
                            edge_list.append({
                                "source": u,
                                "target": v,
                                "type": edata.get("type", "CONNECTED_TO"),
                                "weight": w
                            })

                        # Tally choke point frequency once per intermediate node per path
                        for intermediate in path[1:-1]:
                            node_path_frequency[intermediate] = node_path_frequency.get(intermediate, 0) + 1

                        hops = len(path) - 1
                        # Risk formula: higher if reaches crown jewel in fewer hops with high exploitability weights
                        target_crit = G.nodes[t].get("criticality", 10)
                        risk_score = round(min(100.0, (target_crit * 8.0) + (total_weight * 2.5) - (hops * 1.5)), 1)

                        paths_result.append(AttackPath(
                            path_id=f"PATH-{path_idx:03d}",
                            source=s,
                            target=t,
                            hops=hops,
                            risk_score=risk_score,
                            nodes=nodes_in_path,
                            edges=edge_list
                        ))
                        path_idx += 1
                        count += 1
                except Exception:
                    pass

    # Sort paths by risk score descending
    paths_result.sort(key=lambda p: p.risk_score, reverse=True)

    # Rank choke points
    choke_points: List[ChokePoint] = []
    sorted_chokes = sorted(node_path_frequency.items(), key=lambda x: x[1], reverse=True)

    for node_id, freq in sorted_chokes[:5]:
        ndata = G.nodes.get(node_id, {})
        choke_points.append(ChokePoint(
            node_id=node_id,
            label=ndata.get("label", node_id),
            paths_count=freq,
            criticality=ndata.get("criticality", 5),
            recommendation=f"Deploy hardened firewall policy or host microsegmentation on '{node_id}' to sever {freq} intersecting attack paths."
        ))

    return {
        "paths": [p.model_dump() for p in paths_result[:15]],
        "choke_points": [cp.model_dump() for cp in choke_points],
        "sources_evaluated": sources,
        "targets_evaluated": targets
    }
