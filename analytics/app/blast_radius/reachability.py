"""
Time-respecting forward reachability analysis for blast radius calculation.
Traverses the security graph outward from compromised seed nodes, respecting edge timestamps,
privilege levels, and exploitability weights.
"""

from typing import List, Dict, Any, Set, Tuple
import networkx as nx
from collections import deque


def compute_forward_reachability(
    G: nx.DiGraph,
    seeds: List[str],
    max_hops: int = 5,
    min_weight: float = 0.1
) -> Dict[str, Any]:
    """
    Computes hop-by-hop reachable layers from compromised seed assets.
    """
    visited: Set[str] = set(seeds)
    queue: deque = deque([(s, 0, None) for s in seeds])  # (node, hop, last_timestamp)
    layers: Dict[int, List[Dict[str, Any]]] = {0: [{"node": s, "criticality": G.nodes.get(s, {}).get("criticality", 5)} for s in seeds]}
    impacted_nodes: List[Dict[str, Any]] = []

    crown_jewels_exposed = []

    while queue:
        curr, hop, last_ts = queue.popleft()
        curr_data = G.nodes.get(curr, {})
        is_cj = curr_data.get("is_crown_jewel", False)

        if is_cj and curr not in crown_jewels_exposed:
            crown_jewels_exposed.append(curr)

        if hop >= max_hops:
            continue

        for _, neighbor, edata in G.out_edges(curr, data=True):
            w = float(edata.get("weight", 1.0))
            if w < min_weight:
                continue

            edge_ts = edata.get("timestamp")
            # Time-respecting: event must occur at or after previous hop
            if last_ts and edge_ts and edge_ts < last_ts:
                continue

            if neighbor not in visited:
                visited.add(neighbor)
                next_hop = hop + 1
                neighbor_data = G.nodes.get(neighbor, {})
                node_info = {
                    "node_id": neighbor,
                    "label": neighbor_data.get("label", neighbor),
                    "type": neighbor_data.get("type", "Host"),
                    "criticality": neighbor_data.get("criticality", 5),
                    "is_crown_jewel": neighbor_data.get("is_crown_jewel", False),
                    "hop": next_hop,
                    "reached_via": curr,
                    "edge_type": edata.get("type", "CONNECTED_TO")
                }
                impacted_nodes.append(node_info)

                if next_hop not in layers:
                    layers[next_hop] = []
                layers[next_hop].append(node_info)

                queue.append((neighbor, next_hop, edge_ts or last_ts))

    return {
        "seeds": seeds,
        "impacted_count": len(visited),
        "impacted_nodes": impacted_nodes,
        "crown_jewel_exposure": len(crown_jewels_exposed) > 0,
        "crown_jewels_exposed": crown_jewels_exposed,
        "hop_layers": [{"hop": h, "nodes": nlist} for h, nlist in sorted(layers.items())]
    }
