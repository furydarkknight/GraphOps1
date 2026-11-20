"""
What-If Containment Simulator for GraphOps.
Simulates residual blast radius and risk reduction on a hypothetical graph clone
BEFORE any real-world action is approved or executed.
"""

from typing import List, Dict, Any
import networkx as nx
from app.blast_radius.cascade import run_independent_cascade_simulation


def simulate_containment_impact(
    G: nx.DiGraph,
    seeds: List[str],
    actions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Simulates applying the selected actions to a cloned graph and measures residual blast radius.
    """
    simG = G.copy()

    # Pre-action baseline
    baseline = run_independent_cascade_simulation(G, seeds, iterations=25)

    # Apply actions to simulation graph
    actions_applied = 0
    for act in actions:
        atype = act.get("action_type") or act.get("type")
        target = act.get("target")

        if atype in ["ISOLATE_HOST", "DISABLE_ACCOUNT"]:
            if simG.has_node(target):
                # Sever all incident edges (isolate from network)
                edges_to_remove = list(simG.edges(target)) + list(simG.in_edges(target))
                simG.remove_edges_from(edges_to_remove)
                actions_applied += 1

        elif atype in ["BLOCK_EDGE", "REVOKE_TOKEN"]:
            if " -> " in str(target):
                parts = target.split(" -> ")
                u, v = parts[0].strip(), parts[1].strip()
                if simG.has_edge(u, v):
                    simG.remove_edge(u, v)
                    actions_applied += 1

    # Remaining active seeds that are still reachable
    residual_seeds = [s for s in seeds if simG.degree(s) > 0]
    if not residual_seeds:
        # All seeds completely isolated!
        residual = {
            "expected_impacted_assets": float(len(seeds)),
            "risk_score": 10.0,
            "crown_jewel_exposure": False,
            "hop_layers": [],
            "impacted_nodes": []
        }
    else:
        residual = run_independent_cascade_simulation(simG, residual_seeds, iterations=25)

    risk_reduction_pct = round(
        max(0.0, ((baseline["risk_score"] - residual["risk_score"]) / max(1.0, baseline["risk_score"])) * 100.0),
        1
    )
    asset_reduction_count = max(0, int(baseline["expected_impacted_assets"] - residual["expected_impacted_assets"]))

    return {
        "baseline_risk_score": baseline["risk_score"],
        "residual_risk_score": residual["risk_score"],
        "risk_reduction_percentage": risk_reduction_pct,
        "baseline_impacted_assets": baseline["expected_impacted_assets"],
        "residual_impacted_assets": residual["expected_impacted_assets"],
        "assets_protected_count": asset_reduction_count,
        "crown_jewel_saved": baseline["crown_jewel_exposure"] and not residual["crown_jewel_exposure"],
        "actions_simulated_count": actions_applied,
        "residual_blast_radius": residual
    }
