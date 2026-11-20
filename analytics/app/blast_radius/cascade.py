"""
Independent-Cascade Simulation for Blast Radius Estimation.
Executes Monte Carlo simulations with seeded RNG to compute expected asset exposure,
crown-jewel compromise probability, risk scores, and 95% confidence intervals.
"""

from typing import List, Dict, Any, Tuple
import networkx as nx
import random
import math
from app.blast_radius.reachability import compute_forward_reachability


def run_independent_cascade_simulation(
    G: nx.DiGraph,
    seeds: List[str],
    iterations: int = 50,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Performs Monte Carlo Independent Cascade simulation from seed nodes.
    """
    rng = random.Random(seed)
    trials_compromised_counts: List[int] = []
    trials_cj_hit: List[bool] = []
    node_infection_counts: Dict[str, int] = {s: iterations for s in seeds}

    for _ in range(iterations):
        active = set(seeds)
        newly_active = list(seeds)

        while newly_active:
            candidate = newly_active.pop(0)
            for _, neighbor, edata in G.out_edges(candidate, data=True):
                if neighbor not in active:
                    # Exploitability activation probability
                    w = float(edata.get("weight", 0.7))
                    edge_type = edata.get("type", "CONNECTED_TO")
                    if edge_type == "HAS_ADMIN":
                        w = min(1.0, w * 1.3)
                    elif edge_type == "SPAWNED":
                        w = min(1.0, w * 1.1)

                    if rng.random() <= w:
                        active.add(neighbor)
                        newly_active.append(neighbor)
                        node_infection_counts[neighbor] = node_infection_counts.get(neighbor, 0) + 1

        trials_compromised_counts.append(len(active))
        cj_compromised = any(G.nodes.get(n, {}).get("is_crown_jewel", False) for n in active)
        trials_cj_hit.append(cj_compromised)

    # Statistical estimations
    n_trials = len(trials_compromised_counts)
    mean_count = sum(trials_compromised_counts) / n_trials
    variance = sum((x - mean_count) ** 2 for x in trials_compromised_counts) / max(1, n_trials - 1)
    std_err = math.sqrt(variance / n_trials)
    ci_lower = round(max(len(seeds), mean_count - 1.96 * std_err), 1)
    ci_upper = round(min(len(G), mean_count + 1.96 * std_err), 1)

    cj_exposure_prob = round(sum(1 for hit in trials_cj_hit if hit) / n_trials, 2)

    # Risk score calculation (0 - 100)
    # Scaled by percentage of graph exposed and crown jewel likelihood
    total_nodes = max(1, len(G))
    spread_factor = (mean_count / total_nodes) * 50.0
    cj_factor = cj_exposure_prob * 50.0
    risk_score = round(min(100.0, spread_factor + cj_factor + 15.0), 1)

    # Reachability structure for hop layers and visualization
    reachability = compute_forward_reachability(G, seeds)

    return {
        "seeds": seeds,
        "iterations": iterations,
        "seed": seed,
        "expected_impacted_assets": round(mean_count, 1),
        "confidence_interval": [ci_lower, ci_upper],
        "crown_jewel_exposure": cj_exposure_prob > 0.0,
        "crown_jewel_compromise_probability": cj_exposure_prob,
        "risk_score": risk_score,
        "hop_layers": reachability["hop_layers"],
        "impacted_nodes": reachability["impacted_nodes"]
    }
