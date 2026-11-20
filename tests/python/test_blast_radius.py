"""
Unit tests for blast radius reachability and independent cascade simulation.
"""

import pytest
import networkx as nx
from app.blast_radius.reachability import compute_forward_reachability
from app.blast_radius.cascade import run_independent_cascade_simulation


def create_linear_chain_graph():
    """
    Chain: S -> N1 -> N2 -> CJ (Crown Jewel)
    """
    G = nx.DiGraph()
    G.add_edge("S", "N1", type="CONNECTED_TO", weight=1.0, timestamp="2026-11-14T10:00:00Z")
    G.add_edge("N1", "N2", type="CONNECTED_TO", weight=1.0, timestamp="2026-11-14T10:15:00Z")
    G.add_edge("N2", "CJ", type="HAS_ADMIN", weight=1.0, timestamp="2026-11-14T10:30:00Z")
    G.add_node("CJ", is_crown_jewel=True, criticality=10)
    G.add_node("S", criticality=3)
    G.add_node("N1", criticality=5)
    G.add_node("N2", criticality=6)
    return G


def test_forward_reachability_hops():
    G = create_linear_chain_graph()
    reach = compute_forward_reachability(G, seeds=["S"], max_hops=3)

    assert reach["impacted_count"] == 4
    assert reach["crown_jewel_exposure"] is True
    assert "CJ" in reach["crown_jewels_exposed"]

    # Verify hop numbers
    hops = {node["node_id"]: node["hop"] for node in reach["impacted_nodes"]}
    assert hops["N1"] == 1
    assert hops["N2"] == 2
    assert hops["CJ"] == 3


def test_independent_cascade_confidence_bounds():
    G = create_linear_chain_graph()
    sim = run_independent_cascade_simulation(G, seeds=["S"], iterations=30, seed=42)

    ci = sim["confidence_interval"]
    assert len(ci) == 2
    # Lower bound must be <= upper bound
    assert ci[0] <= ci[1]
    # Expected impacted assets must be >= 1 (the seed itself)
    assert sim["expected_impacted_assets"] >= 1.0
    # Crown jewel exposure should be true for deterministic weights of 1.0
    assert sim["crown_jewel_exposure"] is True
    assert sim["crown_jewel_compromise_probability"] > 0.8
    assert sim["risk_score"] > 50.0
