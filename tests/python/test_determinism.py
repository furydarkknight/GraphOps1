"""
Determinism tests for GraphOps Synthetic Generator and Simulations.
Verifies that identical RNG seeds yield bit-for-bit identical graphs, hashes, and simulation outputs.
"""

import pytest
from app.synthetic.generator import EnterpriseSyntheticGenerator
from app.blast_radius.cascade import run_independent_cascade_simulation
from app.graph.builder import build_networkx_graph


def test_synthetic_generator_determinism():
    gen1 = EnterpriseSyntheticGenerator(seed=42)
    snap1, gt1 = gen1.generate(target_node_count=200)

    gen2 = EnterpriseSyntheticGenerator(seed=42)
    snap2, gt2 = gen2.generate(target_node_count=200)

    # Identical node and edge counts
    assert len(snap1.nodes) == len(snap2.nodes)
    assert len(snap1.edges) == len(snap2.edges)

    # Identical input hashes
    assert snap1.metadata["input_hash"] == snap2.metadata["input_hash"]

    # Identical node IDs in order
    assert [n.id for n in snap1.nodes] == [n.id for n in snap2.nodes]

    # Identical ground truth labels
    assert gt1["malicious_nodes"] == gt2["malicious_nodes"]


def test_independent_cascade_determinism():
    gen = EnterpriseSyntheticGenerator(seed=101)
    snap, _ = gen.generate(target_node_count=150)
    G = build_networkx_graph(snap)

    seed_node = snap.nodes[0].id
    sim1 = run_independent_cascade_simulation(G, seeds=[seed_node], iterations=25, seed=777)
    sim2 = run_independent_cascade_simulation(G, seeds=[seed_node], iterations=25, seed=777)

    assert sim1["expected_impacted_assets"] == sim2["expected_impacted_assets"]
    assert sim1["confidence_interval"] == sim2["confidence_interval"]
    assert sim1["risk_score"] == sim2["risk_score"]
    assert sim1["crown_jewel_compromise_probability"] == sim2["crown_jewel_compromise_probability"]
