"""
Unit tests for Containment Optimiser and What-If Simulator.
"""

import pytest
import networkx as nx
from app.containment.optimiser import ContainmentOptimiser
from app.containment.simulator import simulate_containment_impact


def create_containment_test_graph():
    G = nx.DiGraph()
    G.add_node("WS-01", type="Host", criticality=3, label="WS-01")
    G.add_node("Pivot-SRV", type="Host", criticality=6, label="Pivot-SRV")
    G.add_node("DC-01", type="Host", criticality=10, is_crown_jewel=True, label="DC-01")
    G.add_node("user:compromised", type="User", label="compromised_user")

    G.add_edge("user:compromised", "WS-01", type="LOGGED_IN", weight=1.0)
    G.add_edge("WS-01", "Pivot-SRV", type="CONNECTED_TO", weight=0.9)
    G.add_edge("Pivot-SRV", "DC-01", type="CONNECTED_TO", weight=1.0)
    return G


def test_containment_optimiser_knapsack_budget():
    G = create_containment_test_graph()
    optimiser = ContainmentOptimiser()

    # With budget=30, should select highest benefit/cost action (e.g. DISABLE_ACCOUNT or BLOCK_EDGE)
    plan_low_budget = optimiser.optimize(G, seeds=["WS-01"], budget=30.0)
    assert plan_low_budget["disruption_cost_spent"] <= 30.0
    assert len(plan_low_budget["selected_actions"]) >= 1

    # With budget=100, can select multiple actions
    plan_high_budget = optimiser.optimize(G, seeds=["WS-01"], budget=100.0)
    assert plan_high_budget["disruption_cost_spent"] <= 100.0
    assert len(plan_high_budget["selected_actions"]) >= len(plan_low_budget["selected_actions"])


def test_what_if_containment_simulator_drops_risk():
    G = create_containment_test_graph()
    optimiser = ContainmentOptimiser()
    plan = optimiser.optimize(G, seeds=["WS-01"], budget=80.0)

    sim_res = simulate_containment_impact(G, seeds=["WS-01"], actions=plan["selected_actions"])

    assert sim_res["actions_simulated_count"] >= 1
    # Risk score must decrease or remain bounded
    assert sim_res["residual_risk_score"] <= sim_res["baseline_risk_score"]
    # Risk reduction percentage must be positive
    assert sim_res["risk_reduction_percentage"] >= 0.0
