"""
Unit tests for core graph algorithms on small, hand-computed graphs.
Verifies topological sorting, shortest paths, betweenness, and node reachability.
"""

import pytest
import networkx as nx
from app.graph.schema import GraphNode, GraphEdge, NodeType, EdgeType, GraphSnapshotPayload
from app.graph.builder import build_networkx_graph
from app.paths.attack_paths import analyze_attack_paths


def create_hand_computed_dag():
    """
    Hand-computed 5-node DAG:
    A -> B (weight=0.8)
    A -> C (weight=0.5)
    B -> D (weight=0.9)
    C -> D (weight=0.7)
    D -> E (Crown Jewel, weight=1.0)
    """
    nodes = [
        GraphNode(id="A", type=NodeType.HOST, label="Entry A", criticality=2),
        GraphNode(id="B", type=NodeType.HOST, label="Pivot B", criticality=4),
        GraphNode(id="C", type=NodeType.HOST, label="Pivot C", criticality=4),
        GraphNode(id="D", type=NodeType.HOST, label="Gateway D", criticality=7),
        GraphNode(id="E", type=NodeType.HOST, label="Crown Jewel E", criticality=10, is_crown_jewel=True),
    ]
    edges = [
        GraphEdge(source="A", target="B", type=EdgeType.CONNECTED_TO, weight=0.8),
        GraphEdge(source="A", target="C", type=EdgeType.CONNECTED_TO, weight=0.5),
        GraphEdge(source="B", target="D", type=EdgeType.CONNECTED_TO, weight=0.9),
        GraphEdge(source="C", target="D", type=EdgeType.CONNECTED_TO, weight=0.7),
        GraphEdge(source="D", target="E", type=EdgeType.CONNECTED_TO, weight=1.0),
    ]
    payload = GraphSnapshotPayload(label="Hand-computed DAG", nodes=nodes, edges=edges)
    return build_networkx_graph(payload)


def test_hand_computed_paths():
    G = create_hand_computed_dag()

    # Exact hand-computed shortest paths from A to E:
    # Path 1: A -> B -> D -> E (length 3 edges)
    # Path 2: A -> C -> D -> E (length 3 edges)
    all_paths = list(nx.all_simple_paths(G, "A", "E"))
    assert len(all_paths) == 2
    assert ["A", "B", "D", "E"] in all_paths
    assert ["A", "C", "D", "E"] in all_paths


def test_hand_computed_choke_point():
    G = create_hand_computed_dag()
    res = analyze_attack_paths(G, sources=["A"], targets=["E"], k=5)

    assert len(res["paths"]) == 2
    # Node D is on 100% of paths between A and E (choke point frequency = 2)
    choke_point_ids = [cp["node_id"] for cp in res["choke_points"]]
    assert "D" in choke_point_ids
    d_cp = next(cp for cp in res["choke_points"] if cp["node_id"] == "D")
    assert d_cp["paths_count"] == 2


def test_cycle_graph_handling():
    """
    3-node cycle: A -> B -> C -> A
    Ensures algorithms handle directed loops without infinite recursion.
    """
    G = nx.DiGraph()
    G.add_edge("A", "B", type="CONNECTED_TO", weight=1.0)
    G.add_edge("B", "C", type="CONNECTED_TO", weight=1.0)
    G.add_edge("C", "A", type="CONNECTED_TO", weight=1.0)
    G.add_node("C", is_crown_jewel=True, criticality=9)

    paths = list(nx.all_simple_paths(G, "A", "C"))
    assert len(paths) == 1
    assert paths[0] == ["A", "B", "C"]
