"""
NetworkX Graph Constructor for GraphOps.
Constructs directed multigraphs / DiGraphs with typed attributes from Snapshot payloads.
"""

import networkx as nx
from typing import Dict, Any, List, Optional
from app.graph.schema import GraphNode, GraphEdge, GraphSnapshotPayload, NodeType, EdgeType


def build_networkx_graph(payload: GraphSnapshotPayload) -> nx.DiGraph:
    """
    Constructs a NetworkX DiGraph from a GraphSnapshotPayload.
    """
    G = nx.DiGraph(label=payload.label, metadata=payload.metadata)

    for node in payload.nodes:
        G.add_node(
            node.id,
            type=node.type,
            label=node.label,
            criticality=node.criticality,
            is_crown_jewel=node.is_crown_jewel,
            **node.properties
        )

    for edge in payload.edges:
        G.add_edge(
            edge.source,
            edge.target,
            type=edge.type,
            weight=edge.weight,
            timestamp=edge.timestamp,
            source_log=edge.source_log,
            **edge.properties
        )

    return G


def export_networkx_to_payload(G: nx.DiGraph, label: str = "Exported Graph") -> GraphSnapshotPayload:
    """
    Converts a NetworkX DiGraph back into GraphSnapshotPayload.
    """
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

    for n, data in G.nodes(data=True):
        node_type = data.get("type", NodeType.HOST)
        if isinstance(node_type, str):
            try:
                node_type = NodeType(node_type)
            except ValueError:
                node_type = NodeType.HOST

        nodes.append(GraphNode(
            id=str(n),
            type=node_type,
            label=str(data.get("label", n)),
            criticality=int(data.get("criticality", 5)),
            is_crown_jewel=bool(data.get("is_crown_jewel", False)),
            properties={k: v for k, v in data.items() if k not in ["type", "label", "criticality", "is_crown_jewel"]}
        ))

    for u, v, data in G.edges(data=True):
        edge_type = data.get("type", EdgeType.CONNECTED_TO)
        if isinstance(edge_type, str):
            try:
                edge_type = EdgeType(edge_type)
            except ValueError:
                edge_type = EdgeType.CONNECTED_TO

        edges.append(GraphEdge(
            source=str(u),
            target=str(v),
            type=edge_type,
            weight=float(data.get("weight", 1.0)),
            timestamp=data.get("timestamp"),
            source_log=str(data.get("source_log", "graphops")),
            properties={k: v for k, v in data.items() if k not in ["type", "weight", "timestamp", "source_log"]}
        ))

    return GraphSnapshotPayload(label=label, nodes=nodes, edges=edges)
