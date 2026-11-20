"""
Time-window filtering and snapshot slicing for temporal graph analysis.
"""

from typing import Optional, List
import datetime
from app.graph.schema import GraphSnapshotPayload, GraphEdge


def slice_snapshot_by_window(
    payload: GraphSnapshotPayload,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> GraphSnapshotPayload:
    """
    Filters edges to those within [start_time, end_time], retaining connected nodes.
    """
    if not start_time and not end_time:
        return payload

    filtered_edges: List[GraphEdge] = []
    active_node_ids = set()

    for edge in payload.edges:
        if not edge.timestamp:
            filtered_edges.append(edge)
            active_node_ids.add(edge.source)
            active_node_ids.add(edge.target)
            continue

        include = True
        if start_time and edge.timestamp < start_time:
            include = False
        if end_time and edge.timestamp > end_time:
            include = False

        if include:
            filtered_edges.append(edge)
            active_node_ids.add(edge.source)
            active_node_ids.add(edge.target)

    # Filter nodes to active ones, or keep crown jewels
    filtered_nodes = [
        node for node in payload.nodes
        if node.id in active_node_ids or node.is_crown_jewel
    ]

    return GraphSnapshotPayload(
        label=f"{payload.label} (Sliced {start_time or 'inf'} - {end_time or 'inf'})",
        nodes=filtered_nodes,
        edges=filtered_edges,
        window_start=start_time or payload.window_start,
        window_end=end_time or payload.window_end,
        metadata={**payload.metadata, "sliced": True}
    )
