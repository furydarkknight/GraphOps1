import pytest
import networkx as nx
from app.alerts.correlator import AlertCorrelator


def test_alert_correlator_clustering():
    correlator = AlertCorrelator(max_hops=2)

    # Construct test graph: host-1 -> host-2 -> host-3; host-99 isolated
    G = nx.DiGraph()
    G.add_edge("host-1", "host-2", label="CONNECTED_TO")
    G.add_edge("host-2", "host-3", label="CONNECTED_TO")
    G.add_node("host-99")

    alerts = [
        {"id": "alt-01", "host": "host-1", "severity": "HIGH", "title": "Phish Execution"},
        {"id": "alt-02", "host": "host-2", "severity": "HIGH", "title": "RDP Lateral Movement"},
        {"id": "alt-03", "host": "host-3", "severity": "CRITICAL", "title": "LSASS Dump"},
        {"id": "alt-04", "host": "host-99", "severity": "LOW", "title": "Port Scan"},
    ]

    result = correlator.correlate(alerts, G)
    assert "clusters" in result
    assert "alert_reduction_ratio" in result

    # alt-01, alt-02, alt-03 should cluster together (distance <= 2)
    # alt-04 should form a separate cluster
    assert len(result["clusters"]) == 2
    assert result["alert_reduction_ratio"] == 0.5  # 4 alerts -> 2 clusters = (4-2)/4 = 0.5
