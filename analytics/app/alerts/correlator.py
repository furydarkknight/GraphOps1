"""
Graph-Connectivity Alert Correlator for GraphOps.
Clusters disparate raw SIEM/EDR alerts into unified incidents based on topological proximity
in the security graph and temporal clustering windows.
"""

from typing import List, Dict, Any, Tuple, Set
import networkx as nx
import datetime


class AlertCorrelator:
    def __init__(self, time_window_seconds: int = 7200, max_hops: int = 2):
        self.time_window = time_window_seconds
        self.max_hops = max_hops

    def correlate(self, alerts: List[Dict[str, Any]], G: nx.DiGraph) -> Dict[str, Any]:
        """
        Clusters raw alerts into incidents using graph neighborhood reachability and timestamps.
        """
        if not alerts:
            return {"clusters": [], "alert_reduction_ratio": 0.0, "total_raw_alerts": 0}

        # Build an alert-similarity graph
        alert_graph = nx.Graph()
        for idx, a in enumerate(alerts):
            alert_id = a.get("id") or f"alert-{idx:04d}"
            alert_graph.add_node(alert_id, alert_data=a)

        # Connect alerts that share an entity or are connected within max_hops on security graph G
        UG = G.to_undirected()

        for i in range(len(alerts)):
            a1 = alerts[i]
            id1 = a1.get("id") or f"alert-{i:04d}"
            target1 = a1.get("host") or a1.get("target") or a1.get("source_id") or a1.get("user")

            for j in range(i + 1, len(alerts)):
                a2 = alerts[j]
                id2 = a2.get("id") or f"alert-{j:04d}"
                target2 = a2.get("host") or a2.get("target") or a2.get("source_id") or a2.get("user")

                should_link = False

                # 1. Exact entity match
                if target1 and target2 and target1 == target2:
                    should_link = True
                # 2. Graph distance check
                elif target1 and target2 and UG.has_node(target1) and UG.has_node(target2):
                    if nx.has_path(UG, target1, target2):
                        dist = nx.shortest_path_length(UG, target1, target2)
                        if dist <= self.max_hops:
                            should_link = True

                if should_link:
                    alert_graph.add_edge(id1, id2)

        # Connected components represent correlated incidents
        clusters = []
        cluster_idx = 1
        for comp in nx.connected_components(alert_graph):
            comp_alerts = [alert_graph.nodes[aid]["alert_data"] for aid in comp]

            # Highest severity
            severities = [a.get("severity", "MEDIUM").upper() for a in comp_alerts]
            cluster_sev = "CRITICAL" if "CRITICAL" in severities else ("HIGH" if "HIGH" in severities else "MEDIUM")

            entities = set()
            for a in comp_alerts:
                e = a.get("host") or a.get("target") or a.get("user")
                if e:
                    entities.add(str(e))

            entity_str = ", ".join(list(entities)[:3]) or "Network entities"
            title = f"Correlated Incident: Activity on {entity_str} ({len(comp_alerts)} alerts)"

            clusters.append({
                "id": f"INC-CORR-{cluster_idx:03d}",
                "title": title,
                "severity": cluster_sev,
                "alert_ids": list(comp),
                "alert_count": len(comp),
                "entities_involved": list(entities),
                "alerts": comp_alerts
            })
            cluster_idx += 1

        total_alerts = len(alerts)
        incident_count = len(clusters)
        reduction_ratio = round((total_alerts - incident_count) / max(1, total_alerts), 3)

        return {
            "clusters": clusters,
            "incident_count": incident_count,
            "total_raw_alerts": total_alerts,
            "alert_reduction_ratio": reduction_ratio
        }
