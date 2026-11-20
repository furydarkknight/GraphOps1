"""
GraphOps Telemetry Normaliser.
Normalises heterogeneous security logs (Windows Event Logs, Sysmon, Zeek, AWS CloudTrail, EDR JSON)
into canonical GraphNode and GraphEdge schemas with Entity Resolution.
"""

from typing import List, Dict, Any, Tuple
from app.graph.schema import GraphNode, GraphEdge, NodeType, EdgeType, GraphSnapshotPayload
from app.graph.entity_resolution import EntityResolver
import datetime
import hashlib
import json


class TelemetryNormaliser:
    def __init__(self):
        self.resolver = EntityResolver()

    def normalise(self, raw_events: List[Dict[str, Any]], label: str = "Ingested Telemetry") -> GraphSnapshotPayload:
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        timestamps: List[str] = []

        def add_node(node: GraphNode):
            if node.id not in nodes:
                nodes[node.id] = node
            else:
                # Merge properties & keep highest criticality
                existing = nodes[node.id]
                existing.criticality = max(existing.criticality, node.criticality)
                if node.is_crown_jewel:
                    existing.is_crown_jewel = True
                existing.properties.update(node.properties)

        for event in raw_events:
            event_type = str(event.get("event_type") or event.get("EventID") or event.get("event_id") or "").lower()
            source = str(event.get("source") or event.get("log_source") or "sysmon").lower()
            ts = str(event.get("timestamp") or event.get("@timestamp") or event.get("TimeCreated") or datetime.datetime.now(datetime.timezone.utc).isoformat())
            timestamps.append(ts)

            # ── 1. Windows / Sysmon Process Creation (EventID 1 or "process_create") ──
            if "1" in event_type or "process" in event_type:
                host_id = self.resolver.resolve_host(
                    hostname=event.get("Computer") or event.get("host") or event.get("hostname"),
                    ip=event.get("host_ip")
                )
                user_id = self.resolver.resolve_user(
                    username=event.get("User") or event.get("user") or event.get("SubjectUserName")
                )
                parent_proc = event.get("ParentImage") or event.get("parent_process") or "explorer.exe"
                child_proc = event.get("Image") or event.get("process_name") or event.get("command_line") or "cmd.exe"

                p_parent_id = f"proc:{host_id}:{parent_proc}"
                p_child_id = f"proc:{host_id}:{child_proc}"

                add_node(GraphNode(id=host_id, type=NodeType.HOST, label=host_id.replace("host:", "")))
                add_node(GraphNode(id=user_id, type=NodeType.USER, label=user_id.replace("user:", "")))
                add_node(GraphNode(id=p_parent_id, type=NodeType.PROCESS, label=parent_proc))
                add_node(GraphNode(id=p_child_id, type=NodeType.PROCESS, label=child_proc))

                # SPAWNED edge
                edges.append(GraphEdge(
                    source=p_parent_id,
                    target=p_child_id,
                    type=EdgeType.SPAWNED,
                    timestamp=ts,
                    source_log="sysmon",
                    weight=0.9,
                    properties={"cmdline": event.get("CommandLine") or child_proc}
                ))

            # ── 2. Windows Logon / Remote Desktop (EventID 4624 or "logon") ────────
            elif "4624" in event_type or "logon" in event_type:
                target_host = self.resolver.resolve_host(
                    hostname=event.get("Computer") or event.get("target_host"),
                    ip=event.get("IpAddress") or event.get("src_ip")
                )
                user_id = self.resolver.resolve_user(
                    username=event.get("TargetUserName") or event.get("user")
                )
                add_node(GraphNode(id=target_host, type=NodeType.HOST, label=target_host.replace("host:", "")))
                add_node(GraphNode(id=user_id, type=NodeType.USER, label=user_id.replace("user:", "")))

                edges.append(GraphEdge(
                    source=user_id,
                    target=target_host,
                    type=EdgeType.LOGGED_IN,
                    timestamp=ts,
                    source_log="security_event_4624",
                    weight=1.0,
                    properties={"logon_type": event.get("LogonType", 3)}
                ))

            # ── 3. Network Connection (Sysmon 3, Zeek conn.log) ────────────────────
            elif "3" in event_type or "network" in event_type or "conn" in source:
                src_ip = event.get("SourceIp") or event.get("id.orig_h") or event.get("src_ip") or "10.0.0.1"
                dst_ip = event.get("DestinationIp") or event.get("id.resp_h") or event.get("dest_ip") or "10.0.0.2"
                dst_port = event.get("DestinationPort") or event.get("id.resp_p") or event.get("dest_port")

                src_host = self.resolver.resolve_host(ip=src_ip, hostname=event.get("Computer"))
                dst_node_id = f"ip:{dst_ip}" if dst_ip.startswith("10.") or dst_ip.startswith("192.168.") else f"domain:{event.get('DestinationHostname') or dst_ip}"

                add_node(GraphNode(id=src_host, type=NodeType.HOST, label=src_host.replace("host:", "")))
                add_node(GraphNode(id=dst_node_id, type=NodeType.IP if dst_node_id.startswith("ip:") else NodeType.DOMAIN, label=dst_ip))

                edges.append(GraphEdge(
                    source=src_host,
                    target=dst_node_id,
                    type=EdgeType.CONNECTED_TO,
                    timestamp=ts,
                    source_log=source,
                    weight=0.8,
                    properties={"port": dst_port, "protocol": event.get("proto") or "tcp"}
                ))

            # ── 4. CloudTrail / IAM (AssumeRole, AccessKey abuse) ─────────────────
            elif "cloudtrail" in source or "iam" in event_type:
                user = event.get("userIdentity", {}).get("userName") or event.get("user") or "cloud-identity"
                user_id = self.resolver.resolve_user(username=user)
                resource = event.get("resource") or event.get("eventName") or "s3-bucket"
                resource_id = f"cloud:{resource}"

                add_node(GraphNode(id=user_id, type=NodeType.USER, label=user))
                add_node(GraphNode(id=resource_id, type=NodeType.CLOUD_RESOURCE, label=resource, criticality=8))

                edges.append(GraphEdge(
                    source=user_id,
                    target=resource_id,
                    type=EdgeType.CAN_REACH,
                    timestamp=ts,
                    source_log="cloudtrail",
                    weight=0.95,
                    properties={"action": event.get("eventName")}
                ))

            # ── 5. Generic Fallback Entity Extraction ─────────────────────────────
            else:
                s_id = str(event.get("source_id") or event.get("source") or "entity_src")
                t_id = str(event.get("target_id") or event.get("target") or "entity_dst")
                r_type = event.get("relationship") or EdgeType.CONNECTED_TO

                add_node(GraphNode(id=s_id, type=NodeType.HOST, label=s_id))
                add_node(GraphNode(id=t_id, type=NodeType.HOST, label=t_id))

                edges.append(GraphEdge(
                    source=s_id,
                    target=t_id,
                    type=r_type if r_type in EdgeType.__members__.values() else EdgeType.CONNECTED_TO,
                    timestamp=ts,
                    source_log=source,
                    weight=0.7
                ))

        window_start = min(timestamps) if timestamps else None
        window_end = max(timestamps) if timestamps else None

        return GraphSnapshotPayload(
            label=label,
            nodes=list(nodes.values()),
            edges=edges,
            window_start=window_start,
            window_end=window_end,
            metadata={"raw_events_count": len(raw_events)}
        )
