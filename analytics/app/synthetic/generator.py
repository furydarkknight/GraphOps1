"""
Deterministic Synthetic Enterprise Security Graph Generator.
Generates realistic enterprise network graphs (1k, 10k, 100k nodes) with benign background traffic
and 3 labelled, injected attack campaigns:
  1. Phish -> Credential Theft -> Lateral Movement -> Domain Admin Compromise
  2. Insider Data Exfiltration to External Drop
  3. Cloud IAM Key Abuse & S3 Crown Jewel Access
"""

import random
import datetime
import hashlib
import json
from typing import Dict, Any, List, Tuple
from app.graph.schema import GraphNode, GraphEdge, GraphSnapshotPayload, NodeType, EdgeType


class EnterpriseSyntheticGenerator:
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate(self, target_node_count: int = 1000) -> Tuple[GraphSnapshotPayload, Dict[str, Any]]:
        self.rng = random.Random(self.seed)

        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        ground_truth: Dict[str, Any] = {
            "campaign_1_lateral_movement": {"nodes": [], "edges": []},
            "campaign_2_insider_exfil": {"nodes": [], "edges": []},
            "campaign_3_cloud_abuse": {"nodes": [], "edges": []},
            "malicious_nodes": [],
            "malicious_edges": [],
            "crown_jewel_nodes": ["host:dc01", "host:db01", "cloud:s3-prod-customer-data"]
        }

        # ─── 1. Crown Jewels ──────────────────────────────────────────────────
        dc_node = GraphNode(
            id="host:dc01",
            type=NodeType.HOST,
            label="DC-01 (Domain Controller)",
            criticality=10,
            is_crown_jewel=True,
            properties={"os": "Windows Server 2022", "subnet": "Tier-0-Auth", "ip": "10.0.0.10"}
        )
        db_node = GraphNode(
            id="host:db01",
            type=NodeType.HOST,
            label="DB-01 (Production Database)",
            criticality=9,
            is_crown_jewel=True,
            properties={"os": "Ubuntu 22.04", "subnet": "Tier-1-Data", "ip": "10.0.2.50"}
        )
        s3_node = GraphNode(
            id="cloud:s3-prod-customer-data",
            type=NodeType.CLOUD_RESOURCE,
            label="s3-prod-customer-data",
            criticality=9,
            is_crown_jewel=True,
            properties={"provider": "aws", "encryption": "AES256", "arn": "arn:aws:s3:::prod-customer-data"}
        )
        nodes[dc_node.id] = dc_node
        nodes[db_node.id] = db_node
        nodes[s3_node.id] = s3_node

        # ─── 2. Calculate Scale Distributions ─────────────────────────────────
        # Scale: ~40% workstations, 20% users, 15% processes, 15% external IPs/domains, 10% servers/cloud
        n_workstations = max(10, int(target_node_count * 0.40))
        n_users = max(5, int(target_node_count * 0.20))
        n_servers = max(4, int(target_node_count * 0.10))
        n_ext = max(5, int(target_node_count * 0.15))
        n_procs = max(5, target_node_count - (n_workstations + n_users + n_servers + n_ext + 3))

        workstation_ids = []
        for i in range(1, n_workstations + 1):
            w_id = f"host:ws-{i:04d}"
            workstation_ids.append(w_id)
            nodes[w_id] = GraphNode(
                id=w_id,
                type=NodeType.HOST,
                label=f"WS-{i:04d}",
                criticality=self.rng.randint(2, 4),
                properties={"subnet": f"10.1.{i // 254}.0/24", "ip": f"10.1.{i // 254}.{i % 254 + 1}"}
            )

        server_ids = []
        for i in range(1, n_servers + 1):
            s_id = f"host:srv-{i:03d}"
            server_ids.append(s_id)
            nodes[s_id] = GraphNode(
                id=s_id,
                type=NodeType.HOST,
                label=f"SRV-{i:03d}",
                criticality=self.rng.randint(5, 7),
                properties={"subnet": "10.0.1.0/24", "ip": f"10.0.1.{i + 10}"}
            )

        user_ids = []
        for i in range(1, n_users + 1):
            u_id = f"user:emp-{i:04d}"
            user_ids.append(u_id)
            nodes[u_id] = GraphNode(
                id=u_id,
                type=NodeType.USER,
                label=f"emp_{i:04d}",
                criticality=self.rng.randint(2, 5),
                properties={"department": self.rng.choice(["Finance", "Engineering", "Marketing", "HR", "Sales"])}
            )

        ext_ids = []
        for i in range(1, n_ext + 1):
            is_ip = self.rng.random() > 0.4
            e_id = f"ip:198.51.{i // 254}.{i % 254 + 1}" if is_ip else f"domain:partner-{i}.com"
            ext_ids.append(e_id)
            nodes[e_id] = GraphNode(
                id=e_id,
                type=NodeType.IP if is_ip else NodeType.DOMAIN,
                label=e_id.split(":")[-1],
                criticality=1
            )

        proc_ids = []
        common_procs = ["svchost.exe", "explorer.exe", "chrome.exe", "slack.exe", "teams.exe", "cmd.exe"]
        for i in range(1, n_procs + 1):
            p_name = self.rng.choice(common_procs)
            w_host = self.rng.choice(workstation_ids)
            p_id = f"proc:{w_host}:{p_name}-{i}"
            proc_ids.append(p_id)
            nodes[p_id] = GraphNode(id=p_id, type=NodeType.PROCESS, label=p_name, criticality=2)

        # ─── 3. Benign Edges ──────────────────────────────────────────────────
        base_time = datetime.datetime(2026, 11, 14, 8, 0, 0, tzinfo=datetime.timezone.utc)

        # Normal user logons to assigned workstations
        for i, u_id in enumerate(user_ids):
            target_ws = workstation_ids[i % len(workstation_ids)]
            edges.append(GraphEdge(
                source=u_id,
                target=target_ws,
                type=EdgeType.LOGGED_IN,
                timestamp=(base_time + datetime.timedelta(minutes=self.rng.randint(0, 120))).isoformat(),
                weight=1.0,
                source_log="security_4624"
            ))

        # Workstations connecting to internal servers (routine HTTP/RPC/SMB)
        for ws in workstation_ids:
            # 1-3 connections per workstation
            for _ in range(self.rng.randint(1, 3)):
                srv = self.rng.choice(server_ids)
                edges.append(GraphEdge(
                    source=ws,
                    target=srv,
                    type=EdgeType.CONNECTED_TO,
                    timestamp=(base_time + datetime.timedelta(minutes=self.rng.randint(60, 300))).isoformat(),
                    weight=0.5,
                    source_log="sysmon_network"
                ))

        # Benign web traffic (Workstations -> external IPs / domains)
        for _ in range(len(workstation_ids) * 2):
            ws = self.rng.choice(workstation_ids)
            ext = self.rng.choice(ext_ids)
            edges.append(GraphEdge(
                source=ws,
                target=ext,
                type=EdgeType.CONNECTED_TO,
                timestamp=(base_time + datetime.timedelta(minutes=self.rng.randint(0, 480))).isoformat(),
                weight=0.2,
                source_log="zeek_conn"
            ))

        # Process spawn chains
        for p in proc_ids:
            parts = p.split(":")
            host_owner = f"{parts[0]}:{parts[1]}"
            if host_owner in nodes:
                edges.append(GraphEdge(
                    source=host_owner,
                    target=p,
                    type=EdgeType.SPAWNED,
                    timestamp=(base_time + datetime.timedelta(minutes=self.rng.randint(10, 180))).isoformat(),
                    weight=0.4,
                    source_log="sysmon_1"
                ))

        # ─── 4. Campaign 1: Lateral Movement to Crown Jewel Domain Controller ─
        # Phish -> Credential Theft -> WS-0014 -> SRV-003 -> DC-01 -> HAS_ADMIN
        c1_foothold = workstation_ids[13] if len(workstation_ids) > 13 else workstation_ids[0]
        c1_pivot = server_ids[2] if len(server_ids) > 2 else server_ids[0]
        c1_admin_user = "user:it-admin-priv"
        c1_phish_proc = f"proc:{c1_foothold}:powershell.exe-c1"

        nodes[c1_admin_user] = GraphNode(
            id=c1_admin_user,
            type=NodeType.USER,
            label="it_admin_priv",
            criticality=8,
            properties={"privilege": "Domain Admins"}
        )
        nodes[c1_phish_proc] = GraphNode(
            id=c1_phish_proc,
            type=NodeType.PROCESS,
            label="powershell.exe -Enc JABj...",
            criticality=6,
            properties={"malicious": True, "technique": "T1059.001"}
        )

        c1_t0 = base_time + datetime.timedelta(hours=2)
        # Edge 1: Spawn malicious powershell
        e1 = GraphEdge(
            source=c1_foothold,
            target=c1_phish_proc,
            type=EdgeType.SPAWNED,
            timestamp=c1_t0.isoformat(),
            weight=0.95,
            source_log="sysmon_1",
            properties={"attack": "T1059.001"}
        )
        # Edge 2: Credential theft / logon of stolen admin credential on foothold
        e2 = GraphEdge(
            source=c1_admin_user,
            target=c1_foothold,
            type=EdgeType.LOGGED_IN,
            timestamp=(c1_t0 + datetime.timedelta(minutes=15)).isoformat(),
            weight=0.9,
            source_log="security_4624",
            properties={"attack": "T1078"}
        )
        # Edge 3: Lateral movement from foothold to pivot server
        e3 = GraphEdge(
            source=c1_foothold,
            target=c1_pivot,
            type=EdgeType.CONNECTED_TO,
            timestamp=(c1_t0 + datetime.timedelta(minutes=30)).isoformat(),
            weight=0.85,
            source_log="sysmon_network",
            properties={"port": 3389, "attack": "T1021.001"}
        )
        # Edge 4: Pivot server to DC-01
        e4 = GraphEdge(
            source=c1_pivot,
            target="host:dc01",
            type=EdgeType.CONNECTED_TO,
            timestamp=(c1_t0 + datetime.timedelta(minutes=45)).isoformat(),
            weight=0.95,
            source_log="zeek_conn",
            properties={"port": 445, "attack": "T1021.002"}
        )
        # Edge 5: Admin takeover of DC-01
        e5 = GraphEdge(
            source=c1_admin_user,
            target="host:dc01",
            type=EdgeType.HAS_ADMIN,
            timestamp=(c1_t0 + datetime.timedelta(minutes=50)).isoformat(),
            weight=1.0,
            source_log="security_4672",
            properties={"attack": "T1078.002"}
        )

        c1_edges = [e1, e2, e3, e4, e5]
        edges.extend(c1_edges)
        c1_nodes = [c1_foothold, c1_phish_proc, c1_admin_user, c1_pivot, "host:dc01"]
        ground_truth["campaign_1_lateral_movement"]["nodes"] = c1_nodes
        ground_truth["campaign_1_lateral_movement"]["edges"] = [
            (e.source, e.target, e.type) for e in c1_edges
        ]

        # ─── 5. Campaign 2: Insider Data Exfiltration ─────────────────────────
        c2_user = "user:insider-bob"
        c2_c2_ip = "ip:203.0.113.199"
        nodes[c2_user] = GraphNode(id=c2_user, type=NodeType.USER, label="bob_contractor", criticality=6)
        nodes[c2_c2_ip] = GraphNode(id=c2_c2_ip, type=NodeType.IP, label="203.0.113.199", criticality=3, properties={"threat_intel": "Known Exfil Drop"})

        c2_t0 = base_time + datetime.timedelta(hours=3)
        # Insider accesses DB
        e6 = GraphEdge(
            source=c2_user,
            target="host:db01",
            type=EdgeType.CAN_REACH,
            timestamp=c2_t0.isoformat(),
            weight=0.9,
            source_log="db_audit",
            properties={"query": "SELECT * FROM payroll_records", "attack": "T1005"}
        )
        # Insider host beacons/exfiltrates to external drop with periodic intervals
        c2_host = workstation_ids[5]
        e7 = GraphEdge(
            source=c2_host,
            target=c2_c2_ip,
            type=EdgeType.CONNECTED_TO,
            timestamp=(c2_t0 + datetime.timedelta(minutes=20)).isoformat(),
            weight=0.95,
            source_log="zeek_conn",
            properties={"bytes_out": 524288000, "attack": "T1048", "interval_sec": 60}
        )
        c2_edges = [e6, e7]
        edges.extend(c2_edges)
        c2_nodes = [c2_user, "host:db01", c2_host, c2_c2_ip]
        ground_truth["campaign_2_insider_exfil"]["nodes"] = c2_nodes
        ground_truth["campaign_2_insider_exfil"]["edges"] = [
            (e.source, e.target, e.type) for e in c2_edges
        ]

        # ─── 6. Campaign 3: Cloud IAM Key Abuse ───────────────────────────────
        c3_leaked_key = "user:service-account-ci"
        c3_attacker_ip = "ip:198.51.100.99"
        nodes[c3_leaked_key] = GraphNode(id=c3_leaked_key, type=NodeType.SERVICE_ACCOUNT, label="sa-ci-cd-deployer", criticality=7)
        nodes[c3_attacker_ip] = GraphNode(id=c3_attacker_ip, type=NodeType.IP, label="198.51.100.99", criticality=2)

        c3_t0 = base_time + datetime.timedelta(hours=4)
        e8 = GraphEdge(
            source=c3_attacker_ip,
            target=c3_leaked_key,
            type=EdgeType.CAN_REACH,
            timestamp=c3_t0.isoformat(),
            weight=0.9,
            source_log="cloudtrail",
            properties={"event": "AssumeRoleWithWebIdentity", "attack": "T1078.004"}
        )
        e9 = GraphEdge(
            source=c3_leaked_key,
            target="cloud:s3-prod-customer-data",
            type=EdgeType.CAN_REACH,
            timestamp=(c3_t0 + datetime.timedelta(minutes=10)).isoformat(),
            weight=1.0,
            source_log="cloudtrail",
            properties={"event": "GetObject", "bucket": "prod-customer-data", "attack": "T1530"}
        )
        c3_edges = [e8, e9]
        edges.extend(c3_edges)
        c3_nodes = [c3_attacker_ip, c3_leaked_key, "cloud:s3-prod-customer-data"]
        ground_truth["campaign_3_cloud_abuse"]["nodes"] = c3_nodes
        ground_truth["campaign_3_cloud_abuse"]["edges"] = [
            (e.source, e.target, e.type) for e in c3_edges
        ]

        # Consolidate all malicious entities
        all_mal_nodes = list(set(c1_nodes + c2_nodes + c3_nodes))
        all_mal_edges = [
            (e.source, e.target, e.type) for e in (c1_edges + c2_edges + c3_edges)
        ]
        ground_truth["malicious_nodes"] = all_mal_nodes
        ground_truth["malicious_edges"] = all_mal_edges

        # Canonical input hash
        hash_seed_str = f"graphops_synthetic_size_{target_node_count}_seed_{self.seed}"
        input_hash = hashlib.sha256(hash_seed_str.encode("utf-8")).hexdigest()

        snapshot = GraphSnapshotPayload(
            label=f"Enterprise Synthetic ({len(nodes)} nodes, seed={self.seed})",
            nodes=list(nodes.values()),
            edges=edges,
            window_start=base_time.isoformat(),
            window_end=(base_time + datetime.timedelta(hours=8)).isoformat(),
            metadata={
                "generated": True,
                "target_node_count": target_node_count,
                "actual_node_count": len(nodes),
                "actual_edge_count": len(edges),
                "seed": self.seed,
                "input_hash": input_hash
            }
        )

        return snapshot, ground_truth


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="demo_1k.json")
    args = parser.parse_args()

    gen = EnterpriseSyntheticGenerator(seed=args.seed)
    snap, gt = gen.generate(target_node_count=args.size)
    print(f"Generated {len(snap.nodes)} nodes, {len(snap.edges)} edges.")
    with open(args.output, "w") as f:
        json.dump({"snapshot": snap.model_dump(), "ground_truth": gt}, f, indent=2)
    print(f"Saved snapshot to {args.output}")
