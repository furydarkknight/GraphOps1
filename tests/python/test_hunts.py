"""
Unit tests for proactive hunt rules against synthetic and hand-crafted graphs.
"""

import pytest
import networkx as nx
from app.hunts.lateral_movement import LateralMovementHunt
from app.hunts.credential_reuse import CredentialReuseHunt
from app.hunts.rare_process import RareProcessHunt
from app.hunts.beaconing import BeaconingHunt
from app.hunts.fan_out import FanOutHunt


def test_lateral_movement_hunt():
    G = nx.DiGraph()
    # WS-01 -> SRV-01 -> DC-01 (Crown Jewel)
    G.add_node("WS-01", criticality=3, label="Workstation 1")
    G.add_node("SRV-01", criticality=6, label="Server 1")
    G.add_node("DC-01", criticality=10, is_crown_jewel=True, label="Domain Controller")

    G.add_edge("WS-01", "SRV-01", type="CONNECTED_TO")
    G.add_edge("SRV-01", "DC-01", type="CONNECTED_TO")

    hunter = LateralMovementHunt()
    leads = hunter.run(G)

    assert len(leads) >= 1
    lead = leads[0]
    assert lead.rule_code == "HUNT-LM-001"
    assert lead.attack_id == "T1021.001"
    assert "WS-01" in lead.nodes_involved
    assert "DC-01" in lead.nodes_involved
    assert lead.score >= 80.0


def test_credential_reuse_hunt():
    G = nx.DiGraph()
    G.add_node("user:admin", type="User")
    G.add_node("host:ws-01", type="Host", criticality=3)
    G.add_node("host:dc01", type="Host", criticality=10, is_crown_jewel=True)

    G.add_edge("user:admin", "host:ws-01", type="LOGGED_IN")
    G.add_edge("user:admin", "host:dc01", type="HAS_ADMIN")

    hunter = CredentialReuseHunt()
    leads = hunter.run(G)

    assert len(leads) >= 1
    assert leads[0].rule_code == "HUNT-CR-001"
    assert "user:admin" in leads[0].nodes_involved


def test_rare_process_hunt():
    G = nx.DiGraph()
    G.add_node("proc:word.exe", label="word.exe")
    G.add_node("proc:powershell.exe", label="powershell.exe -enc JABj...")
    G.add_edge("proc:word.exe", "proc:powershell.exe", type="SPAWNED", cmdline="powershell.exe -enc JABj...")

    hunter = RareProcessHunt()
    leads = hunter.run(G)

    assert len(leads) == 1
    assert leads[0].rule_code == "HUNT-RP-001"
    assert leads[0].attack_id == "T1059"


def test_beaconing_hunt():
    G = nx.DiGraph()
    G.add_node("WS-05", label="Finance WS")
    G.add_node("198.51.100.5", label="External IP", threat_intel="Known C2 Drop")
    G.add_edge("WS-05", "198.51.100.5", type="CONNECTED_TO", interval_sec=60, bytes_out=500000000)

    hunter = BeaconingHunt()
    leads = hunter.run(G)

    assert len(leads) >= 1
    assert leads[0].rule_code == "HUNT-BC-001"
    assert leads[0].severity == "HIGH"


def test_fan_out_hunt():
    G = nx.DiGraph()
    G.add_node("Scanner-Host")
    for i in range(10):
        target = f"Target-{i}"
        G.add_node(target)
        G.add_edge("Scanner-Host", target, type="CONNECTED_TO")

    hunter = FanOutHunt()
    leads = hunter.run(G, parameters={"fan_out_threshold": 6})

    assert len(leads) == 1
    assert leads[0].rule_code == "HUNT-FO-001"
    assert "Scanner-Host" in leads[0].nodes_involved
