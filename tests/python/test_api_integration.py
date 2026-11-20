"""
Integration tests for FastAPI endpoints using TestClient.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.synthetic.generator import EnterpriseSyntheticGenerator

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "model_mode" in data
    assert "llm_mode" in data


def test_normalise_endpoint():
    events = [
        {"EventID": 1, "Computer": "WS-01", "User": "alice", "Image": "cmd.exe", "ParentImage": "explorer.exe"},
        {"EventID": 4624, "Computer": "SRV-01", "TargetUserName": "alice"}
    ]
    res = client.post("/normalise", json={"events": events, "label": "Test Normalise"})
    assert res.status_code == 200
    data = res.json()
    assert data["node_count"] >= 2
    assert "graph_json" in data
    assert "input_hash" in data


def test_synthetic_and_hunts_pipeline():
    # 1. Generate synthetic graph
    syn_res = client.post("/synthetic/generate", json={"size": 100, "seed": 42})
    assert syn_res.status_code == 200
    syn_data = syn_res.json()
    graph_json = syn_data["graph_json"]

    # 2. Run hunts
    hunt_res = client.post("/hunts/run", json={"graph_json": graph_json})
    assert hunt_res.status_code == 200
    hunt_data = hunt_res.json()
    assert "hunt_leads" in hunt_data
    assert len(hunt_data["hunt_leads"]) >= 1

    # 3. Calculate blast radius from first malicious lead
    lead = hunt_data["hunt_leads"][0]
    seeds = lead["nodes_involved"][:2]
    br_res = client.post("/blast-radius", json={"graph_json": graph_json, "seeds": seeds})
    assert br_res.status_code == 200
    br_data = br_res.json()
    assert "expected_impacted_assets" in br_data
    assert "risk_score" in br_data

    # 4. Containment plan
    plan_res = client.post("/containment/plan", json={"graph_json": graph_json, "incident": {"blastRadius": br_data}})
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert len(plan_data["actions"]) >= 1

    # 5. What-if simulate
    sim_res = client.post("/containment/simulate", json={"graph_json": graph_json, "seeds": seeds, "actions": plan_data["actions"]})
    assert sim_res.status_code == 200
    assert "residual_risk_score" in sim_res.json()


def test_copilot_endpoint():
    res = client.post("/copilot", json={"masked_query": "Explain lateral movement technique T1021"})
    assert res.status_code == 200
    data = res.json()
    assert "narrative" in data
    assert len(data["sources"]) >= 1
    assert data["mode"] == "rag_only"


def test_pdf_report_endpoint():
    incident_payload = {
        "id": "INC-TEST-001",
        "title": "Test Incident for PDF Generation",
        "severity": "HIGH",
        "status": "CONTAINED",
        "blastRadius": {"risk_score": 75.0, "impacted_nodes": [{"node_id": "WS-01"}], "crown_jewel_exposure": True},
        "containmentPlans": [{"status": "APPROVED", "actions": [{"action_id": "ACT-01", "action_type": "ISOLATE_HOST", "target": "WS-01"}]}],
        "passport": {"passportHash": "a"*64, "issuedAt": "2026-11-14T22:00:00Z"}
    }
    res = client.post("/report/pdf", json={"incident": incident_payload})
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert len(res.content) > 1000
