"""
GraphOps Analytics Service — FastAPI Gateway.
Provides high-performance graph analytics, MITRE ATT&CK hunt patterns,
blast-radius simulation, containment optimization, and hybrid RAG.
"""

import os
import hashlib
import json
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.graph.schema import GraphSnapshotPayload
from app.graph.normaliser import TelemetryNormaliser
from app.graph.builder import build_networkx_graph, export_networkx_to_payload
from app.hunts import run_all_hunts
from app.paths.attack_paths import analyze_attack_paths
from app.blast_radius.cascade import run_independent_cascade_simulation
from app.containment.optimiser import ContainmentOptimiser
from app.containment.simulator import simulate_containment_impact
from app.alerts.correlator import AlertCorrelator
from app.rag.engine import security_rag
from app.ml.inkloom_engine import security_ml_classifier
from app.pdf.incident_report import generate_incident_report_pdf
from app.soar.simulator import soar_simulator
from app.synthetic.generator import EnterpriseSyntheticGenerator

app = FastAPI(
    title="GraphOps Analytics Service",
    description="Graph analytics engine for proactive threat hunting and blast radius containment.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Request Models ───────────────────────────────────────────────────────────

class NormaliseRequest(BaseModel):
    events: List[Dict[str, Any]]
    label: Optional[str] = "Ingested Telemetry"

class HuntRunRequest(BaseModel):
    graph_json: Dict[str, Any]
    rules: Optional[List[Dict[str, Any]]] = None
    parameters: Optional[Dict[str, Any]] = None

class PathsRequest(BaseModel):
    graph_json: Dict[str, Any]
    sources: Optional[List[str]] = None
    targets: Optional[List[str]] = None
    k: Optional[int] = 5

class BlastRadiusRequest(BaseModel):
    graph_json: Dict[str, Any]
    seeds: List[str]
    time_limit_hours: Optional[float] = 72.0
    cascade_seed: Optional[int] = 42

class ContainmentPlanRequest(BaseModel):
    graph_json: Dict[str, Any]
    incident: Optional[Dict[str, Any]] = None
    budget: Optional[float] = 100.0

class ContainmentSimulateRequest(BaseModel):
    graph_json: Dict[str, Any]
    seeds: List[str]
    actions: List[Dict[str, Any]]

class AlertCorrelateRequest(BaseModel):
    alerts: List[Dict[str, Any]]
    graph_json: Dict[str, Any]

class CopilotRequest(BaseModel):
    masked_query: str
    incident_summary: Optional[Dict[str, Any]] = None

class SyntheticRequest(BaseModel):
    size: Optional[int] = 1000
    seed: Optional[int] = 42
    campaigns: Optional[List[str]] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    diag = security_ml_classifier.get_diagnostics()
    gemini_key = os.getenv("GEMINI_API_KEY")
    return {
        "status": "ok",
        "service": "graphops-analytics",
        "model_mode": diag["model_mode"],
        "llm_mode": "gemini" if gemini_key else "rag_only",
        "is_onnx_loaded": diag["is_loaded"],
        "load_notice": diag["load_error"] or "Operational"
    }


@app.post("/normalise")
def normalise_telemetry(req: NormaliseRequest):
    if not req.events:
        raise HTTPException(status_code=400, detail="Events list cannot be empty.")
    normaliser = TelemetryNormaliser()
    snapshot = normaliser.normalise(req.events, label=req.label or "Ingested Telemetry")
    payload_dict = snapshot.model_dump()
    input_hash = hashlib.sha256(json.dumps(req.events, sort_keys=True).encode()).hexdigest()

    return {
        "node_count": len(snapshot.nodes),
        "edge_count": len(snapshot.edges),
        "input_hash": input_hash,
        "graph_json": payload_dict
    }


@app.post("/hunts/run")
def execute_hunts(req: HuntRunRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    rule_codes = None
    if req.rules:
        rule_codes = [r.get("rule_code") for r in req.rules if r.get("rule_code")]

    leads = run_all_hunts(G, requested_rule_codes=rule_codes, parameters=req.parameters)

    config_hash = hashlib.sha256(json.dumps(rule_codes or [], sort_keys=True).encode()).hexdigest()
    result_hash = hashlib.sha256(json.dumps([l.model_dump() for l in leads], sort_keys=True).encode()).hexdigest()

    return {
        "hunt_leads": [l.model_dump() for l in leads],
        "leads_count": len(leads),
        "config_hash": config_hash,
        "result_hash": result_hash
    }


@app.post("/paths")
def compute_attack_paths(req: PathsRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    return analyze_attack_paths(G, sources=req.sources, targets=req.targets, k=req.k or 5)


@app.post("/blast-radius")
def calculate_blast_radius(req: BlastRadiusRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    if not req.seeds:
        raise HTTPException(status_code=400, detail="Seeds cannot be empty.")

    return run_independent_cascade_simulation(
        G,
        seeds=req.seeds,
        seed=req.cascade_seed or 42
    )


@app.post("/containment/plan")
def propose_containment(req: ContainmentPlanRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    # Extract seeds from incident blast radius or pick highest degree compromised nodes
    incident = req.incident or {}
    br = incident.get("blastRadius") or {}
    seeds = br.get("impacted_nodes") or []
    if seeds and isinstance(seeds[0], dict):
        seed_ids = [s.get("node_id") for s in seeds[:3] if s.get("node_id")]
    elif seeds and isinstance(seeds[0], str):
        seed_ids = seeds[:3]
    else:
        # Default to low criticality workstations
        seed_ids = [n for n in G.nodes() if str(n).startswith("host:ws-")][:2]

    optimiser = ContainmentOptimiser()
    plan_result = optimiser.optimize(G, seed_ids or ["host:ws-0001"], budget=req.budget or 100.0)

    return {
        "actions": plan_result["selected_actions"],
        "expected_reduction": plan_result["expected_reduction"],
        "baseline_risk": plan_result["baseline_risk_score"]
    }


@app.post("/containment/simulate")
def simulate_containment(req: ContainmentSimulateRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    return simulate_containment_impact(G, req.seeds, req.actions)


@app.post("/alerts/correlate")
def correlate_alerts(req: AlertCorrelateRequest):
    try:
        payload = GraphSnapshotPayload(**req.graph_json)
        G = build_networkx_graph(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid graph payload: {e}")

    correlator = AlertCorrelator()
    return correlator.correlate(req.alerts, G)


@app.post("/report/pdf")
def generate_pdf_report(payload: Dict[str, Any] = Body(...)):
    incident = payload.get("incident") or payload
    pdf_bytes = generate_incident_report_pdf(incident)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=incident-report.pdf"}
    )


@app.post("/copilot")
def copilot_query(req: CopilotRequest):
    rag_hits = security_rag.search(req.masked_query, top_k=3)

    # Deterministic narrative construction
    sources = [hit["source"] for hit in rag_hits]
    narrative_lines = [
        "[Deterministic SOC Copilot — Citations grounded in verified ATT&CK playbooks]",
        ""
    ]
    for idx, hit in enumerate(rag_hits, 1):
        narrative_lines.append(f"[{idx}] {hit['title']} ({hit['source']}):")
        narrative_lines.append(f"    {hit['content'][:250]}...")
        narrative_lines.append("")

    return {
        "narrative": "\n".join(narrative_lines),
        "mode": "rag_only",
        "sources": sources,
        "rag_hits": rag_hits
    }


@app.post("/synthetic/generate")
def generate_synthetic(req: SyntheticRequest):
    gen = EnterpriseSyntheticGenerator(seed=req.seed or 42)
    snapshot, ground_truth = gen.generate(target_node_count=req.size or 1000)

    return {
        "graph_json": snapshot.model_dump(),
        "ground_truth": ground_truth,
        "input_hash": snapshot.metadata["input_hash"],
        "node_count": len(snapshot.nodes),
        "edge_count": len(snapshot.edges)
    }
