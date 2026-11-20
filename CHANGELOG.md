# GraphOps — What Changed From Originals and Why

> **Documenting the architectural evolution from BrandFlight & TechFusion into GraphOps.**

---

## 1. Executive Summary

GraphOps merges the complementary strengths of two hackathon prototypes to solve the SOC challenge:
- **BrandFlight (TypeScript)** possessed strong enterprise platform patterns: production JWT auth, server-side RBAC, tamper-evident cryptographic HMAC passports, PII masking, and WCAG-compliant UI design. However, it completely lacked graph analytics, trained ML models, and SOC domain logic.
- **TechFusion (Python/FastAPI)** possessed algorithmic intelligence: TF-IDF vector embeddings, hybrid RAG, ReportLab PDF generation, and in-context simulation. However, it lacked persistent databases (used in-memory Python dictionaries), had no authentication or RBAC, lacked tamper-evident auditability, had broken 133-byte Git LFS model pointers, and had domain logic tied strictly to marketing brand copy.

GraphOps merges them into a unified **hybrid microservices platform**:
- **Express 5 API Gateway** (from BrandFlight) manages auth, server-side RBAC, PostgreSQL persistence via Prisma, PII masking, and HMAC signing.
- **FastAPI Analytics Engine** (from TechFusion) manages graph construction, MITRE ATT&CK proactive hunting, blast-radius Monte Carlo simulation, and containment optimization.

---

## 2. Module Mapping: Reuse, Adaptation & Replacement

| Original Module | Original Project | GraphOps Status | Transformation & Justification |
|---|---|:---:|---|
| `auth.ts` (JWT Middleware) | BrandFlight | **REUSED & ADAPTED** | Renamed roles: `CREATOR -> ANALYST`, `REVIEWER -> RESPONDER`, `MANAGER -> SOC_MANAGER`. Added `requireMinRole` hierarchy checks. Enforced server-side on every route. |
| `release-passport.ts` | BrandFlight | **REUSED & ADAPTED** | Adapted to `incident-passport.ts`. Cryptographic HMAC-SHA256 signature generated over canonical JSON incident snapshot. Binds graph snapshot, blast radius, containment decisions, and approver identity. |
| `pii-masking.ts` | BrandFlight | **REUSED & EXTENDED** | Extended regex tokenizers beyond Indian PII (PAN/Aadhaar) to include SOC identifiers: IPv4, IPv6, Hostnames, Usernames, API tokens, Windows SIDs, and UUIDs. Prevents leaking infrastructure topology to external public LLMs. |
| `audit-receipts.ts` | BrandFlight | **REUSED & ADAPTED** | Adapted to `evidence-receipt.ts`. Generates immutable, deterministic SHA256 receipts binding hunt parameters, snapshot hashes, and resulting lead arrays. |
| `governance-insights.ts` | BrandFlight | **REUSED & ADAPTED** | Adapted to `kpi-insights.ts`. Aggregates containment exception requests by category (`BUSINESS_CRITICAL`, `RULE_INCORRECT`, `ACCEPTABLE_RISK`, `FALSE_POSITIVE`). |
| `rag_engine.py` | TechFusion | **REUSED & RE-SEEDED** | Re-seeded in-memory hybrid BM25 + TF-IDF engine with MITRE ATT&CK techniques (T1021, T1078, T1059, T1071, T1048) and NIST SP 800-61 containment playbooks. |
| `pdf_generator_r3.py` | TechFusion | **REUSED & RE-TEMPLATED** | Re-templated ReportLab pipeline to generate executive SOC Incident Triage Reports with risk scores, topology exposure, containment actions, and HMAC passport hashes. |
| `cms_simulator.py` | TechFusion | **REUSED & ADAPTED** | Transformed CMS browser guardrail pattern into `soar_simulator.py`. Simulates EDR host isolation (CrowdStrike), IdP account disabling (Okta/Entra), and firewall edge blocking (Palo Alto). Guaranteed dry-run only. |
| `inkloom_engine.py` | TechFusion | **FIXED & HONEST RUNTIME** | Discovered original `model.onnx.data` was a 133-byte Git LFS pointer stub. Replaced silent failure with explicit startup detection, honest `tfidf_fallback` diagnostic reporting, and a documented script `download_inkloom_weights.sh`. |
| `database.py` (In-Memory Dict) | TechFusion | **REPLACED** | Replaced in-memory Python dictionary with PostgreSQL managed through Prisma 7 migrations. |
| `BrandGovernanceEngine` | TechFusion | **REPLACED** | Marketing heuristics (checking for deprecated hex codes and slogans like "crush the competition") were completely replaced by NetworkX graph pattern hunts mapped to MITRE ATT&CK IDs. |
| Image Contrast / OCR | BrandFlight | **DROPPED** | Sharp pixel contrast checking and Cloudinary image uploads were dropped as irrelevant to graph analytics (available under `/legacy/BrandFlight-main` for reference). |

---

## 3. Net-New Components Built For GraphOps

1. **Security Graph Data Model (`analytics/app/graph/`):**
   - 10 OCSF/ECS-inspired Node types: `Host`, `User`, `ServiceAccount`, `Process`, `File`, `IP`, `Domain`, `CloudResource`, `Vulnerability`, `Group`.
   - 8 Typed Relationships: `LOGGED_IN`, `SPAWNED`, `CONNECTED_TO`, `MEMBER_OF`, `HAS_ADMIN`, `TRUSTS`, `CAN_REACH`, `EXPLOITABLE_VIA`.
2. **Telemetry Normaliser & Entity Resolution (`normaliser.py`, `entity_resolution.py`):**
   - Ingests heterogeneous Sysmon, Windows Event Logs (4624, 4672, 1, 3), Zeek conn logs, and AWS CloudTrail into a unified schema.
   - De-duplicates hostnames, IP addresses, agent IDs, and user identities into canonical entities.
3. **Synthetic Enterprise Generator (`synthetic/generator.py`):**
   - Generates configurable 1k, 10k, and 100k node enterprise topologies with seeded RNG (seed=42).
   - Injects 3 ground-truth labelled campaigns:
     - Campaign 1: Phish &rarr; Credential Theft &rarr; Lateral Movement &rarr; Domain Admin takeover.
     - Campaign 2: Insider Data Exfiltration to C2 Drop.
     - Campaign 3: Cloud IAM Key Abuse on S3 Crown Jewel.
4. **Proactive Graph Hunts (`hunts/`):**
   - 7 ATT&CK-mapped pattern detectors: Lateral Movement (T1021.001), Credential Reuse (T1078), Rare Process Spawns (T1059), Periodic Beaconing (T1071), Fan-Out Reconnaissance (T1046), Cross-Community Boundaries (T1484), and Cloud IAM Abuse (T1078.004).
5. **Attack-Path & Choke-Point Analysis (`paths/attack_paths.py`):**
   - Analyzes k-shortest exploitability paths to Crown Jewels.
   - Computes structural choke points (intermediate nodes traversed by the highest number of paths).
6. **Independent-Cascade Blast Radius Simulation (`blast_radius/cascade.py`):**
   - Monte Carlo cascade simulation (50 iterations) with seeded RNG.
   - Computes expected impacted assets, 95% confidence intervals, and crown jewel compromise probabilities.
7. **Containment Knapsack Optimiser (`containment/optimiser.py`):**
   - Selects highest benefit-to-cost containment actions under a business disruption budget.
   - Features What-If residual blast simulator before any human approval.
8. **Empirical Evaluation Harness (`eval/run_eval.py`):**
   - Evaluates real detection P/R/F1 vs ground truth, containment efficiency vs naive baselines, alert reduction ratios, and latency/memory scaling up to 10,000 nodes.
