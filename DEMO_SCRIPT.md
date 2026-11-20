# GraphOps — 5-Minute Hackathon Judge Demonstration Script

> **Problem Statement:** Graph analytics for proactive threat hunting and blast radius containment in Security Operations Centers (SOCs).

---

## Prerequisites (Pre-seeded Demo)
1. Run services: `docker compose up` (or `make up-dev` / separate local dev servers).
2. Seed database & demo scenario: `make seed`.
3. Open browser at **http://localhost:5173**.

---

## 5-Minute Walkthrough Scenario

### Step 1: Role-Based Authentication & SOC Landing (0:00 - 0:45)
1. Navigate to `http://localhost:5173/login`.
2. Click **SOC Analyst** preset (`analyst@graphops.demo`). Click **Sign In**.
3. **What to show judges:**
   - Server-enforced JWT authentication.
   - User role badge: **SOC Analyst** in the upper right.
   - Top health indicator: `LLM: rag_only | Model: tfidf_fallback` (honestly reporting deterministic mode).
   - High-level SOC KPI strip: 78.0% alert reduction ratio, Crown Jewels protected.

### Step 2: Ingesting Telemetry & Alert Correlation (0:45 - 1:30)
1. On the Dashboard control deck, click **"1. Ingest Graph"**.
   - Generates and normalizes 1,000-node synthetic enterprise network (seed=42).
2. Click **"2. Correlate Alerts"**.
   - Simulates a raw SIEM alert flood (50 noisy alerts across workstations and servers).
   - GraphOps correlates topological proximity and temporal windows.
   - **What to show judges:** Notice: *50 raw alerts collapsed into prioritized incidents — 78.0% alert noise reduction.*

### Step 3: Proactive ATT&CK Graph Hunting (1:30 - 2:30)
1. Click **"3. Run Proactive Hunts"** on the Dashboard (or open the **Proactive Hunts** tab).
2. **What to show judges:**
   - Ranked leads sorted by descending risk score.
   - Expand `LEAD-LM-001` (**Lateral Movement via Remote Desktop - T1021.001**).
   - Evidence explains the exact path: `WS-0014 -> SRV-003 -> DC-01 (Domain Controller)`.
   - Cryptographic Evidence Receipt ID recorded on PostgreSQL.
3. Click **"Inspect On Graph"**.
   - Opens Cytoscape.js interactive topology.
   - Notice the Crown Jewel diamond node `DC-01` glowing crimson.

### Step 4: Blast Radius & Independent Cascade Simulation (2:30 - 3:30)
1. Select compromised foothold node `host:ws-0014`.
2. Click **"Simulate Blast Radius"** in the Node Drawer.
3. **What to show judges:**
   - Independent-cascade Monte Carlo simulation (seed=42).
   - Expected Impacted Assets: `14 nodes` with 95% Confidence Interval.
   - Risk Score: `88.5 / 100` (Crown Jewel Exposure: **EXPOSED - HIGH RISK**).
   - Hop-by-hop reachability animation across network layers.

### Step 5: Containment Optimization & What-If Simulation (3:30 - 4:15)
1. Open the **Containment** tab.
2. The **Containment Optimiser** proposes knapsack actions under business disruption budget:
   - Action 1: `ISOLATE_HOST -> host:ws-0014`
   - Action 2: `DISABLE_ACCOUNT -> user:it-admin-priv`
   - Action 3: `BLOCK_EDGE -> host:srv-003 -> host:dc01`
3. Click **"Run What-If Simulation"**.
   - **What to show judges:** Pre-action risk drops from **88.5** to **12.0** (**81.2% risk reduction**).
   - Residual blast radius shows Crown Jewels are completely secured BEFORE touching production.

### Step 6: SOC Manager Approval & Tamper-Evident Passport (4:15 - 5:00)
1. Log out, then click **SOC Manager** preset (`manager@graphops.demo`) and sign in.
2. Under Containment, the green **"Approve & Execute (Simulated SOAR)"** button is now active.
3. Click **Approve**.
   - SOAR simulator verifies simulated EDR quarantine and IdP session revocation.
4. Open the Incident and click **"Issue Release Passport"**.
   - HMAC-SHA256 signature generated over canonical JSON snapshot.
5. Click **"Download PDF Report"** -> Opens ReportLab PDF with timeline, blast radius, and signature.
6. Open `/verify` (Public Verification):
   - Paste the passport ID -> **VERIFIED AUTHENTIC & UNTAMPERED**.
   - Click **"Demonstrate Tamper Detection (Flip 1 Byte)"** -> **VERIFICATION FAILED / TAMPER DETECTED**.
   - Proves mathematical immutability to judges!
