"""
Hunt Rule: Periodic Beaconing to External C2 Drop (MITRE ATT&CK T1071).
Detects internal assets maintaining regular cadence communication with untrusted external destinations.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class BeaconingHunt(BaseHuntRule):
    rule_code = "HUNT-BC-001"
    attack_id = "T1071"
    tactic = "command-and-control"
    title = "Periodic Command-and-Control Beaconing"
    severity = "HIGH"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []

        # Find edges directed to external IPs or domains
        for u, v, d in G.edges(data=True):
            if d.get("type") == "CONNECTED_TO":
                v_str = str(v)
                v_data = G.nodes.get(v, {})
                threat_intel = v_data.get("threat_intel") or d.get("threat_intel")
                interval_sec = d.get("interval_sec") or d.get("properties", {}).get("interval_sec")
                bytes_out = d.get("bytes_out") or d.get("properties", {}).get("bytes_out", 0)

                # Heuristic: flagged threat intel, or periodic intervals, or high volume out to public IP
                if threat_intel or interval_sec or bytes_out > 100000000 or d.get("attack") in ["T1048", "T1071"]:
                    score = 92.0 if (threat_intel or interval_sec) else 75.0
                    evidence = (
                        f"Host '{u}' exhibits periodic beaconing connectivity to external destination '{v}'. "
                        f"Transfer telemetry: {bytes_out} bytes outbound, cadence interval: {interval_sec or 60}s. "
                        f"Target metadata: {threat_intel or 'Suspicious external endpoint'}."
                    )
                    leads.append(HuntLead(
                        id=f"LEAD-BC-{len(leads)+1:03d}",
                        rule_code=self.rule_code,
                        attack_id=self.attack_id,
                        tactic=self.tactic,
                        title=f"C2 Beaconing: {u} -> {v}",
                        score=score,
                        severity="HIGH",
                        nodes_involved=[u, v],
                        edges_involved=[{"source": u, "target": v, "type": "CONNECTED_TO", "timestamp": d.get("timestamp")}],
                        evidence=evidence,
                        mitigation_suggestion=f"Enforce egress block on firewall for external endpoint '{v}' and isolate host '{u}'."
                    ))

        return leads
