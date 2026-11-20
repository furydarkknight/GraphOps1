"""
Hunt Rule: Cloud IAM Key Compromise & Object Storage Abuse (MITRE ATT&CK T1078.004 / T1530).
Detects external identities accessing internal cloud buckets and sensitive cloud resources.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class CloudAbuseHunt(BaseHuntRule):
    rule_code = "HUNT-CA-001"
    attack_id = "T1078.004"
    tactic = "credential-access"
    title = "Cloud IAM Key Abuse & S3 Access"
    severity = "CRITICAL"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []

        for u, v, d in G.edges(data=True):
            if d.get("type") == "CAN_REACH":
                v_data = G.nodes.get(v, {})
                v_type = v_data.get("type")
                is_cloud = str(v).startswith("cloud:") or v_type in ["CloudResource", "CloudStorage"]

                if is_cloud:
                    # Check if source is external IP or service account
                    is_suspicious = str(u).startswith("ip:") or str(u).startswith("user:service-account") or d.get("source_log") == "cloudtrail"
                    if is_suspicious or d.get("attack") in ["T1078.004", "T1530"]:
                        score = 95.0 if v_data.get("is_crown_jewel") else 82.0
                        evidence = (
                            f"Anomalous cloud IAM traversal: principal '{u}' accessed sensitive cloud resource '{v}'. "
                            f"Action details: {d.get('properties', {}).get('event', d.get('event', 'GetObject'))}. "
                            f"Log telemetry source: {d.get('source_log', 'cloudtrail')}."
                        )
                        leads.append(HuntLead(
                            id=f"LEAD-CA-{len(leads)+1:03d}",
                            rule_code=self.rule_code,
                            attack_id=self.attack_id,
                            tactic=self.tactic,
                            title=f"Cloud IAM Access: {u} -> {v}",
                            score=score,
                            severity="CRITICAL" if score >= 90 else "HIGH",
                            nodes_involved=[u, v],
                            edges_involved=[{"source": u, "target": v, "type": "CAN_REACH", "timestamp": d.get("timestamp")}],
                            evidence=evidence,
                            mitigation_suggestion=f"Apply inline deny policy on IAM principal '{u}' and revoke active STS session tokens."
                        ))

        return leads
