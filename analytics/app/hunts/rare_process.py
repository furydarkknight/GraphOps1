"""
Hunt Rule: Rare Parent-Child Process Spawn (MITRE ATT&CK T1059).
Detects unusual process executions (e.g., Office/Explorer spawning PowerShell or command shells).
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class RareProcessHunt(BaseHuntRule):
    rule_code = "HUNT-RP-001"
    attack_id = "T1059"
    tactic = "execution"
    title = "Anomalous Parent-Child Process Spawn"
    severity = "MEDIUM"

    SUSPICIOUS_SPAWNS = [
        ("word.exe", "powershell.exe"),
        ("excel.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("outlook.exe", "powershell.exe"),
        ("wmiprvse.exe", "powershell.exe")
    ]

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []

        for u, v, d in G.edges(data=True):
            if d.get("type") == "SPAWNED":
                u_label = str(G.nodes.get(u, {}).get("label", u)).lower()
                v_label = str(G.nodes.get(v, {}).get("label", v)).lower()
                cmdline = str(d.get("cmdline", "")).lower()

                is_suspicious = False
                if "powershell" in v_label and ("word" in u_label or "excel" in u_label or "enc" in v_label or "jabc" in cmdline):
                    is_suspicious = True
                elif any(p in u_label and c in v_label for p, c in self.SUSPICIOUS_SPAWNS):
                    is_suspicious = True

                if is_suspicious or d.get("attack") == "T1059.001":
                    score = 90.0 if "enc" in v_label or "enc" in cmdline else 72.0
                    evidence = (
                        f"Anomalous process tree observed on host '{u}': parent '{u_label}' spawned "
                        f"script interpreter '{v_label}' with anomalous command arguments: {d.get('properties', {}).get('cmdline', d.get('cmdline', 'N/A'))}."
                    )
                    leads.append(HuntLead(
                        id=f"LEAD-RP-{len(leads)+1:03d}",
                        rule_code=self.rule_code,
                        attack_id=self.attack_id,
                        tactic=self.tactic,
                        title=f"Suspicious Process Spawn: {v_label} by {u_label}",
                        score=score,
                        severity="HIGH" if score >= 85 else "MEDIUM",
                        nodes_involved=[u, v],
                        edges_involved=[{"source": u, "target": v, "type": "SPAWNED", "timestamp": d.get("timestamp")}],
                        evidence=evidence,
                        mitigation_suggestion=f"Terminate process '{v_label}' and quarantine host '{u}'."
                    ))

        return leads
