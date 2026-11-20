"""
Hunt Rule: Credential Reuse Across Unusual Hosts (MITRE ATT&CK T1078).
Detects single account identities authenticating across anomalous host boundaries.
"""

from typing import List, Dict, Any, Optional
import networkx as nx
from app.hunts.registry import BaseHuntRule, HuntLead


class CredentialReuseHunt(BaseHuntRule):
    rule_code = "HUNT-CR-001"
    attack_id = "T1078"
    tactic = "initial-access"
    title = "Credential Reuse Across Disparate Host Assets"
    severity = "HIGH"

    def run(self, G: nx.DiGraph, parameters: Optional[Dict[str, Any]] = None) -> List[HuntLead]:
        leads: List[HuntLead] = []

        # Find user nodes
        user_nodes = [n for n, d in G.nodes(data=True) if str(n).startswith("user:") or d.get("type") in ["User", "ServiceAccount"]]

        for u in user_nodes:
            # Check outgoing LOGGED_IN or HAS_ADMIN edges
            target_hosts = []
            target_edges = []
            has_admin_on_cj = False

            for _, target, d in G.out_edges(u, data=True):
                if d.get("type") in ["LOGGED_IN", "HAS_ADMIN"]:
                    target_hosts.append(target)
                    target_edges.append({
                        "source": u,
                        "target": target,
                        "type": d.get("type"),
                        "timestamp": d.get("timestamp")
                    })
                    if G.nodes.get(target, {}).get("is_crown_jewel"):
                        has_admin_on_cj = True

            # If user has logged in to multiple distinct hosts, especially a workstation AND domain controller
            unique_targets = list(set(target_hosts))
            if len(unique_targets) >= 2 and any(G.nodes.get(t, {}).get("is_crown_jewel") for t in unique_targets):
                score = 88.0 if has_admin_on_cj else 74.0
                host_labels = ", ".join([G.nodes.get(h, {}).get("label", h) for h in unique_targets])
                evidence = (
                    f"User identity '{u}' was observed authenticating across {len(unique_targets)} disparate hosts: [{host_labels}]. "
                    f"Credential appears shared across standard workstations and high-privilege servers."
                )

                leads.append(HuntLead(
                    id=f"LEAD-CR-{len(leads)+1:03d}",
                    rule_code=self.rule_code,
                    attack_id=self.attack_id,
                    tactic=self.tactic,
                    title=f"Credential Abuse: {u} on multiple assets",
                    score=score,
                    severity="HIGH" if has_admin_on_cj else "MEDIUM",
                    nodes_involved=[u] + unique_targets,
                    edges_involved=target_edges,
                    evidence=evidence,
                    mitigation_suggestion=f"Force immediate credential rotation and session revocation for account '{u}'."
                ))

        return leads
