"""
Semantic & BM25 Hybrid RAG Engine for SOC Operations & MITRE ATT&CK Playbooks.
Reused and adapted from TechFusion's in-memory TF-IDF + BM25 retrieval engine.
Deterministic, runs in-memory without external vector DB dependencies.
"""

import re
import math
import datetime
from typing import List, Dict, Any, Tuple


class SecurityRAGEngine:
    """
    Vector-Grounded Hybrid RAG over MITRE ATT&CK techniques, SOC response playbooks,
    and incident triage procedures.
    """

    def __init__(self):
        self.documents: List[Dict[str, Any]] = []
        self.chunks: List[Dict[str, Any]] = []
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self._load_security_playbook_knowledge_base()

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        words = re.findall(r"\b[a-z0-9\'-]{2,}\b", text)
        stop_words = {
            "the", "and", "is", "in", "to", "of", "for", "with", "a", "an", "as",
            "at", "by", "from", "on", "that", "this", "are", "be", "or", "it", "we"
        }
        return [w for w in words if w not in stop_words]

    def _load_security_playbook_knowledge_base(self):
        seed_docs = [
            {
                "id": "PB-IR-01",
                "title": "SOC Playbook: Lateral Movement Containment & Remediation (T1021)",
                "category": "Containment Playbook",
                "source": "NIST-SP-800-61-Lateral-Movement.md",
                "content": (
                    "When lateral movement (T1021.001 RDP, T1021.002 SMB) is detected traversing toward high-value assets, "
                    "responders must immediately isolate the pivot workstation using EDR network quarantine. "
                    "All Kerberos ticket granting tickets (TGT) and active session tokens for the affected user accounts "
                    "must be revoked via Active Directory or cloud IdP. Check all intermediate jump boxes and servers "
                    "for cached credentials in LSASS memory. Ensure secondary Domain Controllers remain isolated until "
                    "integrity verification is signed by the SOC Manager."
                )
            },
            {
                "id": "PB-IR-02",
                "title": "SOC Playbook: Credential Dumping & Privilege Escalation (T1078, T1003)",
                "category": "Identity Security",
                "source": "CISA-AA23-Privilege-Abuse-Guide.md",
                "content": (
                    "Valid account abuse (T1078) across disparate network segments signals compromised administrative credentials. "
                    "Recommended containment includes immediate password resets across on-premise AD and Entra ID / Okta. "
                    "Review access control lists (ACLs) on sensitive security groups (Domain Admins, Enterprise Admins). "
                    "Rotate all service account passwords and invalidate refresh tokens. Never execute containment without "
                    "recording cryptographic evidence receipts of the active graph snapshot and alert state."
                )
            },
            {
                "id": "PB-IR-03",
                "title": "SOC Playbook: Insider Data Exfiltration & C2 Drops (T1048, T1071)",
                "category": "Exfiltration Mitigation",
                "source": "MITRE-ATT&CK-T1048-Mitigation.md",
                "content": (
                    "Outbound periodic beaconing (T1071) or bulk transfer exceeding standard baseline metrics indicates active exfiltration. "
                    "Action steps: Deploy emergency egress block on perimeter next-gen firewalls for the identified destination IP/domain. "
                    "Isolate the source endpoint to freeze RAM state for volatile forensic capture. "
                    "Enforce TLS inspection rules and review database transaction logs for unauthorized export queries."
                )
            },
            {
                "id": "PB-IR-04",
                "title": "SOC Playbook: Cloud IAM Key Compromise & Object Storage Abuse (T1078.004, T1530)",
                "category": "Cloud Incident Response",
                "source": "AWS-Security-Incident-Response-Guide.md",
                "content": (
                    "Anomalous API calls from untrusted external IPs utilizing long-lived access keys require instant deactivation. "
                    "Apply an explicit inline deny policy on the IAM principal to halt current permissions immediately. "
                    "Enable S3 object lock and review CloudTrail management events for GetObject and PutBucketPolicy activity. "
                    "Rotate access keys and enforce temporary session credentials via AWS STS and IAM Identity Center."
                )
            },
            {
                "id": "PB-IR-05",
                "title": "GraphOps Blast Radius Containment & Minimum Disruption Standards",
                "category": "Operational Governance",
                "source": "GraphOps-Architecture-Standard-2026.md",
                "content": (
                    "Containment actions must be optimized against business disruption budgets before execution. "
                    "Isolating a Tier-0 asset (Domain Controller, Core ERP) carries maximum disruption and requires "
                    "explicit SOC Manager approval with structured justification. "
                    "Graph choke points that sever multiple intersecting attack paths should be prioritized for surgical "
                    "firewall edge blocks rather than wholesale node isolation."
                )
            }
        ]

        for doc in seed_docs:
            self.ingest_document(doc["id"], doc["title"], doc["category"], doc["content"], doc["source"])

    def ingest_document(self, doc_id: str, title: str, category: str, content: str, source: str):
        doc = {"id": doc_id, "title": title, "category": category, "content": content, "source": source}
        self.documents.append(doc)

        # Chunk into paragraphs
        paragraphs = [p.strip() for p in content.split("\n\n") if len(p.strip()) > 30]
        if not paragraphs:
            paragraphs = [content]

        for p_idx, para in enumerate(paragraphs):
            tokens = self._tokenize(para)
            self.chunks.append({
                "chunk_id": f"{doc_id}-C{p_idx+1}",
                "doc_id": doc_id,
                "title": title,
                "category": category,
                "source": source,
                "text": para,
                "tokens": tokens,
                "tf": self._compute_tf(tokens)
            })

        self._recompute_idf()

    def _compute_tf(self, tokens: List[str]) -> Dict[str, float]:
        tf: Dict[str, float] = {}
        total = len(tokens)
        if total == 0:
            return tf
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1.0
        return {k: v / total for k, v in tf.items()}

    def _recompute_idf(self):
        N = len(self.chunks)
        df: Dict[str, int] = {}
        for c in self.chunks:
            for t in set(c["tokens"]):
                df[t] = df.get(t, 0) + 1
        self.idf = {t: math.log((N - count + 0.5) / (count + 0.5) + 1.0) for t, count in df.items()}

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        q_tf = self._compute_tf(query_tokens)
        scores: List[Tuple[float, Dict[str, Any]]] = []

        for chunk in self.chunks:
            score = 0.0
            # BM25 + TF-IDF hybrid
            for t, q_weight in q_tf.items():
                if t in chunk["tf"]:
                    idf_val = self.idf.get(t, 0.5)
                    tf_val = chunk["tf"][t]
                    # BM25 term weight
                    bm25_term = idf_val * (tf_val * 2.2) / (tf_val + 1.2 * (0.25 + 0.75 * (len(chunk['tokens']) / 60.0)))
                    score += bm25_term

            if score > 0.01:
                scores.append((score, chunk))

        scores.sort(key=lambda x: x[0], reverse=True)
        results = []
        for s, c in scores[:top_k]:
            results.append({
                "id": c["chunk_id"],
                "title": c["title"],
                "category": c["category"],
                "source": c["source"],
                "content": c["text"],
                "score": round(float(s), 3)
            })
        return results


security_rag = SecurityRAGEngine()
