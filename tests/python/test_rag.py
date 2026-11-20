import pytest
from app.rag.engine import SecurityRAGEngine


def test_rag_search_lateral_movement():
    rag = SecurityRAGEngine()
    results = rag.search("lateral movement remote desktop RDP T1021", top_k=3)
    assert len(results) > 0
    top_doc = results[0]
    assert "score" in top_doc
    assert top_doc["score"] > 0
    assert "source" in top_doc
    assert "title" in top_doc
    assert any(term in top_doc["content"].lower() or term in top_doc["title"].lower() for term in ["lateral", "movement", "t1021"])


def test_rag_search_credential_dumping():
    rag = SecurityRAGEngine()
    results = rag.search("credential dumping LSASS privilege escalation T1078", top_k=3)
    assert len(results) > 0
    top_doc = results[0]
    assert "credential" in top_doc["content"].lower() or "privilege" in top_doc["content"].lower()
    assert len(top_doc["source"]) > 0
