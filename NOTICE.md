# GraphOps — Notices & Credits

GraphOps was built by merging and extending two separate hackathon projects.

## Originals

### BrandFlight
- **Author:** Rudraksh Kumar (sole developer)
- **Licence:** ISC (see `legacy/BrandFlight-main/server/package.json`)
- **Source:** https://github.com/rudrakshkr/BrandFlight
- **Reused components:** JWT auth middleware, PII masking, HMAC passport, audit receipts,
  approval gate, governance-insights aggregation, review validation, WCAG contrast utilities,
  React + Vite client shell, unit test patterns.

### TechFusion Brand Governance
- **Authors:** Yash Singhla (team leader), Rishit Negi, Ramandeep Singh, Aditya Sharma
- **Licence:** No licence file present in the original repository. Included here as shared
  hackathon assets with full attribution. If open-sourcing GraphOps, obtain a written licence
  from the TechFusion team first.
- **Source:** https://github.com/furydarkknight/techfusion-brand-governance3
- **Reused components:** FastAPI + uvicorn server skeleton, BM25/TF-IDF RAG engine
  (re-seeded), ReportLab PDF pipeline (re-templated), ONNX MiniLM engine (with LFS-stub
  fallback), CMS/SOAR simulator pattern.

## GraphOps Team
- Yash Singhla
- Rishit Negi
- Ramandeep Singh
- Aditya Sharma
- Rudraksh Kumar

## Third-Party Licences
All third-party dependencies retain their own licences. See `api/package.json` and
`analytics/requirements.txt` for the full dependency list. MITRE ATT&CK® content used in
the RAG seed is published under the Apache 2.0 licence by The MITRE Corporation.
