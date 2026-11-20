"""
PDF Incident Report Generator for GraphOps.
Reused and re-templated from TechFusion's ReportLab pipeline.
Generates audit-ready executive PDF incident summaries including graph blast radius,
containment decisions, and cryptographic HMAC passport hashes.
"""

import io
import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_incident_report_pdf(incident: Dict[str, Any]) -> bytes:
    """
    Generates a PDF incident report bytes stream.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Palette
    c_primary = colors.HexColor("#0F172A")    # Slate 900
    c_accent = colors.HexColor("#2563EB")     # Blue 600
    c_danger = colors.HexColor("#DC2626")     # Red 600
    c_dark = colors.HexColor("#1E293B")
    c_light = colors.HexColor("#F8FAFC")
    c_border = colors.HexColor("#CBD5E1")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=c_primary,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=c_accent,
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_primary,
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=c_dark,
        spaceAfter=3
    )

    story = []

    # Title Banner
    story.append(Paragraph("GraphOps — Incident Triage & Blast Radius Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Security Operations Center", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceAfter=10))

    # Section 1: Executive Summary
    story.append(Paragraph("1. Incident Overview", h1_style))
    inc_id = incident.get("id", "INC-DEMO")
    inc_title = incident.get("title", "Active Threat Investigation")
    inc_sev = incident.get("severity", "HIGH")
    inc_status = incident.get("status", "OPEN")

    meta_table_data = [
        [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(str(inc_id), body_style),
         Paragraph("<b>Severity:</b>", body_style), Paragraph(f"<font color='{c_danger}'><b>{inc_sev}</b></font>", body_style)],
        [Paragraph("<b>Incident Title:</b>", body_style), Paragraph(str(inc_title), body_style),
         Paragraph("<b>Status:</b>", body_style), Paragraph(str(inc_status), body_style)],
    ]
    meta_table = Table(meta_table_data, colWidths=[100, 200, 80, 160])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_light),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Section 2: Blast Radius & Attack Paths
    story.append(Paragraph("2. Graph Analytics: Blast Radius & Exposure", h1_style))
    br = incident.get("blastRadius") or {}
    risk_score = br.get("risk_score", 75.0)
    impacted = br.get("impacted_nodes", [])
    cj_exposure = br.get("crown_jewel_exposure", True)

    br_summary = (
        f"Graph simulation estimates a residual risk score of <b>{risk_score}/100</b>. "
        f"Potentially impacted topology assets: <b>{len(impacted)} nodes</b> across hop tiers. "
        f"Crown Jewel Exposure Detected: <b>{'YES - HIGH RISK' if cj_exposure else 'NO'}</b>."
    )
    story.append(Paragraph(br_summary, body_style))
    story.append(Spacer(1, 8))

    # Section 3: Approved Containment Actions
    story.append(Paragraph("3. Containment Decisions & SOAR Operations", h1_style))
    plans = incident.get("containmentPlans", [])
    if plans:
        plan = plans[0]
        actions = plan.get("actions", [])
        act_rows = [["Action ID", "Type", "Target", "Status"]]
        for a in actions:
            act_rows.append([
                str(a.get("action_id", "ACT-01")),
                str(a.get("action_type", "ISOLATE")),
                str(a.get("target", "N/A")),
                str(plan.get("status", "PENDING"))
            ])
        act_table = Table(act_rows, colWidths=[80, 140, 220, 100])
        act_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), c_accent),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BOX', (0,0), (-1,-1), 1, c_border),
            ('INNERGRID', (0,0), (-1,-1), 0.5, c_border),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(act_table)
    else:
        story.append(Paragraph("No containment plan approved yet.", body_style))
    story.append(Spacer(1, 10))

    # Section 4: Cryptographic Incident Passport
    story.append(Paragraph("4. Incident Passport & Audit Verification", h1_style))
    passport = incident.get("passport") or {}
    passport_hash = passport.get("passportHash", "UNISSUED-PENDING-APPROVAL")
    issued_at = passport.get("issuedAt", "N/A")

    pass_box_data = [
        [Paragraph("<b>Cryptographic HMAC-SHA256 Hash:</b>", body_style)],
        [Paragraph(f"<code>{passport_hash}</code>", body_style)],
        [Paragraph(f"<b>Issued At:</b> {issued_at} | <b>Algorithm:</b> HMAC-SHA256 Canonical JSON", body_style)]
    ]
    pass_table = Table(pass_box_data, colWidths=[540])
    pass_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_light),
        ('BOX', (0,0), (-1,-1), 1, c_accent),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(pass_table)

    # Footer notice
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray, spaceAfter=6))
    story.append(Paragraph("<i>GraphOps SOC Platform — Graph Analytics, Proactive Threat Hunting & Cryptographic Audit Integrity</i>", body_style))

    doc.build(story)
    return buffer.getvalue()
