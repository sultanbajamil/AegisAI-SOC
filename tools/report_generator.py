import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle

DARK_NAVY = colors.HexColor("#0D1B2A")
ACCENT    = colors.HexColor("#B71C1C")
LIGHT_GRAY= colors.HexColor("#F8F9FA")
MID_GRAY  = colors.HexColor("#555555")
WHITE     = colors.white

def generate_incident_pdf(investigation_data: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm
    )

    def ps(name, size, color, font="Helvetica", **kw):
        return ParagraphStyle(name, fontSize=size, textColor=color, fontName=font, **kw)

    title_s = ps("t", 20, DARK_NAVY, "Helvetica-Bold", spaceAfter=2, leading=24)
    sub_s   = ps("sb", 10, ACCENT, "Helvetica-Bold", spaceAfter=4)
    sec_s   = ps("sh", 10, WHITE, "Helvetica-Bold", spaceBefore=6, spaceAfter=4, backColor=DARK_NAVY, leftIndent=-4, rightIndent=-4, leading=14, borderPadding=(3,5,3,5))
    jt_s    = ps("jt", 9, DARK_NAVY, "Helvetica-Bold", spaceBefore=4, spaceAfter=1)
    bd_s    = ps("bd", 8.5, DARK_NAVY, "Helvetica", spaceAfter=2, leading=12)
    code_s  = ps("cd", 8, DARK_NAVY, "Courier", spaceAfter=2, leading=11)

    alert = investigation_data.get("alert", {})
    decision = investigation_data.get("decision", {})
    evidence = investigation_data.get("evidence", {})
    proc = alert.get("process", {})
    net = alert.get("network", {})

    story = []
    story.append(Paragraph("🛡️ AegisAI-SOC: Incident Response Report", title_s))
    story.append(Paragraph(f"INCIDENT REF: {alert.get('id', 'N/A')} | HOST: {alert.get('hostname', 'UNKNOWN')} | SEVERITY: {decision.get('severity', 'CRITICAL')}", sub_s))
    story.append(HRFlowable(width="100%", thickness=0.5, color=ACCENT, spaceAfter=4, spaceBefore=2))

    story.append(Paragraph("1. EXECUTIVE SUMMARY & VERDICT", sec_s))
    verdict = decision.get("verdict", "MALICIOUS")
    score = decision.get("risk_score", 90)
    summary_text = f"<b>Triage Verdict:</b> <font color='#B71C1C'>{verdict}</font> (Risk Score: {score}/100)<br/><br/>" \
                   f"<b>Assessment:</b> {decision.get('analyst_assessment', 'N/A')}"
    story.append(Paragraph(summary_text, bd_s))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2. TELEMETRY & PROCESS ARTIFACT DETAILS", sec_s))
    telemetry_table = [
        [Paragraph("<b>Attribute</b>", jt_s), Paragraph("<b>Observed Telemetry Value</b>", jt_s)],
        [Paragraph("Target Hostname:", bd_s), Paragraph(str(alert.get("hostname")), code_s)],
        [Paragraph("Process / PID:", bd_s), Paragraph(f"{proc.get('name')} (PID: {proc.get('pid')})", code_s)],
        [Paragraph("Parent Process:", bd_s), Paragraph(f"{proc.get('parent_name')} (PID: {proc.get('parent_pid')})", code_s)],
        [Paragraph("Command Line:", bd_s), Paragraph(str(proc.get("command_line")), code_s)],
        [Paragraph("Account:", bd_s), Paragraph(str(proc.get("user", "N/A")), code_s)],
        [Paragraph("Target Network C2:", bd_s), Paragraph(f"{net.get('destination_ip')}:{net.get('destination_port')} ({net.get('protocol')})", code_s)],
        [Paragraph("File SHA256/MD5:", bd_s), Paragraph(str(proc.get("file_hash")), code_s)],
    ]
    t = Table(telemetry_table, colWidths=[4.0*cm, 14.0*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), LIGHT_GRAY),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#E0E0E0")),
        ("PADDING", (0,0), (-1,-1), 3),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 4))

    story.append(Paragraph("3. THREAT INTELLIGENCE & MITRE ATT&CK MAPPING", sec_s))
    mitre_list = evidence.get("mitre_attack_correlation", [])
    if mitre_list:
        m_rows = [[Paragraph("<b>Technique ID</b>", jt_s), Paragraph("<b>Tactic</b>", jt_s), Paragraph("<b>Description</b>", jt_s)]]
        for m in mitre_list:
            m_rows.append([
                Paragraph(f"<b>{m['technique_id']}</b>", code_s),
                Paragraph(m.get("tactic", "N/A"), bd_s),
                Paragraph(f"{m.get('name')}: {m.get('description')}", bd_s)
            ])
        mt = Table(m_rows, colWidths=[3.2*cm, 4.0*cm, 10.8*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), LIGHT_GRAY),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#E0E0E0")),
            ("PADDING", (0,0), (-1,-1), 3),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ]))
        story.append(mt)
    else:
        story.append(Paragraph("No critical MITRE ATT&CK adversary matches logged.", bd_s))
    story.append(Spacer(1, 4))

    story.append(Paragraph("4. REMEDIATION & CONTAINMENT SCRIPT", sec_s))
    script = investigation_data.get("containment_script", "# No containment actions generated.")
    story.append(Paragraph(script.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_s))

    doc.build(story)
    return output_path
