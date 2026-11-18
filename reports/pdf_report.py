"""
reports/pdf_report.py

Generates a PDF version of the scan report using ReportLab (pure Python,
no system packages). Built from the SAME ScanResult and the same shared
summaries as the HTML/JSON reports, so all three always agree.

Escaping: ReportLab Paragraph text is a small XML dialect, so every
scan-derived string is escaped with xml.sax.saxutils.escape() before use.
Evidence is shown in a monospaced Preformatted-style paragraph.
"""

import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from analysis.findings import group_by_category, sort_findings
from analysis.risk import risk_from_score_result
from analysis.summary import (
    SEVERITY_DISPLAY_ORDER, category_summary, pass_count, severity_counts,
)
from reports.html_report import (
    LIMITATIONS_TEXT, SCORE_BAND_COLORS, SEVERITY_COLORS, build_executive_summary_text,
)
from scan_controller import ScanResult
from utils.errors import explain_error

# Keep a single pathological evidence string from producing a huge PDF.
MAX_EVIDENCE_CHARS = 2000


def _x(value) -> str:
    return escape(str(value))


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=4, alignment=0),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9.5, leading=13),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#5b6673")),
        "label": ParagraphStyle("l", parent=base["BodyText"], fontSize=8, leading=10,
                                textColor=colors.HexColor("#5b6673"), spaceBefore=4),
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=8, leading=10,
                               backColor=colors.HexColor("#f3f5f7"), borderPadding=3),
        "cell": ParagraphStyle("c", parent=base["BodyText"], fontSize=8.5, leading=10.5),
    }


def _table(data, col_widths, header=True):
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5dbe1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f4f7")))
    t.setStyle(TableStyle(style))
    return t


def generate_pdf_report(
    scan_result: ScanResult,
    include_evidence: bool = True,
    include_recommendations: bool = True,
) -> bytes:
    """Return the report as PDF bytes."""
    st = _styles()
    score = scan_result.score_result
    risk = risk_from_score_result(score)
    band_color = SCORE_BAND_COLORS.get(score.category, "#555555")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="Web Application Security Audit Report", author="Web Application Security Auditing Tool",
    )
    width = A4[0] - 32 * mm
    story = []

    story.append(Paragraph("WEB APPLICATION SECURITY AUDIT REPORT", st["title"]))
    story.append(Paragraph("Automated, non-destructive configuration scan. Use only on systems you own "
                           "or are explicitly authorized to test.", st["small"]))
    story.append(Spacer(1, 8))
    story.append(_table([
        [Paragraph("<b>Target</b>", st["cell"]), Paragraph(_x(scan_result.target_url), st["cell"])],
        [Paragraph("<b>Scan date/time</b>", st["cell"]), Paragraph(_x(scan_result.scan_timestamp), st["cell"])],
        [Paragraph("<b>Scan status</b>", st["cell"]), Paragraph(_x(scan_result.scan_status), st["cell"])],
        [Paragraph("<b>Security score</b>", st["cell"]),
         Paragraph(f"<font color='{band_color}'><b>{score.score} / 100</b></font> ({_x(score.category)})", st["cell"])],
        [Paragraph("<b>Overall risk</b>", st["cell"]),
         Paragraph(f"<font color='{band_color}'><b>{_x(risk.label)}</b></font>", st["cell"])],
    ], [38 * mm, width - 38 * mm], header=False))

    story.append(Paragraph("Executive Summary", st["h2"]))
    story.append(Paragraph(_x(build_executive_summary_text(scan_result)), st["body"]))

    story.append(Paragraph("Severity Summary", st["h2"]))
    counts = severity_counts(scan_result.findings)
    header = [Paragraph(f"<b>{_x(level)}</b>", st["cell"]) for level in SEVERITY_DISPLAY_ORDER] + \
             [Paragraph("<b>Passed</b>", st["cell"])]
    values = [Paragraph(f"<font color='{SEVERITY_COLORS[level]}'><b>{counts[level]}</b></font>", st["cell"])
              for level in SEVERITY_DISPLAY_ORDER] + [Paragraph(f"<b>{pass_count(scan_result.findings)}</b>", st["cell"])]
    story.append(_table([header, values], [width / 6] * 6))

    story.append(Paragraph("Category Summary", st["h2"]))
    rows = [[Paragraph(f"<b>{h}</b>", st["cell"]) for h in
             ("Category", "Result", "Checks", "Issues", "Passed", "Not completed", "Points deducted")]]
    for r in category_summary(scan_result.findings, score, scan_result.module_outcomes):
        rows.append([Paragraph(_x(v), st["cell"]) for v in
                     (r["category"], r["state"], r["checks"], r["issues"], r["passed"], r["errors"], r["points_deducted"])])
    story.append(_table(rows, [34 * mm, 30 * mm, 16 * mm, 16 * mm, 16 * mm, 24 * mm, width - 136 * mm]))

    problems = scan_result.partial_outcomes + scan_result.failed_outcomes
    if problems:
        story.append(Paragraph("Scan Warnings", st["h2"]))
        story.append(Paragraph("These checks did not fully run and are NOT reported as passed.", st["body"]))
        wrows = [[Paragraph("<b>Category</b>", st["cell"]), Paragraph("<b>Status</b>", st["cell"]),
                  Paragraph("<b>Reason</b>", st["cell"])]]
        for o in problems:
            info = explain_error(o.detail or "")
            wrows.append([
                Paragraph(_x(o.name), st["cell"]),
                Paragraph("Could not be completed" if o.status == "failed" else "Partially completed", st["cell"]),
                Paragraph(f"{_x(info.summary)}<br/>{_x(info.technical)}", st["cell"]),
            ])
        story.append(_table(wrows, [34 * mm, 36 * mm, width - 70 * mm]))

    story.append(Paragraph("Detailed Findings", st["h2"]))
    for category, items in group_by_category(scan_result.findings).items():
        story.append(Paragraph(f"{_x(category)} ({len(items)})", st["h3"]))
        for f in sort_findings(items):
            color = SEVERITY_COLORS.get(f.severity, "#555555")
            block = [
                Paragraph(f"<font color='{color}'><b>[{_x(f.severity.upper())}]</b></font> <b>{_x(f.title)}</b> "
                          f"<font size=8 color='#6b7683'>{_x(f.check_id)}</font>", st["body"]),
                Paragraph(f"Category / scanner: {_x(f.category)}"
                          + (" &middot; Check could not be completed" if f.status == "Error" else ""), st["small"]),
                Paragraph("DESCRIPTION", st["label"]), Paragraph(_x(f.description), st["body"]),
            ]
            if include_evidence:
                evidence = f.evidence if len(f.evidence) <= MAX_EVIDENCE_CHARS else f.evidence[:MAX_EVIDENCE_CHARS] + "..."
                # Replace newlines so Paragraph keeps line breaks; escape first.
                block += [Paragraph("EVIDENCE", st["label"]),
                          Paragraph(_x(evidence).replace("\n", "<br/>"), st["mono"])]
            block += [Paragraph("IMPACT", st["label"]), Paragraph(_x(f.impact), st["body"])]
            if include_recommendations:
                block += [Paragraph("RECOMMENDATION", st["label"]), Paragraph(_x(f.recommendation), st["body"])]
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block[:4]))
            story.extend(block[4:])

    story.append(Paragraph("Limitations", st["h2"]))
    story.append(Paragraph(_x(LIMITATIONS_TEXT), st["body"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Report generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", st["small"]))

    doc.build(story)
    return buffer.getvalue()
