import csv
import io
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

FIELDS = ["severity", "title", "file", "line", "cwe", "owasp", "source", "evidence", "remediation"]


def _rows(scan):
    for f in scan.findings.select_related("file"):
        yield [f.severity, f.title, f.file.filename, f.line, f.cwe, f.owasp, f.source, f.evidence, f.remediation]


def _safe(v):  # prevent CSV/formula injection
    s = str(v)
    return "'" + s if s[:1] in "=+-@" else s


def to_csv(scan):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(FIELDS)
    for r in _rows(scan):
        w.writerow([_safe(c) for c in r])
    return buf.getvalue().encode("utf-8")


def to_pdf(scan):
    buf = io.BytesIO()
    st = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    story = [Paragraph(f"SecureCode AI Report: {escape(scan.title)}", st["Title"]),
             Paragraph(f"Language: {scan.language} | Date: {scan.created_at:%Y-%m-%d %H:%M}", st["Normal"]),
             Paragraph("Findings come from static analysis and may include false positives or miss issues. "
                       "AI suggestions are advisory only.", st["Italic"]), Spacer(1, 12)]
    for r in _rows(scan):
        sev, title, fn, line, cwe, owasp, src, ev, fix = r
        story += [Paragraph(f"<b>[{sev}] {escape(title)}</b> ({escape(fn)}:{line}) {escape(cwe)} {escape(owasp)}", st["Heading4"]),
                  Paragraph(f"Evidence: <font face='Courier'>{escape(ev)}</font>", st["Normal"]),
                  Paragraph("Fix: " + escape(fix).replace("\n", "<br/>"), st["Normal"]), Spacer(1, 8)]
    if len(story) == 4:
        story.append(Paragraph("No findings detected by the configured analyzers.", st["Normal"]))
    doc.build(story)
    return buf.getvalue()
