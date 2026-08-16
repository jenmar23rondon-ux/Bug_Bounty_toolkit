from __future__ import annotations

from pathlib import Path

REPORT_TEMPLATE = """# {id} - {title}

## Summary
{summary}

## Severity
{severity}

## Category
{category}

## Affected Target
{target}

## Evidence
{evidence_path}

## Reproduction Notes
Document only actions permitted by the program policy. Include test accounts, timestamps, request IDs, screenshots, and response differences where relevant.

## Impact
Explain what an unauthorized user could access or change, the affected data class, and the business risk.

## Remediation
Describe the expected authorization, validation, configuration, or business-rule control.
"""


def render_markdown(finding, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = dict(finding)
    if not data.get("evidence_path"):
        data["evidence_path"] = "Evidence path not attached yet."
    destination.write_text(REPORT_TEMPLATE.format(**data), encoding="utf-8")
    return destination


def render_pdf(markdown_path: Path, pdf_path: Path) -> Path:
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ModuleNotFoundError:
        render_minimal_pdf(markdown_path, pdf_path)
        return pdf_path

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(pdf_path), pagesize=LETTER, title=markdown_path.stem)
    story = []
    for raw_line in markdown_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            story.append(Spacer(1, 8))
        elif line.startswith("# "):
            story.append(Paragraph(line[2:], styles["Title"]))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], styles["Heading2"]))
        else:
            story.append(Paragraph(line, styles["BodyText"]))
    document.build(story)
    return pdf_path


def render_minimal_pdf(markdown_path: Path, pdf_path: Path) -> None:
    lines = markdown_path.read_text(encoding="utf-8").splitlines()
    content_lines = ["BT", "/F1 11 Tf", "50 750 Td"]
    first = True
    for line in lines[:45]:
        text = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if first:
            first = False
        else:
            content_lines.append("0 -16 Td")
        content_lines.append(f"({text}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    pdf_path.write_bytes(pdf)
