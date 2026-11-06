
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(alerts_df):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph("SOC SENTINEL - SECURITY INCIDENT REPORT", styles["Title"])
    )
    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph(f"Total Security Alerts: {len(alerts_df)}", styles["Heading2"])
    )
    elements.append(Spacer(1, 15))

    if alerts_df.empty:
        elements.append(Paragraph("No security alerts detected.", styles["Normal"]))
    else:
        data = [["Severity", "Alert Type", "Source IP", "Count"]]

        for _, row in alerts_df.iterrows():
            data.append([
                str(row["severity"]),
                str(row["alert_type"]),
                str(row["source_ip"]),
                str(row["count"])
            ])

        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 7),
        ]))

        elements.append(table)

    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph(
            "Note: These alerts are rule-based indicators and require analyst review.",
            styles["Italic"]
        )
    )

    doc.build(elements)
    buffer.seek(0)

    return buffer.getvalue()

