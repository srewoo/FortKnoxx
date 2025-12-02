"""
PDF Security Report Generator
Generates professional PDF security reports with charts, tables, and executive summaries
"""

import io
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

logger = logging.getLogger(__name__)


class PDFSecurityReport:
    """Generate professional security PDF reports"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2563eb'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        ))

        # Executive summary
        self.styles.add(ParagraphStyle(
            name='Executive',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=16,
            textColor=colors.HexColor('#374151')
        ))

        # Critical alert
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold',
            spaceAfter=10
        ))

    def generate_report(
        self,
        repo_data: Dict[str, Any],
        scan_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generate PDF security report

        Args:
            repo_data: Repository information
            scan_data: Scan metadata
            vulnerabilities: List of vulnerabilities
            output_path: Optional file path to save PDF

        Returns:
            PDF bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        # Build report content
        story = []

        # Cover page
        story.extend(self._create_cover_page(repo_data, scan_data))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._create_executive_summary(vulnerabilities, scan_data))
        story.append(PageBreak())

        # Vulnerability overview
        story.extend(self._create_overview_section(vulnerabilities))
        story.append(PageBreak())

        # Detailed findings
        story.extend(self._create_detailed_findings(vulnerabilities))

        # Appendix
        story.append(PageBreak())
        story.extend(self._create_appendix(scan_data))

        # Build PDF
        doc.build(story)

        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()

        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)

        return pdf_bytes

    def _create_cover_page(self, repo_data: Dict, scan_data: Dict) -> List:
        """Create cover page"""
        elements = []

        # Title
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(
            "Security Assessment Report",
            self.styles['CustomTitle']
        ))
        elements.append(Spacer(1, 0.5*inch))

        # Repository info
        repo_name = repo_data.get('name', 'Unknown Repository')
        elements.append(Paragraph(
            f"<b>Repository:</b> {repo_name}",
            self.styles['Executive']
        ))
        elements.append(Spacer(1, 0.2*inch))

        # Scan date
        scan_date = scan_data.get('created_at', datetime.now().isoformat())
        if isinstance(scan_date, str):
            scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))

        elements.append(Paragraph(
            f"<b>Scan Date:</b> {scan_date.strftime('%B %d, %Y at %H:%M UTC')}",
            self.styles['Executive']
        ))
        elements.append(Spacer(1, 0.2*inch))

        # Status
        status = scan_data.get('status', 'completed')
        elements.append(Paragraph(
            f"<b>Status:</b> {status.upper()}",
            self.styles['Executive']
        ))

        # Footer
        elements.append(Spacer(1, 3*inch))
        elements.append(Paragraph(
            "Generated by FortKnoxx Security Platform",
            ParagraphStyle(
                name='Footer',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.gray,
                alignment=TA_CENTER
            )
        ))

        return elements

    def _create_executive_summary(self, vulnerabilities: List[Dict], scan_data: Dict) -> List:
        """Create executive summary with charts"""
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))

        # Overall statistics
        total_vulns = len(vulnerabilities)
        severity_counts = Counter(v.get('severity', 'info') for v in vulnerabilities)

        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        medium_count = severity_counts.get('medium', 0)
        low_count = severity_counts.get('low', 0)

        # Risk assessment
        if critical_count >= 5:
            risk_level = "CRITICAL"
            risk_color = colors.HexColor('#dc2626')
        elif critical_count > 0 or high_count >= 10:
            risk_level = "HIGH"
            risk_color = colors.HexColor('#ea580c')
        elif high_count > 0 or medium_count >= 20:
            risk_level = "MEDIUM"
            risk_color = colors.HexColor('#f59e0b')
        else:
            risk_level = "LOW"
            risk_color = colors.HexColor('#10b981')

        elements.append(Paragraph(
            f"<b>Overall Risk Level: <font color='{risk_color}'>{risk_level}</font></b>",
            self.styles['Executive']
        ))
        elements.append(Spacer(1, 0.3*inch))

        # Summary table
        summary_data = [
            ['Metric', 'Count'],
            ['Total Vulnerabilities', str(total_vulns)],
            ['Critical', str(critical_count)],
            ['High', str(high_count)],
            ['Medium', str(medium_count)],
            ['Low', str(low_count)],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))

        # Severity pie chart
        if total_vulns > 0:
            elements.append(self._create_severity_pie_chart(severity_counts))
            elements.append(Spacer(1, 0.3*inch))

        # Key findings
        elements.append(Paragraph("<b>Key Findings:</b>", self.styles['Executive']))
        elements.append(Spacer(1, 0.1*inch))

        if critical_count > 0:
            elements.append(Paragraph(
                f"• {critical_count} CRITICAL vulnerabilities require immediate attention",
                self.styles['Critical']
            ))

        if high_count > 0:
            elements.append(Paragraph(
                f"• {high_count} HIGH severity issues should be addressed within 7 days",
                self.styles['Executive']
            ))

        # Top vulnerability types
        vuln_types = Counter(v.get('type', 'Unknown') for v in vulnerabilities)
        top_types = vuln_types.most_common(3)

        if top_types:
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph("<b>Most Common Issues:</b>", self.styles['Executive']))
            for vuln_type, count in top_types:
                elements.append(Paragraph(
                    f"• {vuln_type}: {count} occurrence(s)",
                    self.styles['Executive']
                ))

        return elements

    def _create_severity_pie_chart(self, severity_counts: Counter) -> Drawing:
        """Create severity distribution pie chart"""
        drawing = Drawing(400, 200)

        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 120
        pie.height = 120

        # Data
        data = [
            severity_counts.get('critical', 0),
            severity_counts.get('high', 0),
            severity_counts.get('medium', 0),
            severity_counts.get('low', 0),
        ]
        labels = ['Critical', 'High', 'Medium', 'Low']

        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5

        # Colors matching severity levels
        pie.slices[0].fillColor = colors.HexColor('#dc2626')  # Critical - red
        pie.slices[1].fillColor = colors.HexColor('#ea580c')  # High - orange
        pie.slices[2].fillColor = colors.HexColor('#f59e0b')  # Medium - yellow
        pie.slices[3].fillColor = colors.HexColor('#10b981')  # Low - green

        drawing.add(pie)
        return drawing

    def _create_overview_section(self, vulnerabilities: List[Dict]) -> List:
        """Create vulnerability overview section"""
        elements = []

        elements.append(Paragraph("Vulnerability Overview", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))

        # Group by OWASP category
        owasp_counts = Counter(v.get('owasp_category', 'Unknown') for v in vulnerabilities)

        if owasp_counts:
            elements.append(Paragraph("<b>OWASP Top 10 Mapping:</b>", self.styles['Executive']))
            elements.append(Spacer(1, 0.1*inch))

            owasp_data = [['OWASP Category', 'Count']]
            for category, count in owasp_counts.most_common(10):
                owasp_data.append([category, str(count)])

            owasp_table = Table(owasp_data, colWidths=[4*inch, 1.5*inch])
            owasp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
            ]))

            elements.append(owasp_table)
            elements.append(Spacer(1, 0.3*inch))

        # Files with most vulnerabilities
        file_counts = Counter(v.get('file_path', 'Unknown') for v in vulnerabilities)
        top_files = file_counts.most_common(5)

        if top_files:
            elements.append(Paragraph("<b>Most Vulnerable Files:</b>", self.styles['Executive']))
            elements.append(Spacer(1, 0.1*inch))

            file_data = [['File Path', 'Vulnerabilities']]
            for file_path, count in top_files:
                # Truncate long paths
                display_path = file_path if len(file_path) < 60 else '...' + file_path[-57:]
                file_data.append([display_path, str(count)])

            file_table = Table(file_data, colWidths=[4*inch, 1.5*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
            ]))

            elements.append(file_table)

        return elements

    def _create_detailed_findings(self, vulnerabilities: List[Dict]) -> List:
        """Create detailed findings section"""
        elements = []

        elements.append(Paragraph("Detailed Findings", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get('severity', 'info'), 5)
        )

        # Group by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_vulns = [v for v in sorted_vulns if v.get('severity') == severity]

            if not severity_vulns:
                continue

            # Severity header
            severity_colors = {
                'critical': colors.HexColor('#dc2626'),
                'high': colors.HexColor('#ea580c'),
                'medium': colors.HexColor('#f59e0b'),
                'low': colors.HexColor('#10b981')
            }

            elements.append(Paragraph(
                f"<font color='{severity_colors[severity]}'>{severity.upper()} Severity ({len(severity_vulns)} findings)</font>",
                self.styles['SectionHeader']
            ))
            elements.append(Spacer(1, 0.1*inch))

            # Show up to 10 vulnerabilities per severity
            for vuln in severity_vulns[:10]:
                vuln_elements = self._create_vulnerability_item(vuln)
                # Use KeepTogether to avoid page breaks within a vulnerability
                elements.append(KeepTogether(vuln_elements))
                elements.append(Spacer(1, 0.15*inch))

            if len(severity_vulns) > 10:
                elements.append(Paragraph(
                    f"<i>... and {len(severity_vulns) - 10} more {severity} severity findings</i>",
                    self.styles['Executive']
                ))
                elements.append(Spacer(1, 0.2*inch))

        return elements

    def _create_vulnerability_item(self, vuln: Dict) -> List:
        """Create individual vulnerability item"""
        elements = []

        # Title
        title = vuln.get('title', 'Unknown Vulnerability')
        elements.append(Paragraph(f"<b>{title}</b>", self.styles['Executive']))

        # Details table
        details = [
            ['File', vuln.get('file_path', 'N/A')],
            ['Line', f"{vuln.get('line_start', 'N/A')}-{vuln.get('line_end', 'N/A')}"],
            ['Tool', vuln.get('detected_by', 'N/A')],
            ['OWASP', vuln.get('owasp_category', 'N/A')],
        ]

        detail_table = Table(details, colWidths=[1*inch, 4.5*inch])
        detail_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        elements.append(detail_table)

        # Description
        description = vuln.get('description', 'No description available')
        if len(description) > 300:
            description = description[:297] + '...'

        elements.append(Paragraph(
            f"<i>{description}</i>",
            ParagraphStyle(
                name='VulnDesc',
                parent=self.styles['Normal'],
                fontSize=9,
                textColor=colors.HexColor('#4b5563'),
                leftIndent=10
            )
        ))

        # Remediation if available
        remediation = vuln.get('remediation') or vuln.get('fix_recommendation')
        if remediation:
            elements.append(Paragraph(
                f"<b>Recommended Fix:</b> {remediation}",
                ParagraphStyle(
                    name='Remediation',
                    parent=self.styles['Normal'],
                    fontSize=9,
                    textColor=colors.HexColor('#059669'),
                    leftIndent=10
                )
            ))

        return elements

    def _create_appendix(self, scan_data: Dict) -> List:
        """Create appendix with scan details"""
        elements = []

        elements.append(Paragraph("Appendix: Scan Details", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))

        # Scan configuration
        config_data = [
            ['Scan ID', scan_data.get('id', 'N/A')],
            ['Started', str(scan_data.get('created_at', 'N/A'))],
            ['Completed', str(scan_data.get('completed_at', 'N/A'))],
            ['Duration', f"{scan_data.get('duration_seconds', 0)} seconds"],
        ]

        config_table = Table(config_data, colWidths=[2*inch, 4*inch])
        config_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
        ]))

        elements.append(config_table)
        elements.append(Spacer(1, 0.3*inch))

        # Scanners used
        scanners = scan_data.get('scanners_used', [])
        if scanners:
            elements.append(Paragraph("<b>Scanners Used:</b>", self.styles['Executive']))
            for scanner in scanners:
                elements.append(Paragraph(f"• {scanner}", self.styles['Executive']))

        return elements
