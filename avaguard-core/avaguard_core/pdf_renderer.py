"""
AVAGuard Core - PDF Renderer
Generates enterprise-grade PDF compliance reports using ReportLab.
"""
import os
from datetime import datetime
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch

from avaguard_core.checks.base_check import CheckResult, CheckStatus
from avaguard_core.framework_mapper import FrameworkMapper
from avaguard_core.risk_scorer import RiskScorer

class PDFRenderer:
    """Renders scan results to a structured PDF report."""
    
    @staticmethod
    def generate_pdf(results: List[CheckResult], filepath: str, scan_id: str, timestamp: str):
        """Build the PDF document using ReportLab Platypus."""
        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Center', alignment=1))
        
        Story = []
        
        # 1. Title Page
        title_style = styles['Heading1']
        title_style.alignment = 1
        Story.append(Spacer(1, 2 * inch))
        Story.append(Paragraph("AVAGuard Enterprise Compliance Report", title_style))
        Story.append(Spacer(1, 0.5 * inch))
        
        Story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", styles['Center']))
        Story.append(Paragraph(f"<b>Date:</b> {timestamp}", styles['Center']))
        Story.append(Spacer(1, 0.5 * inch))
        
        score = RiskScorer.calculate_score(results)
        risk_level = RiskScorer.get_risk_level(score)
        
        Story.append(Paragraph(f"<b>Overall Compliance Score:</b> {score}%", styles['Center']))
        Story.append(Paragraph(f"<b>Organizational Risk Level:</b> {risk_level}", styles['Center']))
        
        Story.append(PageBreak())
        
        # 2. Framework Mapping
        Story.append(Paragraph("Cross-Framework Compliance mapping", styles['Heading2']))
        Story.append(Spacer(1, 0.2 * inch))
        
        framework_data = FrameworkMapper.generate_framework_report(results)
        
        for framework, data in framework_data.items():
            Story.append(Paragraph(f"<b>{framework}</b> - Score: {data['compliance_score']}%", styles['Heading3']))
            Story.append(Paragraph(f"Covered Controls: {', '.join(data['covered']) if data['covered'] else 'None'}", styles['Normal']))
            if data['at_risk']:
                Story.append(Paragraph(f"<font color='red'>At-Risk Controls: {', '.join(data['at_risk'])}</font>", styles['Normal']))
            Story.append(Spacer(1, 0.2 * inch))
            
        Story.append(PageBreak())
        
        # 3. Detailed Results
        Story.append(Paragraph("Detailed Findings", styles['Heading2']))
        Story.append(Spacer(1, 0.2 * inch))
        
        table_data = [['Control ID', 'Title', 'Status', 'Compliance']]
        
        for r in results:
            cis_id = getattr(r, 'cis_control_id', r.check_id)
            title = (r.title[:45] + '...') if len(r.title) > 45 else r.title
            status = str(r.status.value if hasattr(r.status, 'value') else r.status)
            comp = f"{r.compliant_count}/{r.total_count}"
            table_data.append([cis_id, title, status, comp])
            
        t = Table(table_data, colWidths=[1*inch, 3*inch, 1*inch, 1*inch])
        
        # Styling table
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1'))
        ]))
        
        # Apply color formatting based on pass/fail string values dynamically
        for idx, row in enumerate(table_data[1:], start=1):
            if row[2] == 'PASS':
                t.setStyle(TableStyle([('TEXTCOLOR', (2, idx), (2, idx), colors.HexColor('#16a34a'))]))
            elif row[2] == 'FAIL':
                t.setStyle(TableStyle([('TEXTCOLOR', (2, idx), (2, idx), colors.HexColor('#dc2626'))]))
            elif row[2] == 'ERROR':
                t.setStyle(TableStyle([('TEXTCOLOR', (2, idx), (2, idx), colors.HexColor('#ea580c'))]))

        Story.append(t)
        
        doc.build(Story)
        return filepath
