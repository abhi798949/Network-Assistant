# pdf_generator.py
"""
PDF Report Generator for Network Configuration Changes
Generates professional PDF summaries of configuration changes with explanations
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER
from datetime import datetime
import io
import logging

class ConfigChangePDFGenerator:
    """Generate PDF reports for configuration changes"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#4a90e2'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.grey,
            spaceAfter=20,
            alignment=TA_CENTER
        ))
        
        # Device header style
        self.styles.add(ParagraphStyle(
            name='DeviceHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#357abd'),
            spaceAfter=12,
            spaceBefore=20
        ))
        
        # Success/Fail style
        self.styles.add(ParagraphStyle(
            name='SuccessText',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#28a745'),
            spaceAfter=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='FailText',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#dc3545'),
            spaceAfter=10
        ))
        
        # Code style for commands
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Code'],
            fontSize=9,
            fontName='Courier',
            textColor=colors.HexColor('#2b2b2b'),
            backColor=colors.HexColor('#f8f9fa'),
            leftIndent=10,
            rightIndent=10,
            spaceAfter=10
        ))
    
    def generate_execute_summary(self, results_data, user_prompt):
        """
        Generate PDF summary for execute command results
        
        Args:
            results_data: dict with 'commands' and 'device_results'
            user_prompt: original user prompt
        
        Returns:
            BytesIO object containing the PDF
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        story = []
        
        # Title
        story.append(Paragraph("Configuration Change Summary", self.styles['CustomTitle']))
        story.append(Paragraph(
            f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            self.styles['CustomSubtitle']
        ))
        story.append(Spacer(1, 0.3*inch))
        
        # User Prompt Section
        story.append(Paragraph("“ <b>User Request:</b>", self.styles['Heading3']))
        story.append(Paragraph(self._escape_html(user_prompt), self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Commands Applied Section
        if 'commands' in results_data and results_data['commands']:
            commands = results_data['commands']
            if isinstance(commands, list):
                commands_text = '<br/>'.join([f"â€¢ {self._escape_html(cmd)}" for cmd in commands])
            else:
                commands_text = self._escape_html(str(commands))
            
            story.append(Paragraph("¸ <b>Commands Applied:</b>", self.styles['Heading3']))
            story.append(Paragraph(commands_text, self.styles['CodeBlock']))
            story.append(Spacer(1, 0.2*inch))
        
        # Summary Statistics
        total_devices = len(results_data.get('device_results', []))
        successful = sum(1 for r in results_data.get('device_results', []) if r.get('success'))
        failed = total_devices - successful
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Devices', str(total_devices)],
            ['Successful', str(successful)],
            ['âŒ Failed', str(failed)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90e2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(Paragraph("“ <b>Summary:</b>", self.styles['Heading3']))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Device-by-Device Results
        story.append(Paragraph(" <b>Device Results:</b>", self.styles['Heading3']))
        story.append(Spacer(1, 0.1*inch))
        
        for idx, device_result in enumerate(results_data.get('device_results', [])):
            # Device header
            device_name = device_result.get('device', 'Unknown Device')
            story.append(Paragraph(f"Device: {self._escape_html(device_name)}", 
                                 self.styles['DeviceHeader']))
            
            # Status
            success = device_result.get('success', False)
            status_style = 'SuccessText' if success else 'FailText'
            status_text = "Configuration Applied Successfully" if success else " Configuration Failed"
            story.append(Paragraph(status_text, self.styles[status_style]))
            
            # Message
            if device_result.get('message'):
                story.append(Paragraph(
                    f"<b>Message:</b> {self._escape_html(device_result['message'])}",
                    self.styles['Normal']
                ))
                story.append(Spacer(1, 0.1*inch))
            
            # Configuration Diff
            if device_result.get('config_diff'):
                diff_text = device_result['config_diff']
                change_summary = device_result.get('change_summary', 'Changes detected')
                
                story.append(Paragraph(f"<b>Configuration Changes ({change_summary}):</b>", 
                                     self.styles['Normal']))
                
                if 'No configuration changes' in diff_text:
                    story.append(Paragraph(
                        " No configuration changes detected (already in desired state)",
                        self.styles['Normal']
                    ))
                else:
                    # Format diff nicely
                    diff_lines = diff_text.split('\n')
                    formatted_diff = self._format_diff_for_pdf(diff_lines)
                    story.append(Paragraph(formatted_diff, self.styles['CodeBlock']))
                
                story.append(Spacer(1, 0.1*inch))
            
            # Command Outputs
            if device_result.get('command_outputs'):
                story.append(Paragraph("<b>Command Outputs:</b>", self.styles['Normal']))
                for cmd_output in device_result['command_outputs']:
                    cmd = cmd_output.get('command', '')
                    output = cmd_output.get('output', '')
                    
                    story.append(Paragraph(
                        f"<b>Command:</b> <font face='Courier'>{self._escape_html(cmd)}</font>",
                        self.styles['Normal']
                    ))
                    
                    # Truncate long outputs
                    if len(output) > 500:
                        output = output[:500] + '\n... (output truncated)'
                    
                    story.append(Paragraph(
                        f"<font face='Courier' size=8>{self._escape_html(output)}</font>",
                        self.styles['Normal']
                    ))
                    story.append(Spacer(1, 0.1*inch))
            
            # Add separator between devices
            if idx < len(results_data.get('device_results', [])) - 1:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("â”€" * 80, self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            "Generated by Network Configuration Manager",
            self.styles['CustomSubtitle']
        ))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def generate_verify_summary(self, results_data, user_prompt, is_asis=False):
        """
        Generate PDF summary for verify/as-is command results
        
        Args:
            results_data: dict with 'commands' and 'device_results'
            user_prompt: original user prompt
            is_asis: whether this was run as-is (no AI parsing)
        
        Returns:
            BytesIO object containing the PDF
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        story = []
        
        # Title
        title = "Command Verification Summary" if not is_asis else "Command Execution Summary (As-Is)"
        story.append(Paragraph(title, self.styles['CustomTitle']))
        story.append(Paragraph(
            f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            self.styles['CustomSubtitle']
        ))
        story.append(Spacer(1, 0.3*inch))
        
        # User Command Section
        story.append(Paragraph("“ <b>Command/Request:</b>", self.styles['Heading3']))
        story.append(Paragraph(self._escape_html(user_prompt), self.styles['CodeBlock']))
        story.append(Spacer(1, 0.2*inch))
        
        # Device Results
        story.append(Paragraph("¸ <b>Device Results:</b>", self.styles['Heading3']))
        story.append(Spacer(1, 0.1*inch))
        
        for idx, device_result in enumerate(results_data.get('device_results', [])):
            device_name = device_result.get('device', 'Unknown Device')
            story.append(Paragraph(f"Device: {self._escape_html(device_name)}", 
                                 self.styles['DeviceHeader']))
            
            success = device_result.get('success', False)
            status_style = 'SuccessText' if success else 'FailText'
            status_text = "Verification Successful" if success else "âŒ Verification Failed"
            story.append(Paragraph(status_text, self.styles[status_style]))
            
            if device_result.get('message'):
                story.append(Paragraph(
                    f"<b>Message:</b> {self._escape_html(device_result['message'])}",
                    self.styles['Normal']
                ))
                story.append(Spacer(1, 0.1*inch))
            
            # Command Outputs
            if device_result.get('command_outputs'):
                for cmd_output in device_result['command_outputs']:
                    cmd = cmd_output.get('command', '')
                    output = cmd_output.get('output', '')
                    
                    story.append(Paragraph(
                        f"<b>Command:</b> <font face='Courier'>{self._escape_html(cmd)}</font>",
                        self.styles['Normal']
                    ))
                    
                    # Truncate very long outputs
                    if len(output) > 1000:
                        output = output[:1000] + '\n... (output truncated for brevity)'
                    
                    story.append(Paragraph(
                        f"<font face='Courier' size=8>{self._escape_html(output)}</font>",
                        self.styles['Normal']
                    ))
                    story.append(Spacer(1, 0.1*inch))
            
            if idx < len(results_data.get('device_results', [])) - 1:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("â”€" * 80, self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            "Generated by Network Configuration Manager",
            self.styles['CustomSubtitle']
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _format_diff_for_pdf(self, diff_lines):
        """Format diff lines for PDF display with color coding"""
        formatted = []
        for line in diff_lines[:50]:  # Limit to 50 lines
            line = self._escape_html(line)
            if line.startswith('+++') or line.startswith('---'):
                formatted.append(f'<font color="#75715e">{line}</font>')
            elif line.startswith('@@'):
                formatted.append(f'<font color="#66d9ef"><b>{line}</b></font>')
            elif line.startswith('+'):
                formatted.append(f'<font color="#28a745">{line}</font>')
            elif line.startswith('-'):
                formatted.append(f'<font color="#dc3545">{line}</font>')
            else:
                formatted.append(line)
        
        if len(diff_lines) > 50:
            formatted.append('<font color="#6c757d">... (diff truncated, showing first 50 lines)</font>')
        
        return '<br/>'.join(formatted)
    
    def _escape_html(self, text):
        """Escape HTML special characters for ReportLab"""
        if not text:
            return ""
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text