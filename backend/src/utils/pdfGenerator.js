const PDFDocument = require('pdfkit');
const logger = require('./logger');

/**
 * PDF Report Generator
 * Creates professional vulnerability assessment reports
 */

class PDFGenerator {
  /**
   * Generate PDF report from scan results
   * @param {Object} scan - Scan document from database
   * @returns {Buffer} PDF file buffer
   */
  static async generateReport(scan) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ 
          size: 'A4',
          margins: { top: 50, bottom: 50, left: 50, right: 50 },
          bufferPages: true
        });

        const chunks = [];
        
        // Collect PDF chunks
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        // Generate report content
        this._addHeader(doc, scan);
        this._addExecutiveSummary(doc, scan);
        this._addVulnerabilityDetails(doc, scan);
        this._addRecommendations(doc, scan);
        this._addFooter(doc);

        // Finalize PDF
        doc.end();

      } catch (error) {
        logger.error(`PDF generation failed: ${error.message}`);
        reject(error);
      }
    });
  }

  /**
   * Add report header
   */
  static _addHeader(doc, scan) {
    doc
      .fontSize(24)
      .fillColor('#1a1a1a')
      .text('Security Code Review Report', { align: 'center' })
      .moveDown(0.5);

    doc
      .fontSize(12)
      .fillColor('#666666')
      .text(`Language: ${scan.language.toUpperCase()}`, { align: 'center' })
      .text(`Generated: ${new Date(scan.createdAt).toLocaleString()}`, { align: 'center' })
      .text(`Scan ID: ${scan._id}`, { align: 'center' })
      .moveDown(2);

    // Add separator line
    doc
      .moveTo(50, doc.y)
      .lineTo(550, doc.y)
      .stroke('#cccccc')
      .moveDown(1.5);
  }

  /**
   * Add executive summary section
   */
  static _addExecutiveSummary(doc, scan) {
    doc
      .fontSize(18)
      .fillColor('#1a1a1a')
      .text('Executive Summary')
      .moveDown(0.5);

    doc
      .fontSize(11)
      .fillColor('#333333');

    // Summary statistics
    const { summary } = scan;
    
    doc.text(`Total Vulnerabilities Found: ${summary.total}`, { continued: false });
    doc.moveDown(0.3);

    // Severity breakdown with color coding
    this._addSeverityLine(doc, 'Critical', summary.critical, '#dc2626');
    this._addSeverityLine(doc, 'High', summary.high, '#ea580c');
    this._addSeverityLine(doc, 'Medium', summary.medium, '#f59e0b');
    this._addSeverityLine(doc, 'Low', summary.low, '#3b82f6');
    
    doc.moveDown(1);

    // Risk assessment
    const riskScore = this._calculateRiskScore(summary);
    const riskLevel = this._getRiskLevel(riskScore);
    
    doc
      .fontSize(12)
      .fillColor('#1a1a1a')
      .text(`Overall Risk Level: `, { continued: true })
      .fillColor(this._getRiskColor(riskLevel))
      .text(riskLevel, { continued: false });

    doc.moveDown(2);
  }

  /**
   * Add severity line with colored bullet
   */
  static _addSeverityLine(doc, severity, count, color) {
    doc
      .circle(doc.x, doc.y + 4, 3)
      .fillAndStroke(color, color)
      .fillColor('#333333')
      .text(`  ${severity}: ${count}`, 65, doc.y - 4);
    
    doc.moveDown(0.3);
  }

  /**
   * Add vulnerability details section
   */
  static _addVulnerabilityDetails(doc, scan) {
    doc
      .fontSize(18)
      .fillColor('#1a1a1a')
      .text('Vulnerability Details')
      .moveDown(1);

    if (scan.vulnerabilities.length === 0) {
      doc
        .fontSize(11)
        .fillColor('#22c55e')
        .text('✓ No vulnerabilities detected. Code appears secure!');
      return;
    }

    scan.vulnerabilities.forEach((vuln, index) => {
      // Check if we need a new page
      if (doc.y > 650) {
        doc.addPage();
      }

      this._addVulnerability(doc, vuln, index + 1);
    });
  }

  /**
   * Add single vulnerability entry
   */
  static _addVulnerability(doc, vuln, number) {
    // Check if we need to start a new page before drawing
    if (doc.y > 600) {
      doc.addPage();
    }

    const severityColor = this._getSeverityColor(vuln.severity);
    
    // Header
    doc
      .font('Helvetica-Bold')
      .fontSize(13)
      .fillColor('#111827') // slate-900
      .text(`${number}. ${vuln.type}`);

    doc.moveDown(0.2);

    // Metadata: Severity & Location
    doc
      .font('Helvetica-Bold')
      .fontSize(10)
      .fillColor(severityColor)
      .text(`Severity: ${vuln.severity}`, { continued: true })
      .font('Helvetica')
      .fillColor('#4b5563')
      .text(`  |  Location: Line ${vuln.line}`);

    doc.moveDown(0.4);

    // Description (Detector Message)
    doc
      .font('Helvetica')
      .fontSize(10.5)
      .fillColor('#1f2937')
      .text(vuln.message, { align: 'justify' });

    // AI Explanation (if available)
    if (
      vuln.aiExplanation &&
      vuln.aiExplanation !== 'AI analysis unavailable' &&
      vuln.aiExplanation !== 'AI analysis temporarily unavailable'
    ) {
      doc.moveDown(0.5);
      doc
        .font('Helvetica-Bold')
        .fontSize(10.5)
        .fillColor('#111827')
        .text('AI Security Analysis:');
      
      doc.moveDown(0.25);
      
      // Strip wrapping quotes if any
      const cleanExplanation = vuln.aiExplanation.replace(/^"|"$/g, '').trim();
      doc
        .font('Helvetica')
        .fontSize(10)
        .fillColor('#374151')
        .text(cleanExplanation, { align: 'justify' });
    }

    // AI Secure Fix (if available)
    if (
      vuln.secureFix &&
      vuln.secureFix !== 'Unable to generate fix suggestion' &&
      vuln.secureFix !== 'No fix suggestion available' &&
      vuln.secureFix !== 'See AI response'
    ) {
      doc.moveDown(0.5);
      doc
        .font('Helvetica-Bold')
        .fontSize(10.5)
        .fillColor('#16a34a') // green-600
        .text('Suggested Secure Fix:');
      
      doc.moveDown(0.25);

      // Extract code block if present
      let fixText = vuln.secureFix;
      let codeBlock = '';
      let explanationText = '';

      const codeBlockMatch = fixText.match(/```(?:[a-zA-Z0-9+#]+)?\n([\s\S]*?)\n```/);
      if (codeBlockMatch) {
        codeBlock = codeBlockMatch[1];
        explanationText = fixText.replace(codeBlockMatch[0], '').trim();
      } else {
        explanationText = fixText;
      }

      if (codeBlock) {
        const codeFont = 'Courier';
        const codeSize = 8.5;
        const padding = 8;
        const textWidth = 484; // 500 total width (50 to 550) - 2 * 8 padding
        const rectX = 50;

        // Save current font settings to calculate height
        doc.font(codeFont).fontSize(codeSize);
        const textHeight = doc.heightOfString(codeBlock, { width: textWidth });
        const blockHeight = textHeight + padding * 2;

        // Check page overflow for code block
        if (doc.y + blockHeight > doc.page.height - 50) {
          doc.addPage();
        }

        const drawY = doc.y;

        // Draw light gray background rect
        doc
          .rect(rectX, drawY, 500, blockHeight)
          .fill('#f3f4f6');

        // Draw code text
        doc
          .fillColor('#1f2937')
          .text(codeBlock, rectX + padding, drawY + padding, {
            width: textWidth,
            lineGap: 2
          });

        // Set cursor below block
        doc.y = drawY + blockHeight;
        doc.moveDown(0.4);
      }

      if (explanationText) {
        doc
          .font('Helvetica')
          .fontSize(10)
          .fillColor('#374151')
          .text(explanationText, { align: 'justify' });
      }
    }

    // AI Attack Example (if available)
    if (
      vuln.attackExample &&
      vuln.attackExample !== 'Unable to generate attack example' &&
      vuln.attackExample !== 'No attack example available' &&
      vuln.attackExample !== 'See AI response'
    ) {
      doc.moveDown(0.5);
      doc
        .font('Helvetica-Bold')
        .fontSize(10.5)
        .fillColor('#dc2626') // red-600
        .text('Exploit Demonstration / Attack Example:');
      
      doc.moveDown(0.25);
      doc
        .font('Helvetica')
        .fontSize(10)
        .fillColor('#374151')
        .text(vuln.attackExample, { align: 'justify' });
    }

    // OWASP & CWE Metadata line
    doc.moveDown(0.6);
    let metaText = '';
    if (vuln.owaspCategory) {
      metaText += `OWASP: ${vuln.owaspCategory}`;
    }
    if (vuln.cweId) {
      metaText += metaText ? `  |  CWE: ${vuln.cweId}` : `CWE: ${vuln.cweId}`;
    }
    
    if (metaText) {
      doc
        .font('Helvetica-Oblique')
        .fontSize(9)
        .fillColor('#6b7280') // gray-500
        .text(metaText);
    }

    // Add separator line after each vulnerability, except if we are at the end, or if we want spacing
    doc.moveDown(1);
    doc
      .moveTo(50, doc.y)
      .lineTo(550, doc.y)
      .stroke('#e5e7eb') // light gray-200 line
      .moveDown(1);
  }

  /**
   * Add recommendations section
   */
  static _addRecommendations(doc, scan) {
    // Add new page for recommendations
    doc.addPage();

    doc
      .fontSize(18)
      .fillColor('#1a1a1a')
      .text('Recommendations')
      .moveDown(1);

    doc
      .fontSize(11)
      .fillColor('#333333');

    const recommendations = [
      'Address all Critical and High severity vulnerabilities immediately',
      'Implement input validation and sanitization for all user inputs',
      'Use parameterized queries to prevent SQL injection',
      'Implement proper output encoding to prevent XSS attacks',
      'Store secrets in environment variables, never in source code',
      'Use strong cryptographic functions (bcrypt, Argon2) for password hashing',
      'Implement proper error handling and logging',
      'Regular security code reviews and automated scanning',
      'Keep dependencies updated and scan for known vulnerabilities',
      'Follow the principle of least privilege for all operations',
    ];

    recommendations.forEach((rec, index) => {
      doc.text(`${index + 1}. ${rec}`, { align: 'left' });
      doc.moveDown(0.5);
    });
  }

  /**
   * Add footer to all pages
   */
  static _addFooter(doc) {
    const pages = doc.bufferedPageRange();
    
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      
      doc
        .fontSize(9)
        .fillColor('#999999')
        .text(
          `Page ${i + 1} of ${pages.count}`,
          50,
          doc.page.height - 50,
          { align: 'center' }
        );
      
      doc
        .text(
          'Generated by Secure Code Reviewer',
          50,
          doc.page.height - 35,
          { align: 'center' }
        );
    }
  }

  /**
   * Get severity color
   */
  static _getSeverityColor(severity) {
    const colors = {
      'Critical': '#dc2626',
      'High': '#ea580c',
      'Medium': '#f59e0b',
      'Low': '#3b82f6',
      'Info': '#6b7280',
    };
    return colors[severity] || '#6b7280';
  }

  /**
   * Calculate risk score
   */
  static _calculateRiskScore(summary) {
    return (
      summary.critical * 40 +
      summary.high * 25 +
      summary.medium * 10 +
      summary.low * 5
    );
  }

  /**
   * Get risk level from score
   */
  static _getRiskLevel(score) {
    if (score >= 100) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 20) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'MINIMAL';
  }

  /**
   * Get risk level color
   */
  static _getRiskColor(level) {
    const colors = {
      'CRITICAL': '#dc2626',
      'HIGH': '#ea580c',
      'MEDIUM': '#f59e0b',
      'LOW': '#3b82f6',
      'MINIMAL': '#22c55e',
    };
    return colors[level] || '#6b7280';
  }
}

module.exports = PDFGenerator;
