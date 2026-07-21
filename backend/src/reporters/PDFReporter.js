const fs = require('fs');
const path = require('path');
const PDFGenerator = require('../utils/pdfGenerator');
const logger = require('../utils/logger');

/**
 * PDFReporter
 * Exports executive PDF reports to disk or buffer.
 */
class PDFReporter {
  /**
   * Generates PDF report buffer
   * @param {Object} scanResults - Scan result object
   * @returns {Promise<Buffer>} PDF file buffer
   */
  static async generateBuffer(scanResults) {
    const scanDoc = {
      _id: scanResults.scanId || 'CLI-SCAN',
      language: scanResults.language || 'multi-file',
      createdAt: (scanResults.scan && scanResults.scan.timestamp) || scanResults.timestamp || new Date().toISOString(),
      summary: scanResults.summary || {
        total: (scanResults.findings || []).length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      vulnerabilities: scanResults.findings || scanResults.vulnerabilities || []
    };

    return await PDFGenerator.generateReport(scanDoc);
  }

  /**
   * Generates PDF report file on disk
   * @param {Object} scanResults - Scan result object
   * @param {string} outputPath - Target PDF file path
   * @returns {Promise<string>} Resolved file path
   */
  static async generateFile(scanResults, outputPath) {
    const pdfBuffer = await PDFReporter.generateBuffer(scanResults);
    const absolutePath = path.resolve(outputPath);
    fs.writeFileSync(absolutePath, pdfBuffer);
    logger.info(`PDF report exported to: ${absolutePath}`);
    return absolutePath;
  }
}

module.exports = PDFReporter;
