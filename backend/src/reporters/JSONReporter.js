const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * JSONReporter
 * Generates schemaVersion "1.0" structured report.json and machine-readable summary.json output files for NoVuln.
 */
class JSONReporter {
  /**
   * Generates full report.json and summary.json
   * @param {Object} scanResults - Unified scan results object
   * @param {Object} [options] - Output path options { json, summary }
   */
  static generate(scanResults, options = {}) {
    // 1. Ensure full JSON report object with NoVuln branding
    const reportData = {
      schemaVersion: scanResults.schemaVersion || '1.0',
      scanner: {
        name: 'NoVuln',
        edition: 'Enterprise AI SAST Platform',
        version: scanResults.scanner ? (scanResults.scanner.version || '2.0.0') : '2.0.0'
      },
      git: scanResults.git || {
        branch: 'unknown',
        commit: 'unknown',
        repository: 'local'
      },
      scan: scanResults.scan || {
        timestamp: scanResults.timestamp || new Date().toISOString(),
        durationMs: scanResults.scanDuration || 0,
        filesScanned: 1
      },
      summary: scanResults.summary || {
        total: (scanResults.findings || scanResults.vulnerabilities || []).length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        riskScore: 0,
        riskLevel: 'MINIMAL'
      },
      findings: scanResults.findings || scanResults.vulnerabilities || [],
      owaspMapping: scanResults.owaspMapping || {},
      cweMapping: scanResults.cweMapping || {}
    };

    // 2. Generate summary JSON object
    const summaryData = {
      schemaVersion: reportData.schemaVersion,
      scanner: reportData.scanner.name,
      edition: reportData.scanner.edition,
      version: reportData.scanner.version,
      timestamp: reportData.scan.timestamp,
      scannedFiles: reportData.scan.filesScanned,
      scanDurationMs: reportData.scan.durationMs,
      total: reportData.summary.total,
      critical: reportData.summary.critical,
      high: reportData.summary.high,
      medium: reportData.summary.medium,
      low: reportData.summary.low,
      info: reportData.summary.info,
      riskScore: reportData.summary.riskScore,
      riskLevel: reportData.summary.riskLevel
    };

    // 3. Write report.json if path specified
    if (options.json) {
      const jsonPath = path.resolve(options.json);
      fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2), 'utf8');
      logger.info(`Full NoVuln JSON report exported to: ${jsonPath}`);
    }

    // 4. Write summary.json if path specified
    if (options.summary) {
      const summaryPath = path.resolve(options.summary);
      fs.writeFileSync(summaryPath, JSON.stringify(summaryData, null, 2), 'utf8');
      logger.info(`NoVuln summary JSON report exported to: ${summaryPath}`);
    }

    return {
      reportData,
      summaryData
    };
  }
}

module.exports = JSONReporter;
