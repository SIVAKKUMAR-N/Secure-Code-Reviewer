const path = require('path');

/**
 * ConsoleReporter
 * Formats clean, professional terminal output for NoVuln CLI execution.
 */
class ConsoleReporter {
  /**
   * Prints polished Release Candidate startup banner
   * @param {Object} details - { version, targetPath, aiEnabled, isCiMode, configSource }
   */
  static printBanner(details = {}) {
    const version = details.version || '2.0.0';
    const targetPath = details.targetPath || process.cwd();
    const repoName = path.basename(targetPath) || targetPath;
    const aiEnabled = details.aiEnabled !== false;
    const isCiMode = !!details.isCiMode;
    const configSource = details.configSource ? path.basename(details.configSource) : 'Built-in Defaults';

    console.log('\n==================================================');
    console.log('NoVuln');
    console.log('Enterprise AI SAST Platform');
    console.log(`Version ${version}`);
    console.log('==================================================\n');

    console.log('Repository:');
    console.log(`${repoName}\n`);

    console.log('Mode:');
    console.log(`${isCiMode ? 'CI/CD Pipeline Mode' : 'Developer Mode'}\n`);

    console.log('Configuration:');
    console.log(`${configSource}\n`);

    console.log('AI:');
    console.log(`${aiEnabled ? 'Enabled' : 'Disabled'}\n`);
  }

  /**
   * Prints final Release Candidate scan summary layout
   * @param {Object} scanResults - Scan results object
   * @param {Array<string>} [reportsGenerated] - List of report file paths generated
   * @param {boolean} [verbose=false] - Whether verbose parser error details are printed
   */
  static printSummary(scanResults, reportsGenerated = [], verbose = false) {
    const summary = scanResults.summary || {};
    const scan = scanResults.scan || {};
    const git = scanResults.git || {};
    const parserErrorDetails = scanResults.parserErrorDetails || [];

    // Repository Display (Clean, single name)
    const repoName = (git.repository && git.repository !== 'local')
      ? path.basename(git.repository)
      : path.basename(scan.targetPath || process.cwd());

    // Duration & Throughput Calculation
    const filesScanned = scan.filesScanned || summary.scannedFiles || 1;
    const durationMs = scan.durationMs || scanResults.scanDuration || 0;
    const durationSec = (durationMs / 1000).toFixed(1);
    const throughput = durationMs > 0 ? Math.round(filesScanned / (durationMs / 1000)) : filesScanned;

    console.log('=========================================\n');
    console.log('NoVuln Scan Summary\n');
    console.log('=========================================\n');

    console.log('Repository:');
    console.log(`${repoName}\n`);

    console.log('Files Scanned:');
    console.log(`${filesScanned}\n`);

    // Language Summary with Breakdown Count
    console.log('Languages Detected:');
    const langCounts = summary.languageCounts || { JavaScript: filesScanned };
    Object.entries(langCounts).forEach(([lang, count]) => {
      console.log(`  ✓ ${lang} (${count} files)`);
    });
    console.log('');

    console.log('Duration:');
    console.log(`${durationSec} sec\n`);

    console.log('Average Throughput:');
    console.log(`${throughput} files/sec\n`);

    // Professional Findings Table
    console.log('Severity        Findings');
    console.log('-------------------------');
    console.log(`Critical        ${String(summary.critical || 0).padStart(6)}`);
    console.log(`High            ${String(summary.high || 0).padStart(6)}`);
    console.log(`Medium          ${String(summary.medium || 0).padStart(6)}`);
    console.log(`Low             ${String(summary.low || 0).padStart(6)}`);
    console.log(`Info            ${String(summary.info || 0).padStart(6)}\n`);

    // Parser Error Summary
    console.log('Parser Errors:');
    const errCount = summary.parserErrors || parserErrorDetails.length || 0;
    if (errCount > 0) {
      console.log(`${errCount} files could not be parsed.\n`);
      if (verbose && parserErrorDetails.length > 0) {
        console.log('--- Parser Diagnostics (--verbose) ---');
        parserErrorDetails.forEach((e, idx) => {
          console.log(`  [${idx + 1}] ${e.filePath}: ${e.message}`);
        });
        console.log('');
      } else if (!verbose) {
        console.log('Use:\nnovuln scan . --verbose\n\nto view detailed parser diagnostics.\n');
      }
    } else {
      console.log('0 files failed parsing.\n');
    }

    // Report Output Status
    if (reportsGenerated && reportsGenerated.length > 0) {
      console.log('Reports Generated:');
      reportsGenerated.forEach(rep => {
        console.log(`  ✓ ${rep}`);
      });
      console.log('');
    } else {
      console.log('Reports:');
      console.log('Console output only\n');
      console.log('Use:\n--ci\nor\n--json\nto generate reports.\n');
    }

    console.log('Risk Score:');
    console.log(`${summary.riskScore || 0}\n`);

    console.log('Risk Level:');
    console.log(`${summary.riskLevel || 'MINIMAL'}\n`);

    console.log('=========================================\n');
  }

  /**
   * Backwards compatible print method
   */
  static print(scanResults) {
    ConsoleReporter.printSummary(scanResults);
  }
}

module.exports = ConsoleReporter;
