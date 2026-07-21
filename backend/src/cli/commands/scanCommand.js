const path = require('path');
const ScannerEngine = require('../../core/ScannerEngine');
const ConfigLoader = require('../../core/ConfigLoader');
const JSONReporter = require('../../reporters/JSONReporter');
const ConsoleReporter = require('../../reporters/ConsoleReporter');
const PDFReporter = require('../../reporters/PDFReporter');
const MongoStorage = require('../../storage/MongoStorage');
const logger = require('../../utils/logger');

/**
 * executeScanCommand
 * CLI action handler for `novuln scan <targetPath>`
 */
async function executeScanCommand(targetPath, options = {}) {
  try {
    const absPath = path.resolve(targetPath || '.');
    const aiEnabled = options.ai !== false;

    // Load target configuration to detect config source
    const loadedConfig = ConfigLoader.loadConfig(options.config, options, absPath);

    // 1. Print polished Release Candidate startup banner
    ConsoleReporter.printBanner({
      version: '2.0.0',
      targetPath: absPath,
      aiEnabled,
      isCiMode: !!options.ci,
      configSource: loadedConfig.loadedFrom
    });

    const engine = new ScannerEngine({ ...options, targetPath: absPath });

    logger.debug(`NoVuln CLI executing on target: ${absPath} (CI Mode: ${!!options.ci})`);

    // 2. Run directory scan
    const scanResults = await engine.scanDirectory(absPath, options);

    // 3. Determine output file paths
    let jsonPath = options.json || null;
    let summaryPath = options.summary || null;

    // CI mode automatically enables report.json and summary.json outputs
    if (options.ci) {
      jsonPath = jsonPath || 'report.json';
      summaryPath = summaryPath || 'summary.json';
    }

    const reportsGenerated = [];

    // 4. Generate JSON & Summary reports if requested or in CI mode
    if (jsonPath || summaryPath) {
      JSONReporter.generate(scanResults, {
        json: jsonPath,
        summary: summaryPath
      });
      if (jsonPath) reportsGenerated.push(path.basename(jsonPath));
      if (summaryPath) reportsGenerated.push(path.basename(summaryPath));
    }

    // 5. Optional PDF export
    if (options.pdf) {
      await PDFReporter.generateFile(scanResults, options.pdf);
      reportsGenerated.push(path.basename(options.pdf));
    }

    // 6. Optional MongoDB storage
    if (options.store) {
      const storage = new MongoStorage();
      await storage.save(scanResults);
    }

    // 7. Output final summary
    ConsoleReporter.printSummary(scanResults, reportsGenerated, !!options.verbose);

    // Exit code 0 when scan completes successfully
    process.exit(0);

  } catch (err) {
    console.error(`\n❌ NoVuln SCANNER ERROR: ${err.message}\n`);
    logger.debug(`NoVuln CLI Execution Failed: ${err.stack}`);
    // Exit code 1 on scanner runtime error
    process.exit(1);
  }
}

module.exports = { executeScanCommand };
