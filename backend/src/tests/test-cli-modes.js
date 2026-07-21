const fs = require('fs');
const path = require('path');
const ScannerEngine = require('../core/ScannerEngine');
const JSONReporter = require('../reporters/JSONReporter');

async function testCLIMode() {
  console.log('=== TESTING CLI MODE & ENTERPRISE JSON REPORTS ===\n');

  const engine = new ScannerEngine();
  const testDir = path.resolve(__dirname, '../core');

  console.log(`Executing repository scan on: ${testDir}`);
  const result = await engine.scanDirectory(testDir, { ai: false });

  console.log(`\nScan completed in ${result.scan.durationMs}ms`);
  console.log(`Schema Version: ${result.schemaVersion}`);
  console.log(`Git Repository: ${result.git.repository} (${result.git.branch})`);
  console.log(`Files Scanned:  ${result.scan.filesScanned}`);
  console.log(`Total Findings: ${result.summary.total}`);

  // Test Exporting report.json and summary.json
  const outJson = path.resolve(__dirname, 'test-report.json');
  const outSummary = path.resolve(__dirname, 'test-summary.json');

  JSONReporter.generate(result, { json: outJson, summary: outSummary });

  if (!fs.existsSync(outJson) || !fs.existsSync(outSummary)) {
    throw new Error('Report or Summary file failed to generate!');
  }

  const jsonContent = JSON.parse(fs.readFileSync(outJson, 'utf8'));
  const summaryContent = JSON.parse(fs.readFileSync(outSummary, 'utf8'));

  if (jsonContent.schemaVersion !== '1.0' || summaryContent.schemaVersion !== '1.0') {
    throw new Error('Schema version missing or invalid in output JSON!');
  }

  // Cleanup test files
  fs.unlinkSync(outJson);
  fs.unlinkSync(outSummary);

  console.log('\n🎉 CLI MODE & REPORT GENERATION TEST PASSED SUCCESSFULLY!\n');
}

testCLIMode().catch(err => {
  console.error('❌ CLI MODE TEST FAILED:', err);
  process.exit(1);
});
