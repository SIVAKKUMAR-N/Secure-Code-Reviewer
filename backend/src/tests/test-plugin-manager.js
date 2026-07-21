const PluginManager = require('../plugins/PluginManager');
const FindingNormalizer = require('../core/FindingNormalizer');
const RiskAggregator = require('../core/RiskAggregator');

async function testPluginManager() {
  console.log('=== TESTING PLUGIN MANAGER & FINDING NORMALIZER ===\n');

  const manager = new PluginManager();
  const registered = manager.getRegisteredPlugins();
  console.log(`Registered Plugins (${registered.length}):`);
  registered.forEach(p => console.log(`  - ${p.name} [Type: ${p.type}]`));

  const sampleCode = `
    const exec = require('child_process').exec;
    exec("ping " + req.query.host);
    db.query("SELECT * FROM users WHERE name = " + req.query.name);
  `;

  console.log('\nExecuting plugins for JavaScript code...');
  const rawFindings = await manager.executePlugins(sampleCode, 'javascript', 'src/app.js');
  console.log(`Raw findings generated: ${rawFindings.length}`);

  const normalized = FindingNormalizer.normalize(rawFindings, 'src/app.js');
  console.log(`Normalized findings: ${normalized.length}`);

  if (normalized.length > 0) {
    const first = normalized[0];
    console.log(`\nSample Normalized Finding:`);
    console.log(`  ID: ${first.id} | Severity: ${first.severity} | CVSS: ${first.cvssScore}`);
    console.log(`  Type: ${first.type} | Source: ${first.source}`);
    console.log(`  Location: ${first.filePath}:${first.line}`);
  }

  const aggregation = RiskAggregator.aggregate(normalized, 100, 1);
  console.log(`\nRisk Aggregation:`);
  console.log(`  Risk Score: ${aggregation.riskScore}/100 [Level: ${aggregation.riskLevel}]`);
  console.log(`  Total: ${aggregation.summary.total} (Critical: ${aggregation.summary.critical}, High: ${aggregation.summary.high})`);

  console.log('\n🎉 PLUGIN MANAGER & NORMALIZER TEST PASSED SUCCESSFULLY!\n');
}

testPluginManager().catch(err => {
  console.error('❌ PLUGIN MANAGER TEST FAILED:', err);
  process.exit(1);
});
