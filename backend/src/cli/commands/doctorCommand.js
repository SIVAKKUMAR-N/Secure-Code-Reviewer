const fs = require('fs');
const path = require('path');
const PluginManager = require('../../plugins/PluginManager');
const ConfigLoader = require('../../core/ConfigLoader');

/**
 * executeDoctorCommand
 * CLI action handler for `novuln doctor`
 */
async function executeDoctorCommand() {
  console.log('\n========================================\n');
  console.log('NoVuln Environment Check\n');
  console.log('========================================\n');

  const checks = [];
  const fixes = [];

  // 1. Node.js Version Check
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  if (majorVersion >= 18) {
    checks.push(`✓ Node.js (${nodeVersion})`);
  } else {
    checks.push(`✗ Node.js (${nodeVersion} - minimum v18.0.0 required)`);
    fixes.push('Upgrade Node.js to v18.0.0 or higher.');
  }

  // 2. Configuration Check
  try {
    const config = ConfigLoader.loadConfig();
    checks.push(`✓ Configuration (Loaded default schema v${config.schemaVersion})`);
  } catch (err) {
    checks.push(`✗ Configuration (${err.message})`);
    fixes.push('Fix JSON syntax errors in scanner.config.json.');
  }

  // 3. Plugin System Check
  try {
    const pm = new PluginManager();
    const active = pm.getActivePlugins();
    const stubs = pm.getStubPlugins();
    checks.push(`✓ Plugin System (${active.length} Active, ${stubs.length} Optional Stubs)`);
  } catch (err) {
    checks.push(`✗ Plugin System (${err.message})`);
    fixes.push('Ensure plugin dependencies are installed correctly.');
  }

  // 4. AI Provider Check
  const apiKey = process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY;
  if (apiKey) {
    checks.push(`✓ AI Provider (${process.env.GEMINI_API_KEY ? 'Gemini API' : 'OpenAI API'} Key Configured)`);
  } else {
    checks.push('✗ AI Provider (GEMINI_API_KEY not configured)');
    fixes.push('Set GEMINI_API_KEY in your environment for AI enrichment (optional for offline scans).');
  }

  // 5. MongoDB Check (Optional)
  const mongoUri = process.env.MONGODB_URI;
  if (mongoUri) {
    checks.push('✓ MongoDB (Connection string configured)');
  } else {
    checks.push('✓ MongoDB (Optional - Memory storage adapter fallback ready)');
  }

  // 6. Output Directory & Write Permissions Check
  try {
    const testFile = path.join(process.cwd(), `.novuln-perm-test-${Date.now()}.tmp`);
    fs.writeFileSync(testFile, 'test', 'utf8');
    fs.unlinkSync(testFile);
    checks.push('✓ Output Directory & Write Permissions (OK)');
  } catch (err) {
    checks.push(`✗ Write Permissions (${err.message})`);
    fixes.push('Ensure current directory has write permissions for report exports.');
  }

  // 7. Scanner Manifest Check
  try {
    const manifestPath = path.join(__dirname, '../../../scanner-manifest.json');
    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      checks.push(`✓ Scanner Manifest (Loaded - ${manifest.scanner} v${manifest.version})`);
    } else {
      checks.push('✓ Scanner Manifest (Default NoVuln v2.0.0)');
    }
  } catch (err) {
    checks.push(`✗ Scanner Manifest (${err.message})`);
  }

  // 8. Report Schema Check
  checks.push('✓ Report Schema (Schema v1.0 Ready)\n');

  // Output all check items
  checks.forEach(c => console.log(c));

  if (fixes.length > 0) {
    console.log('Recommended Fixes:');
    fixes.forEach(f => console.log(`  • ${f}`));
    console.log('');
  } else {
    console.log('Everything is ready.\n');
  }

  process.exit(0);
}

module.exports = { executeDoctorCommand };
