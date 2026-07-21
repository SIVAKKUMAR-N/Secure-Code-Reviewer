const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const { executeScanCommand } = require('./commands/scanCommand');
const { executeDoctorCommand } = require('./commands/doctorCommand');

function loadManifest() {
  const paths = [
    path.join(__dirname, '../../scanner-manifest.json'),
    path.join(__dirname, '../../../scanner-manifest.json')
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      try {
        return JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch (_) {}
    }
  }
  return {
    scanner: 'NoVuln',
    edition: 'Enterprise AI SAST Platform',
    version: '2.0.0'
  };
}

function runCLI(args = process.argv) {
  const manifest = loadManifest();
  const program = new Command();

  program
    .name('novuln')
    .description('NoVuln - Enterprise AI SAST Platform CLI')
    .version(manifest.version);

  program
    .command('scan')
    .argument('<path>', 'Target file or directory path to scan recursively')
    .option('-c, --config <path>', 'Path to custom scanner.config.json')
    .option('--ci', 'Enable CI mode (automatically exports report.json and summary.json)', false)
    .option('-j, --json <filepath>', 'Export full JSON report file')
    .option('-s, --summary <filepath>', 'Export machine-readable summary JSON file')
    .option('-p, --pdf <filepath>', 'Export PDF executive report file')
    .option('--store', 'Persist report to MongoDB database', false)
    .option('--no-ai', 'Disable AI enrichment for fast offline scans')
    .option('-v, --verbose', 'Display detailed parser error details and debug information', false)
    .action(async (targetPath, options) => {
      await executeScanCommand(targetPath, options);
    });

  program
    .command('doctor')
    .description('Perform environment diagnostic check')
    .action(async () => {
      await executeDoctorCommand();
    });

  program.parse(args);
}

module.exports = { runCLI };
