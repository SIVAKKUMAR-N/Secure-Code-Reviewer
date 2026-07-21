const path = require('path');
const DirectoryScanner = require('../core/DirectoryScanner');
const ConfigLoader = require('../core/ConfigLoader');

async function testDirectoryScanner() {
  console.log('=== TESTING DIRECTORY SCANNER & CONFIG LOADER ===\n');

  // 1. Test ConfigLoader
  const config = ConfigLoader.loadConfig();
  console.log('✅ Loaded default config:');
  console.log(`   Ignored folders: ${config.ignore.slice(0, 5).join(', ')}...`);
  console.log(`   Languages: ${config.languages.join(', ')}`);

  // 2. Test DirectoryScanner
  const testDir = path.resolve(__dirname, '../../'); // backend root
  const files = DirectoryScanner.scanPath(testDir, config.ignore);

  console.log(`\n✅ Scanned directory: ${testDir}`);
  console.log(`   Source files found: ${files.length}`);

  if (files.length > 0) {
    console.log(`   Sample relative path: ${files[0].relativePath} (${files[0].language})`);
  } else {
    throw new Error('No files found during directory scan!');
  }

  console.log('\n🎉 DIRECTORY SCANNER TEST PASSED SUCCESSFULLY!\n');
}

testDirectoryScanner().catch(err => {
  console.error('❌ DIRECTORY SCANNER TEST FAILED:', err);
  process.exit(1);
});
