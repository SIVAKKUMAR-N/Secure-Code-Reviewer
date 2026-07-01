const ScannerEngine = require('./index');

const engine = new ScannerEngine();

const testCode = `
const express = require('express');
const app = express();
const fs = require('fs');
const exec = require('child_process').exec;
const crypto = require('crypto');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const axios = require('axios');

app.post('/unsafe-action', (req, res) => {
  const query = req.query;

  // 1. SQL Injection
  db.query(\`SELECT * FROM users WHERE username = '\${query.username}'\`);

  // 2. XSS
  document.getElementById('output').innerHTML = query.name;

  // 3. Command Injection
  exec('ping -c 1 ' + query.host);

  // 4. Hardcoded Secrets
  const apiKey = 'AIzaSyA12345678901234567890';

  // 5. Weak Hashing
  const hash = crypto.createHash('md5');

  // 6. Dangerous eval()
  eval(query.code);

  // 7. Unsafe File Upload
  const upload = multer({ dest: 'uploads/' }).single('avatar');

  // 8. Path Traversal
  fs.readFileSync('/var/www/uploads/' + query.filename);

  // 9. Unsafe Deserialization
  const obj = require('node-serialize').unserialize(query.serialized);

  // 10. JWT Misconfigurations
  jwt.sign({ id: 1 }, 'weak');

  // 11. Missing Input Validation
  const username = req.body.username;

  // 12. ReDoS
  const r = new RegExp(query.pattern);

  // 13. SSRF
  axios.get('https://' + query.url);

  // 14. Insecure Randomness
  const randomToken = Math.random();

  res.send('Done');
});
`;

async function runTest() {
  console.log('=== RUNNING ALL 14 CATEGORIES SCANNER TEST ===\n');

  try {
    const result = await engine.scan(testCode, 'javascript');
    
    console.log(`Scan completed in ${result.scanDuration}ms`);
    console.log(`Vulnerabilities detected: ${result.vulnerabilities.length}`);
    console.log(`Scan Risk Score: ${result.statistics.riskScore}/100\n`);

    // We want to map each detected vulnerability by its type/name
    const detectedCategories = new Set();
    
    console.log('Detected Findings:');
    result.vulnerabilities.forEach(v => {
      detectedCategories.add(v.type);
      console.log(`  - [ID: ${v.id}] [Line ${v.line}] [Severity: ${v.severity}] [CVSS: ${v.cvssScore}] ${v.type}: ${v.message}`);
    });
    
    console.log('\nSummary of Detected Categories:');
    console.log(Array.from(detectedCategories).map(c => `  - ${c}`).join('\n'));

    // Check if we detected all 14 categories
    const expectedCategories = [
      'SQL Injection',
      'Cross-Site Scripting (XSS)',
      'Command Injection',
      'Hardcoded Secrets',
      'Weak Password Hashing',
      'Dangerous Eval',
      'Insecure File Upload',
      'Path Traversal',
      'Unsafe Deserialization',
      'Unsafe JWT Usage',
      'Missing Input Validation',
      'Regular Expression Denial of Service (ReDoS)',
      'Server-Side Request Forgery (SSRF)',
      'Insecure Randomness'
    ];

    console.log('\nCategory Match Verification:');
    let missingCount = 0;
    expectedCategories.forEach(cat => {
      const detected = detectedCategories.has(cat);
      if (detected) {
        console.log(`  ✅ ${cat}: DETECTED`);
      } else {
        console.log(`  ❌ ${cat}: MISSING`);
        missingCount++;
      }
    });

    // Verify finding ID patterns: should be JS-SQLI-001, etc.
    console.log('\nID Format Verification:');
    let badIds = 0;
    result.vulnerabilities.forEach(v => {
      const match = /^[A-Z]{2,4}-[A-Z]{3,5}-\d{3}$/.test(v.id);
      if (match) {
        // Correct format
      } else {
        console.log(`  ❌ Finding ID "${v.id}" does not match standard pattern (e.g. JS-SQLI-001)`);
        badIds++;
      }
    });
    if (badIds === 0) {
      console.log('  ✅ All Finding IDs match naming standard.');
    }

    // Verify CVSS score exists and is a number between 0.0 and 10.0
    console.log('\nCVSS Score Verification:');
    let badCvss = 0;
    result.vulnerabilities.forEach(v => {
      if (typeof v.cvssScore !== 'number' || v.cvssScore < 0.0 || v.cvssScore > 10.0) {
        console.log(`  ❌ Vulnerability line ${v.line} has invalid CVSS score: ${v.cvssScore}`);
        badCvss++;
      }
    });
    if (badCvss === 0) {
      console.log('  ✅ All CVSS scores are valid numbers between 0.0 and 10.0.');
    }

    if (missingCount === 0 && badIds === 0 && badCvss === 0) {
      console.log('\n🎉 ALL 14 CATEGORY VERIFICATION TESTS PASSED SUCCESSFULLY! 🎉');
      process.exit(0);
    } else {
      console.log(`\n❌ TEST FAILURE: ${missingCount} categories missing, ${badIds} invalid IDs, ${badCvss} invalid CVSS.`);
      process.exit(1);
    }

  } catch (error) {
    console.error('Test execution failed:', error);
    process.exit(1);
  }
}

runTest();
