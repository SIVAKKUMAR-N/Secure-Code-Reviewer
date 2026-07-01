/**
 * AST Detection Test Suite
 * Asserts that the hybrid SAST engine successfully parses and traverses JavaScript/TypeScript 
 * files, structurally matching and reporting the 6 AST-based vulnerability categories.
 * Validates false positive reduction by asserting that safe code blocks produce zero findings.
 */

const ScannerEngine = require('./index');
const engine = new ScannerEngine();

// Vulnerable JS source block for structural testing
const vulnerableJS = `
const express = require('express');
const app = express();
const fs = require('fs');
const exec = require('child_process').exec;
const axios = require('axios');

app.get('/vulnerable-route', (req, res) => {
  const host = req.query.host;
  const userQuery = req.query.q;
  const pathInput = req.query.path;
  const targetUrl = req.query.url;
  const code = req.query.code;

  // 1. Command Injection
  exec("ping -c 1 " + host);

  // 2. SQL Injection
  db.query(\`SELECT * FROM users WHERE name = '\${userQuery}'\`);

  // 3. Dangerous eval()
  eval(code);

  // 4. XSS
  res.send("Hello " + req.query.name);

  // 5. SSRF
  axios.get(targetUrl);

  // 6. Path Traversal
  fs.readFileSync("/var/data/" + pathInput);
});
`;

// Safe JS source block to verify False Positive Reduction
const safeJS = `
const express = require('express');
const app = express();
const fs = require('fs');
const { exec, execFile, spawn } = require('child_process');
const axios = require('axios');
const DOMPurify = require('dompurify');
const path = require('path');

app.get('/safe-route', (req, res) => {
  const host = req.query.host;
  const userQuery = req.query.q;
  const pathInput = req.query.path;
  const targetUrl = req.query.url;
  const code = req.query.code;

  // 1. Safe Command Execution (static or shell-less with static args)
  exec("ls");
  execFile("ping", ["127.0.0.1"]);
  spawn("ping", ["127.0.0.1"]);

  // 2. Safe SQL Injection (parameterized or static)
  db.query("SELECT * FROM users");
  db.query("SELECT * FROM users WHERE id=?", [userQuery]);
  pool.execute("SELECT * FROM users WHERE email=$1", [userQuery]);
  sequelize.query(userQuery, {
    replacements: [userQuery]
  });

  // 3. Safe Eval (static string)
  eval("1 + 1");

  // 4. Safe XSS (static or sanitized)
  res.send("Hello World");
  res.send(DOMPurify.sanitize(req.query.name));
  res.send(encodeURIComponent(req.query.name));

  // 5. Safe SSRF (static URL)
  axios.get("https://google.com");

  // 6. Safe Path Traversal (static or sanitized basename)
  fs.readFileSync("/etc/hosts");
  fs.readFileSync(path.basename(pathInput));
  fs.readFileSync(basename(pathInput));
});
`;

// Vulnerable TS source block for structural testing
const vulnerableTS = `
import { exec } from 'child_process';
import * as fs from 'fs';
import axios from 'axios';

function handleRequest(req: any, res: any) {
  const host: string = req.query.host;
  const queryStr: string = req.query.q;
  const file: string = req.query.file;
  
  // AST Command Injection in TS
  exec(\`ping -c 1 \${host}\`);

  // AST SQL Injection in TS
  db.execute("SELECT * FROM products WHERE name = " + queryStr);

  // AST Path Traversal in TS
  fs.readFileSync(\`/app/static/\${file}\`);
}
`;

async function runTests() {
  console.log('=== RUNNING AST STRUCTURAL ANALYSIS VERIFICATION TESTS ===\n');
  
  let failed = false;

  // TEST 1: JavaScript AST Scan (Vulnerable Code)
  console.log('--- TEST 1: Scanning Vulnerable JavaScript Code via AST... ---');
  try {
    const result = await engine.scan(vulnerableJS, 'javascript');
    
    console.log(`Scan complete in ${result.scanDuration}ms.`);
    console.log(`Vulnerabilities found: ${result.vulnerabilities.length}\n`);

    const astFindings = result.vulnerabilities.filter(v => v.source === 'ast');
    console.log(`AST-sourced findings: ${astFindings.length} / ${result.vulnerabilities.length}`);
    
    // Output details of the findings
    astFindings.forEach(v => {
      console.log(`  [Line ${v.line}] ✅ Detected ${v.type} (ID: ${v.id}, Source: ${v.source})`);
      console.log(`    Sink: ${v.sink} | Reason: ${v.reason}`);
      console.log(`    CVSS: ${v.cvssScore} | Confidence: ${v.confidence} | CWE: ${v.cweId}\n`);
      
      // Assert explainability fields exist
      if (!v.sink) {
        console.log(`  ❌ Missing 'sink' field on finding line ${v.line}`);
        failed = true;
      }
      if (!v.reason) {
        console.log(`  ❌ Missing 'reason' field on finding line ${v.line}`);
        failed = true;
      }
      if (typeof v.confidence !== 'number' || v.confidence < 0.0 || v.confidence > 1.0) {
        console.log(`  ❌ Invalid 'confidence' value: ${v.confidence} (expected 0.0 - 1.0)`);
        failed = true;
      }
    });

    // Check we caught the 6 expected AST categories
    const expectedJSCategories = [
      'Command Injection',
      'SQL Injection',
      'Dangerous Eval',
      'Cross-Site Scripting (XSS)',
      'Server-Side Request Forgery (SSRF)',
      'Path Traversal'
    ];

    console.log('AST Category Coverage Validation:');
    expectedJSCategories.forEach(cat => {
      const found = astFindings.some(v => v.type === cat);
      if (found) {
        console.log(`  ✅ ${cat}: DETECTED`);
      } else {
        console.log(`  ❌ ${cat}: NOT DETECTED`);
        failed = true;
      }
    });
    console.log('');

  } catch (error) {
    console.error('❌ JavaScript AST Scan failed:', error);
    failed = true;
  }

  // TEST 2: JavaScript AST Scan (Safe Code - FP Reduction Verification)
  console.log('--- TEST 2: Scanning Safe JavaScript Code (False Positive Checks)... ---');
  try {
    const result = await engine.scan(safeJS, 'javascript');
    
    console.log(`Scan complete in ${result.scanDuration}ms.`);
    
    const astFindings = result.vulnerabilities.filter(v => v.source === 'ast');
    console.log(`AST-sourced findings: ${astFindings.length} (Expected: 0)`);
    
    if (astFindings.length === 0) {
      console.log('  ✅ SUCCESS: No false positive AST findings detected on safe coding patterns.');
    } else {
      console.log('  ❌ FAILURE: Detected false positive AST findings:');
      astFindings.forEach(v => {
        console.log(`    - Line ${v.line}: ${v.type} (Sink: ${v.sink}, Reason: ${v.reason})`);
      });
      failed = true;
    }
    console.log('');

  } catch (error) {
    console.error('❌ Safe JavaScript AST Scan failed:', error);
    failed = true;
  }

  // TEST 3: TypeScript AST Scan
  console.log('--- TEST 3: Scanning TypeScript Code via AST... ---');
  try {
    const result = await engine.scan(vulnerableTS, 'typescript');
    
    console.log(`Scan complete in ${result.scanDuration}ms.`);
    console.log(`Vulnerabilities found: ${result.vulnerabilities.length}\n`);

    const astFindings = result.vulnerabilities.filter(v => v.source === 'ast');
    console.log(`AST-sourced findings: ${astFindings.length} / ${result.vulnerabilities.length}`);
    
    astFindings.forEach(v => {
      console.log(`  [Line ${v.line}] ✅ Detected ${v.type} (ID: ${v.id}, Source: ${v.source})`);
      console.log(`    Message: ${v.message}\n`);
    });

    const expectedTSCategories = [
      'Command Injection',
      'SQL Injection',
      'Path Traversal'
    ];

    console.log('TypeScript AST Category Coverage Validation:');
    expectedTSCategories.forEach(cat => {
      const found = astFindings.some(v => v.type === cat);
      if (found) {
        console.log(`  ✅ ${cat}: DETECTED`);
      } else {
        console.log(`  ❌ ${cat}: NOT DETECTED`);
        failed = true;
      }
    });
    console.log('');

  } catch (error) {
    console.error('❌ TypeScript AST Scan failed:', error);
    failed = true;
  }

  if (!failed) {
    console.log('🎉 ALL AST SCANNER VERIFICATION TESTS PASSED SUCCESSFULLY! 🎉');
    process.exit(0);
  } else {
    console.log('❌ AST SCANNER VERIFICATION TESTS FAILED.');
    process.exit(1);
  }
}

runTests();
