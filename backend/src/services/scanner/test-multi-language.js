const ScannerEngine = require('./index');

const engine = new ScannerEngine();

const testCases = {
  typescript: {
    language: 'typescript',
    code: `
import { createHash } from 'crypto';
import { exec } from 'child_process';

function processUser(id: string, req: any) {
  // 1. SQL injection in TS (string interpolation in query method)
  db.query(\`SELECT * FROM users WHERE id = \${id}\`);

  // 2. XSS in TS
  document.getElementById('app').innerHTML = req.query.name;

  // 3. Weak Hashing in TS
  const hash = createHash('md5').update('secret').digest('hex');

  // 4. Command Injection in TS
  exec(\`ping \${req.query.host}\`);
}
    `
  },
  java: {
    language: 'java',
    code: `
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Vulnerable {
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        
        // 1. SQL Injection (String concatenation in raw SQL execution)
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        connection.executeQuery(sql);
        
        // 2. XSS (Direct response writing of request parameter)
        response.getWriter().println(request.getParameter("name"));
        
        // 3. Weak Hashing (MD5 algorithm initialization)
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        // 4. Command Injection (Executing shell command with user input)
        Runtime.getRuntime().exec("ping " + request.getParameter("host"));
    }
}
    `
  },
  csharp: {
    language: 'csharp',
    code: `
using System;
using System.Security.Cryptography;
using System.Diagnostics;

class Program {
    void Unsafe(string id, string host) {
        // 1. SQL Injection (String concatenation in SQL command text)
        cmd.CommandText = "SELECT * FROM users WHERE id = '" + id + "'";
        
        // 2. XSS (Direct output of Request parameters)
        Response.Write(Request.QueryString["name"]);
        
        // 3. Weak Hashing (MD5 hash algorithm instantiated)
        var hash = MD5.Create();
        
        // 4. Command Injection (Process started with user query)
        Process.Start("ping.exe", Request.QueryString["host"]);
    }
}
    `
  },
  ruby: {
    language: 'ruby',
    code: `
# SQL Injection (String interpolation in ActiveRecord query)
User.where("SELECT * FROM users WHERE id = '#{id}'")

# XSS (html_safe raw params)
raw(params[:name])

# Weak Hashing (MD5 Utilized)
Digest::MD5.hexdigest("password")

# Command Injection (String interpolation in shell call)
system("ping #{params[:host]}")
    `
  },
  go: {
    language: 'go',
    code: `
package main

import (
    "crypto/md5"
    "fmt"
    "os/exec"
    "net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
    // 1. SQL Injection (fmt.Sprintf in Exec context)
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
    
    // 2. XSS (unescaped request variable writing to response)
    w.Write([]byte(r.FormValue("name")))
    
    // 3. Weak Hashing (md5 Sum package)
    h := md5.New()
    
    // 4. Command Injection (shell command populated from request)
    exec.Command("ping", r.FormValue("host"))
}
    `
  }
};

async function runTests() {
  console.log('=== RUNNING MULTI-LANGUAGE SCANNER VERIFICATION ===\n');
  
  let totalFailed = 0;
  
  for (const [langKey, testCase] of Object.entries(testCases)) {
    console.log(`Scanning ${testCase.language.toUpperCase()}...`);
    try {
      const result = await engine.scan(testCase.code, testCase.language);
      console.log(`Scan duration: ${result.scanDuration}ms`);
      console.log(`Vulnerabilities detected: ${result.vulnerabilities.length}`);
      
      const detectedTypes = result.vulnerabilities.map(v => v.type);
      console.log('Detected Types:', detectedTypes);
      
      // We expect 4 vulnerabilities for each language test case
      if (result.vulnerabilities.length >= 4) {
        console.log('✅ PASS: Detected all key vulnerability classes.');
      } else {
        console.log(`❌ FAIL: Expected 4 vulnerabilities, detected ${result.vulnerabilities.length}`);
        totalFailed++;
      }
      
      // Log details of detection
      result.vulnerabilities.forEach(v => {
        console.log(`  - [Line ${v.line}] [Severity: ${v.severity}] [CWE: ${v.cweId}] ${v.type}: ${v.message}`);
      });
      console.log('\n----------------------------------------\n');
    } catch (err) {
      console.error(`❌ ERROR scanning ${testCase.language}:`, err);
      totalFailed++;
    }
  }
  
  if (totalFailed === 0) {
    console.log('🎉 ALL MULTI-LANGUAGE SCANNER TESTS PASSED! 🎉');
  } else {
    console.log(`⚠️ SCANNER TESTS FAILED: ${totalFailed} language suites failed validation.`);
    process.exit(1);
  }
}

runTests();
