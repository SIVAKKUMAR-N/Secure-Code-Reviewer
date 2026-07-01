const path = require('path');
const dotenv = require('dotenv');

const envPath = path.resolve(__dirname, '../../../.env');
console.log('Resolving .env path to:', envPath);
dotenv.config({ path: envPath });

const ScannerEngine = require('../scanner');
const AIService = require('./index');

const scanner = new ScannerEngine();
const aiService = new AIService();

const pythonCode = `# Example vulnerable code
import hashlib
from flask import Flask, request

app = Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('username')
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    # Weak hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()`;

async function run() {
  try {
    console.log('Running scanner...');
    const scanResults = await scanner.scan(pythonCode, 'python');
    console.log('Local vulnerabilities count:', scanResults.vulnerabilities.length);
    
    console.log('Calling AI service enrichment...');
    const enriched = await aiService.enrichVulnerabilities(
      scanResults.vulnerabilities,
      pythonCode,
      'python'
    );
    console.log('Enriched results:', JSON.stringify(enriched, null, 2));
  } catch (error) {
    console.error('Enrichment failed:', error);
  }
}

run();
