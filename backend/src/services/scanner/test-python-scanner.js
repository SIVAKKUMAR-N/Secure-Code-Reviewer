const ScannerEngine = require('./index');

const engine = new ScannerEngine();

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
    const results = await engine.scan(pythonCode, 'python');
    console.log('Scan results:', JSON.stringify(results, null, 2));
  } catch (err) {
    console.error('Scan failed:', err);
  }
}

run();
