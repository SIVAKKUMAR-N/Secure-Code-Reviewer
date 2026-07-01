const BaseDetector = require('./BaseDetector');

class SecretsDetector extends BaseDetector {
  constructor() {
    super('Hardcoded Secrets', 'secrets', 'secrets');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  isFalsePositive(match, line, language) {
    const placeholders = [
      'your_password_here',
      'your_api_key_here',
      'YOUR_PASSWORD',
      'YOUR_API_KEY',
      'password_here',
      'api_key_here',
      'replace_me',
      'changeme',
      'example',
      'dummy',
      'test123',
      '12345',
      'password123',
    ];

    // Extract the quoted secret value from the match to avoid substring false positives
    const quoteRegex = /(['"])(.*?)\1/;
    const quoteMatch = match.match(quoteRegex);
    if (!quoteMatch) {
      return false;
    }
    const secretValue = quoteMatch[2];
    const lowerSecret = secretValue.toLowerCase();

    // Check if the secret value matches any placeholder exactly
    if (placeholders.some(p => lowerSecret === p.toLowerCase())) {
      return true;
    }

    // Check if the secret contains obvious placeholders
    const obviousPlaceholders = [
      'your_password_here',
      'your_api_key_here',
      'password_here',
      'api_key_here',
      'replace_me',
      'changeme',
    ];
    if (obviousPlaceholders.some(p => lowerSecret.includes(p.toLowerCase()))) {
      return true;
    }

    // Check if it's an environment variable reference
    if (line.includes('process.env') || line.includes('os.environ') || line.includes('getenv')) {
      return true;
    }

    // Check if it's in a config template file
    if (line.includes('.example') || line.includes('.template')) {
      return true;
    }

    return false;
  }

  extractSnippet(lines, lineIndex) {
    const line = lines[lineIndex];
    // Mask the secret value
    const maskedLine = line.replace(/(['"])([a-zA-Z0-9+/=]{15,})\1/g, (match, quote, secret) => {
      return `${quote}${'*'.repeat(Math.min(secret.length, 20))}${quote}`;
    });
    return `> ${lineIndex + 1} | ${maskedLine}`;
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 70;

    // Higher confidence for longer secrets
    const secretLength = match.replace(/['"=:\s]/g, '').length;
    if (secretLength > 30) {
      confidence += 15;
    }

    // Lower confidence if contains common words
    const commonWords = ['password', 'secret', 'key', 'token'];
    const hasCommonWord = commonWords.some(word => match.toLowerCase().includes(word));
    if (hasCommonWord) {
      confidence += 10;
    }

    // Higher confidence for specific formats (AWS keys, JWT, etc.)
    if (/[A-Z0-9]{20}/.test(match)) {
      confidence += 10; // AWS access key format
    }
    if (/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/.test(match)) {
      confidence += 15; // JWT format
    }

    return Math.max(60, Math.min(100, confidence));
  }
}

module.exports = SecretsDetector;