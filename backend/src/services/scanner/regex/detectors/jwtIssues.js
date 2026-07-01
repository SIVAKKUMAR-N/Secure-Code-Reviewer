const BaseDetector = require('./BaseDetector');

class JWTIssuesDetector extends BaseDetector {
  constructor() {
    super('Unsafe JWT Usage', 'jwt_issues', 'jwtIssues');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  detect(code, language) {
    // Run the base detector first
    const findings = super.detect(code, language);
    
    // If not javascript or typescript, return base findings
    if (language !== 'javascript' && language !== 'typescript') {
      return findings;
    }

    const lines = code.split('\n');

    lines.forEach((line, index) => {
      const lineNumber = index + 1;

      if (this.shouldSkipLine(line, language)) {
        return;
      }

      // Additional check: jwt.sign without expiration
      if (line.includes('jwt.sign') && !line.includes('expiresIn')) {
        const snippet = this.extractSnippet(lines, index);
        
        findings.push({
          id: `${language === 'typescript' ? 'TS' : 'JS'}-JWT-003`,
          type: this.name,
          severity: 'Medium',
          cvssScore: 5.5,
          line: lineNumber,
          column: line.indexOf('jwt.sign'),
          snippet: snippet,
          message: 'JWT without expiration: Token should have an expiration time',
          recommendation: 'Configure expiresIn parameter in jwt.sign options to enforce token expiration.',
          confidence: 80,
          cweId: 'CWE-613',
          owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        });
      }

      // Check for algorithm 'none' vulnerability
      if (line.includes('algorithm') && /algorithm.*['"]none['"]/.test(line)) {
        const snippet = this.extractSnippet(lines, index);
        
        findings.push({
          id: `${language === 'typescript' ? 'TS' : 'JS'}-JWT-004`,
          type: this.name,
          severity: 'Critical',
          cvssScore: 9.5,
          line: lineNumber,
          column: line.indexOf('algorithm'),
          snippet: snippet,
          message: 'JWT Algorithm None: Critical vulnerability allowing signature bypass',
          recommendation: 'Do not allow "none" algorithm in JWT headers. Explicitly restrict allowed algorithms during verification.',
          confidence: 95,
          cweId: 'CWE-347',
          owaspCategory: 'A02:2021 - Cryptographic Failures',
        });
      }
    });

    return this.deduplicateFindings(findings);
  }
}

module.exports = JWTIssuesDetector;