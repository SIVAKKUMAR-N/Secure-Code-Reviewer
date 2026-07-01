const BaseDetector = require('./BaseDetector');

class SQLInjectionDetector extends BaseDetector {
  constructor() {
    super('SQL Injection', 'sqli', 'sqlInjection');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 80;

    // Increase confidence if dangerous SQL keywords are present
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE'];
    const upperLine = line.toUpperCase();
    
    const hasSQLKeyword = sqlKeywords.some(keyword => upperLine.includes(keyword));
    if (hasSQLKeyword) {
      confidence += 10;
    }

    // Increase confidence if user input variables are detected
    const userInputPatterns = {
      javascript: ['req.body', 'req.query', 'req.params', 'input', 'userInput'],
      python: ['request.args', 'request.form', 'request.json', 'input()'],
      php: ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'],
    };

    const inputVars = userInputPatterns[language] || [];
    const hasUserInput = inputVars.some(varName => line.includes(varName));
    
    if (hasUserInput) {
      confidence = Math.min(95, confidence + 10);
    }

    // Decrease confidence if parameterized query indicators are present
    const parameterizedIndicators = ['?', '$1', '$2', ':name', 'prepared'];
    const hasParameterized = parameterizedIndicators.some(ind => line.includes(ind));
    
    if (hasParameterized && !match.includes('$')) {
      confidence -= 20;
    }

    return Math.max(50, Math.min(100, confidence));
  }
}

module.exports = SQLInjectionDetector;