const BaseDetector = require('./BaseDetector');

class XSSDetector extends BaseDetector {
  constructor() {
    super('Cross-Site Scripting (XSS)', 'xss', 'xss');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 75;

    // Check for sanitization functions
    const sanitizationIndicators = {
      javascript: ['DOMPurify', 'sanitize', 'escape', 'encodeHTML'],
      python: ['escape', 'bleach', 'markupsafe'],
      php: ['htmlspecialchars', 'htmlentities', 'strip_tags'],
    };

    const sanitizers = sanitizationIndicators[language] || [];
    const hasSanitization = sanitizers.some(s => line.includes(s));
    
    if (hasSanitization) {
      confidence -= 30;
    }

    // Check for user input
    const userInputIndicators = ['req.', 'input', '$_GET', '$_POST', 'request.'];
    const hasUserInput = userInputIndicators.some(i => line.includes(i));
    
    if (hasUserInput) {
      confidence += 15;
    }

    return Math.max(50, Math.min(100, confidence));
  }
}

module.exports = XSSDetector;