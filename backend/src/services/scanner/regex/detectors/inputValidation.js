const BaseDetector = require('./BaseDetector');

class InputValidationDetector extends BaseDetector {
  constructor() {
    super('Missing Input Validation', 'input_validation', 'inputValidation');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  isFalsePositive(match, line, language) {
    const validationIndicators = [
      'validate', 'sanitize', 'check', 'verify',
      'test(', 'match(', 'typeof', 'instanceof',
      'parseInt', 'parseFloat', 'Number(',
      'trim()', 'escape', 'filter'
    ];

    return validationIndicators.some(indicator => line.includes(indicator));
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 60;

    // Check for direct assignment or usage patterns
    if (line.includes('=') || line.includes('function') || line.includes('return')) {
      confidence += 10;
    }

    // Lower confidence if it's just passing through
    if (line.includes('next()') || line.includes('res.json')) {
      confidence -= 15;
    }

    return Math.max(50, Math.min(100, confidence));
  }
}

module.exports = InputValidationDetector;
