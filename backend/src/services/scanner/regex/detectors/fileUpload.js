const BaseDetector = require('./BaseDetector');

class FileUploadDetector extends BaseDetector {
  constructor() {
    super('Insecure File Upload', 'file_upload', 'fileUpload');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  detect(code, language) {
    this.currentLines = code.split('\n');
    return super.detect(code, language);
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 75;

    // Find the line index
    if (!this.currentLines) return confidence;
    const lineIndex = this.currentLines.indexOf(line);
    if (lineIndex === -1) return confidence;

    // Check surrounding lines for validation
    const contextRange = 5;
    const startIndex = Math.max(0, lineIndex - contextRange);
    const endIndex = Math.min(this.currentLines.length - 1, lineIndex + contextRange);
    
    const context = this.currentLines.slice(startIndex, endIndex + 1).join('\n');

    // Look for validation keywords
    const validationKeywords = [
      'mimetype', 'fileFilter', 'allowedTypes', 'whitelist',
      'extension', 'size', 'maxSize', 'validate'
    ];

    const hasValidation = validationKeywords.some(keyword => 
      context.toLowerCase().includes(keyword.toLowerCase())
    );

    if (hasValidation) {
      confidence -= 30; // Likely has some validation
    } else {
      confidence += 10; // No validation found nearby
    }

    return Math.max(50, Math.min(100, confidence));
  }
}

module.exports = FileUploadDetector;