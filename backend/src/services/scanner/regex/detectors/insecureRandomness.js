const BaseDetector = require('./BaseDetector');

class InsecureRandomnessDetector extends BaseDetector {
  constructor() {
    super('Insecure Randomness', 'insecure_randomness', 'insecureRandomness');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = InsecureRandomnessDetector;
