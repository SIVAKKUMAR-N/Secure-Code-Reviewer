const BaseDetector = require('./BaseDetector');

class ReDoSDetector extends BaseDetector {
  constructor() {
    super('Regular Expression Denial of Service (ReDoS)', 'redos', 'redos');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = ReDoSDetector;
