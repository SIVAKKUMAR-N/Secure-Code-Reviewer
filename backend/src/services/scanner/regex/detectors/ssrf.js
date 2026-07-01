const BaseDetector = require('./BaseDetector');

class SSRFDetector extends BaseDetector {
  constructor() {
    super('Server-Side Request Forgery (SSRF)', 'ssrf', 'ssrf');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = SSRFDetector;
