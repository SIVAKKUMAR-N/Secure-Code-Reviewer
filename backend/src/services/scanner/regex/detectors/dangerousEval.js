const BaseDetector = require('./BaseDetector');

class DangerousEvalDetector extends BaseDetector {
  constructor() {
    super('Dangerous Eval', 'dangerous_eval', 'dangerousEval');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = DangerousEvalDetector;
