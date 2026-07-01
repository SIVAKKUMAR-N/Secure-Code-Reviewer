const BaseDetector = require('./BaseDetector');

class UnsafeDeserializationDetector extends BaseDetector {
  constructor() {
    super('Unsafe Deserialization', 'unsafe_deserialization', 'unsafeDeserialization');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = UnsafeDeserializationDetector;
