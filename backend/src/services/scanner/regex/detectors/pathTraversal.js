const BaseDetector = require('./BaseDetector');

class PathTraversalDetector extends BaseDetector {
  constructor() {
    super('Path Traversal', 'path_traversal', 'pathTraversal');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }
}

module.exports = PathTraversalDetector;
