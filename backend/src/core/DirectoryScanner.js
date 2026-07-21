const fs = require('fs');
const path = require('path');
const ConfigLoader = require('./ConfigLoader');
const logger = require('../utils/logger');

/**
 * DirectoryScanner
 * Recursively locates source files in a target directory while honoring ignore rules.
 */
class DirectoryScanner {
  static EXTENSION_MAP = {
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.java': 'java',
    '.cs': 'csharp',
    '.rb': 'ruby',
    '.go': 'go',
    '.php': 'php'
  };

  /**
   * Scans a target path (file or directory) and returns source files to be analyzed.
   * @param {string} targetPath - Path to directory or single file
   * @param {Array<string>} [ignoreList] - Directory names/paths to ignore
   * @returns {Array<Object>} List of file objects: { filePath, relativePath, language, code, lineCount }
   */
  static scanPath(targetPath, ignoreList = []) {
    const absolutePath = path.resolve(targetPath);
    
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stat = fs.statSync(absolutePath);

    // If single file target
    if (stat.isFile()) {
      const ext = path.extname(absolutePath).toLowerCase();
      const language = DirectoryScanner.EXTENSION_MAP[ext];
      if (!language) {
        throw new Error(`Unsupported file extension: ${ext}`);
      }
      const code = fs.readFileSync(absolutePath, 'utf8');
      return [{
        filePath: absolutePath,
        relativePath: path.basename(absolutePath),
        language,
        code,
        lineCount: code.split('\n').length
      }];
    }

    // If directory target
    const filesFound = [];
    const normalizedIgnore = ignoreList.map(p => ConfigLoader.normalizeIgnorePath(p)).filter(Boolean);

    function walkDir(currentDir) {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        const entryNameNorm = ConfigLoader.normalizeIgnorePath(entry.name);
        const relPathNorm = ConfigLoader.normalizeIgnorePath(path.relative(absolutePath, fullPath));

        // Check ignore list against folder name or relative path
        const isIgnored = normalizedIgnore.some(ignoreItem => (
          entryNameNorm === ignoreItem ||
          relPathNorm === ignoreItem ||
          relPathNorm.startsWith(ignoreItem + '/') ||
          relPathNorm.startsWith(ignoreItem + '\\')
        ));

        if (isIgnored || entry.name.startsWith('.')) {
          if (entry.name !== '.' && entry.name !== '..') {
            continue;
          }
        }

        if (entry.isDirectory()) {
          walkDir(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          const language = DirectoryScanner.EXTENSION_MAP[ext];

          if (language) {
            try {
              const code = fs.readFileSync(fullPath, 'utf8');
              const relativePath = path.relative(absolutePath, fullPath).replace(/\\/g, '/');
              filesFound.push({
                filePath: fullPath,
                relativePath,
                language,
                code,
                lineCount: code.split('\n').length
              });
            } catch (err) {
              logger.warn(`Could not read file ${fullPath}: ${err.message}`);
            }
          }
        }
      }
    }

    walkDir(absolutePath);
    return filesFound;
  }
}

module.exports = DirectoryScanner;
