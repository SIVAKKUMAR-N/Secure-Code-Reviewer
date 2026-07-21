const { execSync } = require('child_process');
const path = require('path');

/**
 * GitHelper
 * Extracts Git repository metadata (branch, commit hash, repository name) if available.
 */
class GitHelper {
  /**
   * Retrieves git details for a given working directory
   * @param {string} cwd - Directory path to inspect
   * @returns {Object} { branch, commit, repository }
   */
  static getGitContext(cwd = process.cwd()) {
    const absPath = path.resolve(cwd);
    const defaultInfo = {
      branch: 'main',
      commit: 'local',
      repository: path.basename(absPath) || absPath
    };

    try {
      const execOpts = { cwd: absPath, stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 };

      // 1. Get branch
      let branch = defaultInfo.branch;
      try {
        branch = execSync('git rev-parse --abbrev-ref HEAD', execOpts).toString().trim();
      } catch (_) {}

      // 2. Get commit hash
      let commit = defaultInfo.commit;
      try {
        commit = execSync('git rev-parse --short HEAD', execOpts).toString().trim();
      } catch (_) {}

      // 3. Get remote repository URL or folder name
      let repository = defaultInfo.repository;
      try {
        const remoteUrl = execSync('git config --get remote.origin.url', execOpts).toString().trim();
        if (remoteUrl) {
          const parts = remoteUrl.replace(/\\/g, '/').replace(/\.git$/, '').split('/').filter(Boolean);
          const repoName = parts.pop();
          const ownerName = parts.pop();
          if (repoName) {
            repository = (ownerName && ownerName.toLowerCase() !== repoName.toLowerCase())
              ? repoName
              : repoName;
          }
        }
      } catch (_) {}

      return {
        branch,
        commit,
        repository
      };

    } catch (err) {
      return defaultInfo;
    }
  }
}

module.exports = GitHelper;
