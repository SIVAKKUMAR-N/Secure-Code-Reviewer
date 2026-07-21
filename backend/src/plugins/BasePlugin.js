/**
 * BasePlugin
 * Standard interface contract for all SAST detection plugins.
 */
class BasePlugin {
  /**
   * @param {string} name - Plugin name
   * @param {string} type - Plugin type ('ast' | 'regex' | 'semgrep' | 'codeql')
   * @param {Array<string>} supportedLanguages - Supported language strings
   * @param {boolean} [isStub=false] - Whether this plugin is a future extension stub
   */
  constructor(name, type, supportedLanguages = [], isStub = false) {
    if (new.target === BasePlugin) {
      throw new TypeError('Cannot construct BasePlugin instances directly');
    }
    this.name = name;
    this.type = type;
    this.supportedLanguages = supportedLanguages.map(l => l.toLowerCase());
    this.isStub = isStub;
    this.enabled = !isStub;
  }

  /**
   * Check if plugin supports a given language
   * @param {string} language - Target language
   * @returns {boolean} True if supported
   */
  supportsLanguage(language) {
    if (!language || !this.enabled || this.isStub) return false;
    return this.supportedLanguages.includes(language.toLowerCase());
  }

  /**
   * Abstract scan method
   * @param {string} code - Source code string
   * @param {string} language - Target language
   * @param {string} filePath - Relative or absolute file path
   * @returns {Promise<Array<Object>>} Array of raw finding objects
   */
  async scan(code, language, filePath = 'snippet.js') {
    throw new Error(`Plugin ${this.name} must implement the scan() method.`);
  }
}

module.exports = BasePlugin;
