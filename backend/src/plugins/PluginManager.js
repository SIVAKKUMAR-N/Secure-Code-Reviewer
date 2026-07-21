const ASTPlugin = require('./ASTPlugin');
const RegexPlugin = require('./RegexPlugin');
const SemgrepPlugin = require('./SemgrepPlugin');
const CodeQLPlugin = require('./CodeQLPlugin');
const logger = require('../utils/logger');

/**
 * PluginManager
 * Coordinates registration, discovery, and execution of active SAST detection plugins.
 * Distinguishes functional active plugins from architectural stubs.
 */
class PluginManager {
  constructor() {
    this.plugins = [];
    this.registerDefaultPlugins();
  }

  registerDefaultPlugins() {
    this.register(new ASTPlugin());
    this.register(new RegexPlugin());
    this.register(new SemgrepPlugin());
    this.register(new CodeQLPlugin());
  }

  register(plugin) {
    if (!plugin || typeof plugin.scan !== 'function') {
      throw new Error('Invalid plugin. Must inherit from BasePlugin');
    }
    this.plugins.push(plugin);

    if (plugin.isStub || !plugin.enabled) {
      logger.debug(`Registered NoVuln Plugin (Stub / Disabled): ${plugin.name} (${plugin.type})`);
    } else {
      logger.debug(`Loaded Active NoVuln Plugin: ${plugin.name} (${plugin.type})`);
    }
  }

  getRegisteredPlugins() {
    return this.plugins.map(p => ({
      name: p.name,
      type: p.type,
      supportedLanguages: p.supportedLanguages,
      enabled: p.enabled,
      isStub: p.isStub
    }));
  }

  getActivePlugins() {
    return this.plugins.filter(p => p.enabled && !p.isStub);
  }

  getStubPlugins() {
    return this.plugins.filter(p => p.isStub || !p.enabled);
  }

  /**
   * Executes active functional plugins for a specific source file
   * @param {string} code - Source code
   * @param {string} language - Programming language
   * @param {string} filePath - Target file path
   * @returns {Promise<Array<Object>>} Aggregated raw findings
   */
  async executePlugins(code, language, filePath = 'snippet.js') {
    const rawFindings = [];
    const activePlugins = this.getActivePlugins().filter(p => p.supportsLanguage(language));

    for (const plugin of activePlugins) {
      try {
        const results = await plugin.scan(code, language, filePath);
        if (Array.isArray(results) && results.length > 0) {
          rawFindings.push(...results);
        }
      } catch (err) {
        logger.debug(`Error executing plugin ${plugin.name} on ${filePath}: ${err.message}`);
      }
    }

    return rawFindings;
  }
}

module.exports = PluginManager;
