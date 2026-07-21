const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * ConfigLoader
 * Reads, validates, normalizes, and merges default configs, scanner.config.json, and CLI flags.
 */
class ConfigLoader {
  static SUPPORTED_LANGUAGES = [
    'javascript',
    'typescript',
    'python',
    'java',
    'csharp',
    'ruby',
    'go',
    'php'
  ];

  static VALID_CONFIG_KEYS = [
    '$schema',
    'schemaVersion',
    'ignore',
    'languages',
    'ai',
    'output'
  ];

  static DEFAULT_CONFIG = {
    schemaVersion: '1.0',
    ignore: [
      'node_modules',
      '.git',
      'dist',
      'build',
      'coverage',
      'vendor',
      '.env',
      '.vscode',
      '.idea',
      'temp',
      'tmp'
    ],
    languages: [
      'javascript',
      'typescript',
      'python',
      'java',
      'csharp',
      'ruby',
      'go',
      'php'
    ],
    ai: true,
    output: {
      json: 'report.json',
      summary: 'summary.json'
    }
  };

  /**
   * Standardizes ignore path strings across OS platforms.
   * Strip leading dot-slashes, trailing slashes, and convert to lowercase.
   * e.g., ".\node_modules\", "./node_modules/", "node_modules" -> "node_modules"
   */
  static normalizeIgnorePath(p) {
    if (!p || typeof p !== 'string') return '';
    return path.normalize(p)
      .replace(/^[.\\/]+/, '')
      .replace(/[\\/]+$/, '')
      .toLowerCase();
  }

  /**
   * Load, validate, normalize, and merge configuration settings.
   * Priority Order:
   * 1. --config <path> (if supplied)
   * 2. <targetPath>/scanner.config.json
   * 3. <process.cwd()>/scanner.config.json
   * 4. Built-in defaults
   * 
   * @param {string} [customConfigPath] - Optional custom config file path
   * @param {Object} [cliOverrides] - CLI flag overrides
   * @param {string} [targetPath] - Target scan directory path
   * @returns {Object} Final merged configuration object
   */
  static loadConfig(customConfigPath, cliOverrides = {}, targetPath = null) {
    let fileConfig = {};
    let loadedFrom = null;

    // 1. Locate config file according to strict priority order
    const resolvedTarget = targetPath ? path.resolve(targetPath) : null;
    const searchPaths = [
      customConfigPath ? path.resolve(customConfigPath) : null,
      resolvedTarget ? path.join(resolvedTarget, 'scanner.config.json') : null,
      path.join(process.cwd(), 'scanner.config.json')
    ].filter(Boolean);

    // Deduplicate search paths preserving order
    const uniqueSearchPaths = Array.from(new Set(searchPaths));

    for (const configPath of uniqueSearchPaths) {
      if (fs.existsSync(configPath) && fs.statSync(configPath).isFile()) {
        try {
          const raw = fs.readFileSync(configPath, 'utf8');
          fileConfig = JSON.parse(raw);
          loadedFrom = configPath;
          logger.debug(`Loaded configuration file from: ${configPath}`);
          break;
        } catch (err) {
          throw new Error(`Invalid JSON in configuration file at ${configPath}: ${err.message}`);
        }
      }
    }

    if (!loadedFrom) {
      logger.debug('Using default configuration.');
    }

    // 2. Validate unknown keys (typo detection)
    const fileKeys = Object.keys(fileConfig);
    const unknownKeys = fileKeys.filter(k => !ConfigLoader.VALID_CONFIG_KEYS.includes(k));
    if (unknownKeys.length > 0) {
      logger.warn(`Unknown configuration property: "${unknownKeys.join(', ')}". Valid keys are: ${ConfigLoader.VALID_CONFIG_KEYS.join(', ')}`);
    }

    // 3. Validate types (fail-fast)
    if (fileConfig.ignore !== undefined && !Array.isArray(fileConfig.ignore)) {
      throw new Error('Configuration error: "ignore" must be an array of string paths.');
    }
    if (fileConfig.languages !== undefined && !Array.isArray(fileConfig.languages)) {
      throw new Error('Configuration error: "languages" must be an array of string language names.');
    }
    if (fileConfig.ai !== undefined && typeof fileConfig.ai !== 'boolean') {
      throw new Error('Configuration error: "ai" option must be a boolean (true or false).');
    }
    if (fileConfig.output !== undefined && (typeof fileConfig.output !== 'object' || fileConfig.output === null)) {
      throw new Error('Configuration error: "output" must be an object with output path options.');
    }

    // 4. Validate configured language names
    const configuredLanguages = fileConfig.languages || ConfigLoader.DEFAULT_CONFIG.languages;
    configuredLanguages.forEach(lang => {
      const normLang = String(lang).toLowerCase().trim();
      if (!ConfigLoader.SUPPORTED_LANGUAGES.includes(normLang)) {
        throw new Error(`Unsupported language configured: "${lang}". Supported languages are: ${ConfigLoader.SUPPORTED_LANGUAGES.join(', ')}`);
      }
    });

    // 5. Normalize ignore paths
    const rawIgnoreList = [
      ...ConfigLoader.DEFAULT_CONFIG.ignore,
      ...(fileConfig.ignore || []),
      ...(cliOverrides.ignore || [])
    ];
    const normalizedIgnoreList = Array.from(new Set(
      rawIgnoreList.map(p => ConfigLoader.normalizeIgnorePath(p)).filter(Boolean)
    ));

    // 6. Merge final effective configuration
    const mergedConfig = {
      schemaVersion: fileConfig.schemaVersion || ConfigLoader.DEFAULT_CONFIG.schemaVersion,
      loadedFrom,
      ignore: normalizedIgnoreList,
      languages: Array.from(new Set(configuredLanguages.map(l => String(l).toLowerCase().trim()))),
      ai: cliOverrides.ai !== undefined ? cliOverrides.ai : (fileConfig.ai !== undefined ? fileConfig.ai : ConfigLoader.DEFAULT_CONFIG.ai),
      output: {
        json: cliOverrides.json || (fileConfig.output && fileConfig.output.json) || ConfigLoader.DEFAULT_CONFIG.output.json,
        summary: cliOverrides.summary || (fileConfig.output && fileConfig.output.summary) || ConfigLoader.DEFAULT_CONFIG.output.summary,
        pdf: cliOverrides.pdf || (fileConfig.output && fileConfig.output.pdf) || null
      },
      store: !!cliOverrides.store
    };

    logger.debug(`Effective Config -> Languages: [${mergedConfig.languages.join(', ')}], AI: ${mergedConfig.ai}, Ignore Items: ${mergedConfig.ignore.length}`);

    return mergedConfig;
  }
}

module.exports = ConfigLoader;
