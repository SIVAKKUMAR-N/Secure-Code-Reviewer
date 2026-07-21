const PluginManager = require('../plugins/PluginManager');
const ConfigLoader = require('./ConfigLoader');
const DirectoryScanner = require('./DirectoryScanner');
const FindingNormalizer = require('./FindingNormalizer');
const RiskAggregator = require('./RiskAggregator');
const GitHelper = require('./GitHelper');
const { mergeFindings } = require('../services/scanner/utils/merger');
const AIService = require('../services/ai');
const logger = require('../utils/logger');

/**
 * ScannerEngine
 * Enterprise SAST Orchestrator supporting single-file snippets and repository directory scanning.
 */
class ScannerEngine {
  constructor(config = {}) {
    // Load config once during initialization
    this.config = ConfigLoader.loadConfig(config.config, config, config.targetPath);
    // Initialize plugins once
    this.pluginManager = new PluginManager();

    try {
      this.aiService = new AIService();
    } catch (err) {
      logger.debug(`AI Service disabled or API key missing: ${err.message}`);
      this.aiService = null;
    }

    logger.debug('NoVuln Engine initialized successfully.');
  }

  /**
   * Scans a single string of code (Web UI & backwards compatibility mode)
   * @param {string} code - Source code string
   * @param {string} language - Target language
   * @param {Object} [options] - Additional options
   * @returns {Promise<Object>} Scan results
   */
  async scan(code, language, options = {}) {
    const startTime = Date.now();
    const normalizedLang = (language || 'javascript').toLowerCase().trim();
    const filePath = options.filePath || `code.${normalizedLang === 'typescript' ? 'ts' : 'js'}`;

    logger.debug(`Starting NoVuln scan for ${normalizedLang} code snippet (${code.length} chars)`);

    // 1. Execute detection plugins
    const rawFindings = await this.pluginManager.executePlugins(code, normalizedLang, filePath);

    // 2. Separate AST parser errors & valid findings
    const parserErrorMarkers = rawFindings.filter(f => f.__isParserError);
    const validRaw = rawFindings.filter(f => !f.__isParserError);

    const astFindings = validRaw.filter(f => f.source === 'ast');
    const regexFindings = validRaw.filter(f => f.source !== 'ast');

    // 3. Deduplicate overlapping findings
    const mergedRaw = ['javascript', 'typescript'].includes(normalizedLang)
      ? mergeFindings(astFindings, regexFindings)
      : validRaw;

    // 4. Normalize findings
    let normalizedFindings = FindingNormalizer.normalize(mergedRaw, filePath);

    // 5. AI Enrichment (if enabled and available)
    const enableAi = options.ai !== undefined ? options.ai : this.config.ai;
    if (enableAi && this.aiService && normalizedFindings.length > 0) {
      try {
        normalizedFindings = await this.aiService.enrichVulnerabilities(
          normalizedFindings,
          code,
          normalizedLang
        );
      } catch (aiErr) {
        logger.debug(`AI enrichment failed: ${aiErr.message}`);
      }
    }

    const durationMs = Date.now() - startTime;
    const langKey = normalizedLang.charAt(0).toUpperCase() + normalizedLang.slice(1);
    const aggregation = RiskAggregator.aggregate(
      normalizedFindings,
      durationMs,
      1,
      parserErrorMarkers.length,
      { [langKey]: 1 }
    );

    return {
      vulnerabilities: normalizedFindings,
      findings: normalizedFindings,
      statistics: aggregation.summary,
      summary: aggregation.summary,
      owaspMapping: aggregation.owaspMapping,
      cweMapping: aggregation.cweMapping,
      parserErrorDetails: parserErrorMarkers,
      scanDuration: durationMs,
      language: normalizedLang,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Scans an entire project repository directory
   * @param {string} targetPath - Directory or file path
   * @param {Object} [options] - Scan overrides
   * @returns {Promise<Object>} Enterprise scan result object
   */
  async scanDirectory(targetPath, options = {}) {
    const startTime = Date.now();
    // Use target-specific configuration
    const mergedConfig = ConfigLoader.loadConfig(options.config, options, targetPath);
    
    // 1. Locate files
    const sourceFiles = DirectoryScanner.scanPath(targetPath, mergedConfig.ignore);
    logger.debug(`NoVuln repository scan started. Found ${sourceFiles.length} file(s) to analyze in ${targetPath}`);

    const allValidFindings = [];
    const parserErrorMarkers = [];
    const languageCounts = {};

    // 2. Scan files with active plugins
    for (const fileObj of sourceFiles) {
      if (fileObj.language) {
        const langKey = fileObj.language === 'javascript' ? 'JavaScript'
          : fileObj.language === 'typescript' ? 'TypeScript'
          : fileObj.language === 'python' ? 'Python'
          : fileObj.language === 'java' ? 'Java'
          : fileObj.language === 'csharp' ? 'C#'
          : fileObj.language === 'ruby' ? 'Ruby'
          : fileObj.language === 'go' ? 'Go'
          : fileObj.language === 'php' ? 'PHP'
          : fileObj.language.charAt(0).toUpperCase() + fileObj.language.slice(1);

        languageCounts[langKey] = (languageCounts[langKey] || 0) + 1;
      }

      const fileRaw = await this.pluginManager.executePlugins(fileObj.code, fileObj.language, fileObj.relativePath);

      const fileErrors = fileRaw.filter(f => f.__isParserError);
      const fileValid = fileRaw.filter(f => !f.__isParserError);

      if (fileErrors.length > 0) {
        parserErrorMarkers.push(...fileErrors);
      }

      const astFindings = fileValid.filter(f => f.source === 'ast');
      const regexFindings = fileValid.filter(f => f.source !== 'ast');

      const merged = ['javascript', 'typescript'].includes(fileObj.language)
        ? mergeFindings(astFindings, regexFindings)
        : fileValid;

      allValidFindings.push(...merged);
    }

    // 3. Normalize findings
    let normalizedFindings = FindingNormalizer.normalize(allValidFindings, targetPath);

    // 4. Optional AI Enrichment
    if (mergedConfig.ai && this.aiService && normalizedFindings.length > 0) {
      try {
        logger.debug(`Enriching ${normalizedFindings.length} finding(s) with AI explanations...`);
        normalizedFindings = await this.aiService.enrichVulnerabilities(
          normalizedFindings,
          sourceFiles.length > 0 ? sourceFiles[0].code : '',
          sourceFiles.length > 0 ? sourceFiles[0].language : 'javascript'
        );
      } catch (aiErr) {
        logger.debug(`AI enrichment failed during repository scan: ${aiErr.message}`);
      }
    }

    const durationMs = Date.now() - startTime;
    const gitContext = GitHelper.getGitContext(targetPath);

    const aggregation = RiskAggregator.aggregate(
      normalizedFindings,
      durationMs,
      sourceFiles.length,
      parserErrorMarkers.length,
      languageCounts
    );

    return {
      schemaVersion: '1.0',
      scanner: {
        name: 'NoVuln',
        edition: 'Enterprise AI SAST Platform',
        version: '2.0.0'
      },
      git: gitContext,
      scan: {
        timestamp: new Date().toISOString(),
        durationMs,
        filesScanned: sourceFiles.length,
        targetPath
      },
      summary: aggregation.summary,
      findings: normalizedFindings,
      parserErrorDetails: parserErrorMarkers,
      owaspMapping: aggregation.owaspMapping,
      cweMapping: aggregation.cweMapping
    };
  }

  getDetectors() {
    return this.pluginManager.getRegisteredPlugins();
  }

  getSupportedLanguages() {
    return [
      'javascript',
      'typescript',
      'python',
      'java',
      'csharp',
      'ruby',
      'go',
      'php'
    ];
  }
}

module.exports = ScannerEngine;
