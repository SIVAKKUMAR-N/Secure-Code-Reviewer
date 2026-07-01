const GeminiService = require('./gemini');
const OpenAIService = require('./openai');
const { config, validateConfig } = require('../../config/ai.config');
const prompts = require('./prompts');
const logger = require('../../utils/logger');

/**
 * AI Service
 * Provider-agnostic interface for AI-powered vulnerability analysis
 * Supports Gemini and OpenAI with automatic fallback
 */

class AIService {
  constructor() {
    // Validate configuration
    validateConfig();

    // Initialize the selected provider
    this.provider = config.provider;
    
    try {
      if (this.provider === 'gemini') {
        this.ai = new GeminiService();
      } else if (this.provider === 'openai') {
        this.ai = new OpenAIService();
      } else {
        throw new Error(`Unknown AI provider: ${this.provider}`);
      }

      logger.info(`AI Service initialized with ${this.provider} provider`);
    } catch (error) {
      logger.error(`Failed to initialize AI service: ${error.message}`);
      throw error;
    }
  }

  /**
   * Enrich a vulnerability with AI-generated content
   * @param {Object} vulnerability - Vulnerability finding from scanner
   * @param {string} codeSnippet - Relevant code snippet
   * @param {string} language - Programming language
   * @returns {Promise<Object>} Enriched vulnerability object
   */
  async enrichVulnerability(vulnerability, codeSnippet, language) {
    try {
      logger.debug(`Enriching ${vulnerability.type} vulnerability with AI`);

      // Generate comprehensive analysis using a single AI call (more efficient)
      const prompt = prompts.getComprehensivePrompt(vulnerability, codeSnippet, language);
      
      let analysis;
      try {
        if (this.provider === 'gemini') {
          // For Gemini, call generate directly and use our robust parser to avoid double API calls on JSON errors
          const textResponse = await this.ai.generate(prompt);
          analysis = this._parseTextResponse(textResponse);
        } else {
          // For OpenAI, use native JSON mode
          analysis = await this.ai.generateJSON(prompt);
        }
      } catch (jsonError) {
        logger.warn(`AI analysis generation failed: ${jsonError.message}. Retrying with generate and robust parsing...`);
        const textResponse = await this.ai.generate(prompt);
        analysis = this._parseTextResponse(textResponse);
      }

      // Validate and extract fields
      const enriched = {
        ...vulnerability,
        aiExplanation: analysis.explanation || 'AI analysis unavailable',
        secureFix: analysis.secureFix || 'No fix suggestion available',
        attackExample: analysis.attackExample || 'No attack example available',
        owaspCategory: analysis.owaspCategory || vulnerability.owaspCategory || 'Not mapped',
        recommendations: analysis.recommendations || [],
      };

      logger.debug(`Successfully enriched vulnerability with AI`);
      return enriched;

    } catch (error) {
      logger.error(`Failed to enrich vulnerability: ${error.message}`);
      
      // Return vulnerability without AI enrichment rather than failing
      return {
        ...vulnerability,
        aiExplanation: 'AI analysis temporarily unavailable',
        secureFix: vulnerability.recommendation || 'Unable to generate fix suggestion',
        attackExample: 'Unable to generate attack example',
        owaspCategory: vulnerability.owaspCategory || 'Not mapped',
        recommendations: [vulnerability.recommendation].filter(Boolean),
      };
    }
  }

  /**
   * Enrich multiple vulnerabilities in batch
   * @param {Array} vulnerabilities - Array of vulnerability findings
   * @param {string} fullCode - Complete source code
   * @param {string} language - Programming language
   * @returns {Promise<Array>} Array of enriched vulnerabilities
   */
  async enrichVulnerabilities(vulnerabilities, fullCode, language) {
    logger.info(`Enriching ${vulnerabilities.length} vulnerabilities with AI`);

    const enriched = [];

    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      const snippet = this._extractCodeSnippet(fullCode, vuln.line, 3);
      
      try {
        const result = await this.enrichVulnerability(vuln, snippet, language);
        enriched.push(result);
      } catch (err) {
        logger.error(`Failed to enrich vulnerability index ${i}: ${err.message}`);
        // Fallback
        enriched.push({
          ...vuln,
          aiExplanation: 'AI analysis temporarily unavailable',
          secureFix: vuln.recommendation || 'Unable to generate fix suggestion',
          attackExample: 'Unable to generate attack example',
          owaspCategory: vuln.owaspCategory || 'Not mapped',
          recommendations: [vuln.recommendation].filter(Boolean),
        });
      }

      // Small delay between sequential requests to respect rate limits
      if (i < vulnerabilities.length - 1) {
        await this._delay(800);
      }
    }

    logger.info(`Successfully enriched ${enriched.length} vulnerabilities`);
    return enriched;
  }

  /**
   * Extract code snippet around a specific line
   * @param {string} code - Full source code
   * @param {number} lineNumber - Target line number
   * @param {number} contextLines - Number of lines before/after
   * @returns {string} Code snippet
   */
  _extractCodeSnippet(code, lineNumber, contextLines = 2) {
    const lines = code.split('\n');
    const startLine = Math.max(0, lineNumber - contextLines - 1);
    const endLine = Math.min(lines.length, lineNumber + contextLines);
    
    return lines.slice(startLine, endLine).join('\n');
  }

  /**
   * Parse text response when JSON parsing fails
   * @param {string} text - AI response text
   * @returns {Object} Parsed response object
   */
  /**
 * Parse text response safely when JSON parsing fails
 * @param {string} text - AI response text
 * @returns {Object} Parsed response object
 */
  _parseTextResponse(text) {
    let cleanText = text.trim();
    
    // Strip markdown code blocks
    const tripleBacktick = '`' + '`' + '`';
    if (cleanText.startsWith(tripleBacktick)) {
      const firstNewline = cleanText.indexOf('\n');
      const lastBackticks = cleanText.lastIndexOf(tripleBacktick);
      if (firstNewline !== -1 && lastBackticks !== -1 && lastBackticks > firstNewline) {
        cleanText = cleanText.substring(firstNewline + 1, lastBackticks).trim();
      }
    }

    // First try parsing as JSON
    try {
      const parsed = JSON.parse(cleanText);
      return {
        explanation: parsed.explanation || '',
        secureFix: parsed.secureFix || '',
        attackExample: parsed.attackExample || '',
        owaspCategory: parsed.owaspCategory || 'Not mapped',
        recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
      };
    } catch (error) {
      logger.warn('Direct JSON.parse failed, running robust regex extraction fallback');
    }

    const result = {
      explanation: '',
      secureFix: '',
      attackExample: '',
      owaspCategory: 'Not mapped',
      recommendations: []
    };

    const extractField = (key, nextKeyPattern) => {
      const keyPattern = new RegExp('"' + key + '"\\s*:\\s*"', 'i');
      const keyMatch = cleanText.match(keyPattern);
      if (!keyMatch) return '';
      
      const keyIndex = cleanText.search(keyPattern);
      const valStart = keyIndex + keyMatch[0].length;
      
      let valEnd = -1;
      if (nextKeyPattern) {
        const nextKeyIndex = cleanText.search(nextKeyPattern);
        if (nextKeyIndex !== -1 && nextKeyIndex > valStart) {
          valEnd = cleanText.lastIndexOf('"', nextKeyIndex);
        }
      }
      
      if (valEnd === -1 || valEnd <= valStart) {
        valEnd = cleanText.lastIndexOf('"');
      }
      
      if (valEnd > valStart) {
        let val = cleanText.substring(valStart, valEnd).trim();
        
        if (val.endsWith(',')) {
          val = val.substring(0, val.length - 1).trim();
        }
        if (val.endsWith('"')) {
          val = val.substring(0, val.length - 1).trim();
        }
        
        try {
          return JSON.parse('"' + val + '"');
        } catch (parseErr) {
          return val
            .replace(/\\n/g, '\n')
            .replace(/\\"/g, '"')
            .replace(/\\'/g, "'")
            .replace(/\\\\/g, '\\');
        }
      }
      
      return '';
    };

    result.explanation = extractField('explanation', /"secureFix"\s*:/i);
    result.secureFix = extractField('secureFix', /"attackExample"\s*:/i);
    result.attackExample = extractField('attackExample', /"owaspCategory"\s*:/i);
    result.owaspCategory = extractField('owaspCategory', /"recommendations"\s*:/i);

    // Extract recommendations array
    const recMatch = cleanText.match(/"recommendations"\s*:\s*\[([\s\S]*?)\]/i);
    if (recMatch) {
      const arrContent = recMatch[1];
      const items = [];
      const itemRegex = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
      let match;
      while ((match = itemRegex.exec(arrContent)) !== null) {
        let item = match[1];
        try {
          item = JSON.parse('"' + item + '"');
        } catch (e) {
          item = item.replace(/\\"/g, '"').replace(/\\n/g, '\n');
        }
        items.push(item);
      }
      result.recommendations = items;
    }

    return result;
  }

  /**
   * Extract a section from text response
   * @param {string} text - Response text
   * @param {string} section - Section name
   * @returns {string} Extracted section
   */

  /**
   * Delay helper for rate limiting
   * @param {number} ms - Milliseconds to delay
   * @returns {Promise} Promise that resolves after delay
   */
  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Check if AI service is available
   * @returns {Promise<boolean>} True if available
   */
  async isAvailable() {
    try {
      return await this.ai.isAvailable();
    } catch (error) {
      logger.error(`AI availability check failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Get current provider name
   * @returns {string} Provider name
   */
  getProvider() {
    return this.provider;
  }
}

module.exports = AIService;
 