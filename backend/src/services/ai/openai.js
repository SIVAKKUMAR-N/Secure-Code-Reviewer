const OpenAI = require('openai');
const { config } = require('../../config/ai.config');
const logger = require('../../utils/logger');

/**
 * OpenAI Service
 * Integration with OpenAI GPT API for vulnerability analysis
 */

class OpenAIService {
  constructor() {
    if (!config.openai.apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    this.openai = new OpenAI({
      apiKey: config.openai.apiKey,
    });

    this.model = config.openai.model;

    logger.info('OpenAI service initialized');
  }

  /**
   * Generate AI response for a prompt
   * @param {string} prompt - Input prompt
   * @param {Object} options - Generation options
   * @returns {Promise<string>} AI-generated response
   */
  async generate(prompt, options = {}) {
    try {
      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are a senior application security engineer specializing in secure code review and vulnerability analysis.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: options.temperature || config.openai.temperature,
        max_tokens: options.maxTokens || config.openai.maxTokens,
      });

      const response = completion.choices[0]?.message?.content;

      if (!response) {
        throw new Error('Empty response from OpenAI');
      }

      return response.trim();

    } catch (error) {
      logger.error(`OpenAI API error: ${error.message}`);

      // Handle specific error cases
      if (error.code === 'invalid_api_key') {
        throw new Error('Invalid OpenAI API key');
      }

      if (error.code === 'insufficient_quota') {
        throw new Error('OpenAI API quota exceeded');
      }

      if (error.code === 'rate_limit_exceeded') {
        throw new Error('OpenAI rate limit exceeded. Please try again later.');
      }

      throw new Error(`OpenAI generation failed: ${error.message}`);
    }
  }

  /**
   * Generate JSON response
   * @param {string} prompt - Input prompt
   * @returns {Promise<Object>} Parsed JSON response
   */
  async generateJSON(prompt) {
    try {
      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are a security expert. Always respond with valid JSON only.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: config.openai.temperature,
        max_tokens: config.openai.maxTokens,
        response_format: { type: 'json_object' }, // Force JSON response
      });

      const response = completion.choices[0]?.message?.content;

      if (!response) {
        throw new Error('Empty response from OpenAI');
      }

      // Parse JSON
      const parsed = JSON.parse(response.trim());
      return parsed;

    } catch (error) {
      if (error instanceof SyntaxError) {
        logger.error('Failed to parse OpenAI JSON response');
        throw new Error('Invalid JSON response from AI');
      }
      throw error;
    }
  }

  /**
   * Check if service is available
   * @returns {Promise<boolean>} True if available
   */
  async isAvailable() {
    try {
      await this.generate('Test', { maxTokens: 10 });
      return true;
    } catch (error) {
      logger.error(`OpenAI availability check failed: ${error.message}`);
      return false;
    }
  }
}

module.exports = OpenAIService;
