const { GoogleGenerativeAI } = require('@google/generative-ai');
const { config } = require('../../config/ai.config');
const logger = require('../../utils/logger');

/**
 * Gemini AI Service
 * Integration with Google's Gemini API for vulnerability analysis
 */

class GeminiService {
  constructor() {
    if (!config.gemini.apiKey) {
      throw new Error('Gemini API key not configured');
    }

    this.genAI = new GoogleGenerativeAI(config.gemini.apiKey);
    this.model = this.genAI.getGenerativeModel({ 
      model: config.gemini.model 
    });

    logger.info('Gemini AI service initialized');
  }

  /**
   * Generate AI response for a prompt
   * @param {string} prompt - Input prompt
   * @param {Object} options - Generation options
   * @returns {Promise<string>} AI-generated response
   */
  async generate(prompt, options = {}) {
    try {
      const generationConfig = {
        temperature: options.temperature || config.gemini.temperature,
        maxOutputTokens: options.maxTokens || config.gemini.maxOutputTokens,
      };

      const result = await this.model.generateContent({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig,
      });

      const response = result.response;
      const text = response.text();

      if (!text) {
        throw new Error('Empty response from Gemini');
      }

      return text.trim();

    } catch (error) {
      logger.error(`Gemini API error: ${error.message}`);
      
      // Handle specific error cases
      if (error.message.includes('API key')) {
        throw new Error('Invalid Gemini API key');
      }
      
      if (error.message.includes('quota')) {
        throw new Error('Gemini API quota exceeded');
      }

      if (error.message.includes('SAFETY')) {
        logger.warn('Gemini safety filter triggered');
        return 'Unable to generate content due to safety filters.';
      }

      throw new Error(`Gemini generation failed: ${error.message}`);
    }
  }

  /**
   * Generate JSON response (parse Gemini output as JSON)
   * @param {string} prompt - Input prompt
   * @returns {Promise<Object>} Parsed JSON response
   */
  async generateJSON(prompt) {
    try {
      const text = await this.generate(prompt);
      
      // Try to extract JSON from markdown code blocks
      let jsonText = text;
      const jsonMatch = text.match(/```json\n?([\s\S]*?)\n?```/);
      if (jsonMatch) {
        jsonText = jsonMatch[1];
      }

      // Parse JSON
      const parsed = JSON.parse(jsonText.trim());
      return parsed;

    } catch (error) {
      if (error instanceof SyntaxError) {
        logger.error('Failed to parse Gemini JSON response');
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
      logger.error(`Gemini availability check failed: ${error.message}`);
      return false;
    }
  }
}

module.exports = GeminiService;
