/**
 * AI Service Configuration
 * Manages API keys and provider selection for Gemini and OpenAI
 */

const config = {
  // AI Provider selection: 'gemini' or 'openai'
  provider: process.env.AI_PROVIDER || 'gemini',

  // Gemini Configuration
  gemini: {
    apiKey: process.env.GEMINI_API_KEY,
    model: 'gemini-2.5-flash', // Fast and cost-effective
    temperature: 0.3, // Lower temperature for more consistent security analysis
    maxOutputTokens: 2048,
  },

  // OpenAI Configuration
  openai: {
    apiKey: process.env.OPENAI_API_KEY,
    model: 'gpt-4-turbo-preview', // or 'gpt-3.5-turbo' for cost savings
    temperature: 0.3,
    maxTokens: 2048,
  },

  // Rate limiting for AI calls
  rateLimit: {
    maxRequestsPerMinute: 20,
    retryAttempts: 3,
    retryDelay: 1000, // milliseconds
  },

  // Timeout settings
  timeout: 30000, // 30 seconds
};

/**
 * Validates AI configuration
 * @returns {boolean} True if config is valid
 */
const validateConfig = () => {
  const provider = config.provider;

  if (!['gemini', 'openai'].includes(provider)) {
    throw new Error(`Invalid AI provider: ${provider}. Must be 'gemini' or 'openai'`);
  }

  if (provider === 'gemini' && !config.gemini.apiKey) {
    throw new Error('GEMINI_API_KEY is required when using Gemini provider');
  }

  if (provider === 'openai' && !config.openai.apiKey) {
    throw new Error('OPENAI_API_KEY is required when using OpenAI provider');
  }

  return true;
};

module.exports = {
  config,
  validateConfig,
};