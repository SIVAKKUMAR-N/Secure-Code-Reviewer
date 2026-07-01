/**
 * Application Configuration
 * Central configuration for app-wide settings
 */

module.exports = {
  // Server settings
  port: process.env.PORT || 5000,
  env: process.env.NODE_ENV || 'development',
  
  // CORS settings
  cors: {
    origins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  },

  // Rate limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000, // 1 minute
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 10,
    message: 'Too many requests from this IP, please try again later.',
  },

  // Code submission limits
  codeLimits: {
    maxCodeLength: 50000, // 50KB of code
    maxLineCount: 2000,
    supportedLanguages: [
      'javascript',
      'typescript',
      'python',
      'java',
      'php',
      'csharp',
      'ruby',
      'go',
    ],
  },

  // Vulnerability severity levels
  severityLevels: {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFO: 'Info',
  },

  // OWASP Top 10 2021 mapping
  owaspCategories: {
    A01_BROKEN_ACCESS_CONTROL: 'A01:2021 - Broken Access Control',
    A02_CRYPTOGRAPHIC_FAILURES: 'A02:2021 - Cryptographic Failures',
    A03_INJECTION: 'A03:2021 - Injection',
    A04_INSECURE_DESIGN: 'A04:2021 - Insecure Design',
    A05_SECURITY_MISCONFIGURATION: 'A05:2021 - Security Misconfiguration',
    A06_VULNERABLE_COMPONENTS: 'A06:2021 - Vulnerable and Outdated Components',
    A07_IDENTIFICATION_FAILURES: 'A07:2021 - Identification and Authentication Failures',
    A08_DATA_INTEGRITY_FAILURES: 'A08:2021 - Software and Data Integrity Failures',
    A09_LOGGING_FAILURES: 'A09:2021 - Security Logging and Monitoring Failures',
    A10_SSRF: 'A10:2021 - Server-Side Request Forgery',
  },

  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.NODE_ENV === 'production' ? 'json' : 'simple',
  },
};