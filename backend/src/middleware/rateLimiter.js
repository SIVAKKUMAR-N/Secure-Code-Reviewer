const rateLimit = require('express-rate-limit');
const appConfig = require('../config/app.config');
const logger = require('../utils/logger');

/**
 * Rate Limiting Middleware
 * Prevents abuse and DOS attacks by limiting requests per IP
 */

/**
 * General API rate limiter
 * Applies to all API routes
 */
const apiLimiter = rateLimit({
  windowMs: appConfig.rateLimit.windowMs,
  max: appConfig.rateLimit.max,
  message: {
    success: false,
    error: appConfig.rateLimit.message,
  },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  
  // Custom handler for rate limit exceeded
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later.',
      retryAfter: Math.ceil(appConfig.rateLimit.windowMs / 1000), // seconds
    });
  },

  // Skip rate limiting for certain IPs (optional)
  skip: (req) => {
    // Example: Skip for localhost in development
    if (appConfig.env === 'development' && req.ip === '::1') {
      return true;
    }
    return false;
  },
});

/**
 * Stricter rate limiter for scan endpoint
 * Scans are resource-intensive, so limit them more aggressively
 */
const scanLimiter = rateLimit({
  windowMs: 60000, // 1 minute
  max: 5, // 5 requests per minute
  message: {
    success: false,
    error: 'Too many scan requests. Please wait before scanning again.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  handler: (req, res) => {
    logger.warn(`Scan rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      error: 'Too many scan requests. Please wait 1 minute before trying again.',
      retryAfter: 60,
    });
  },

  // Track by IP and potentially by user ID in the future
  keyGenerator: (req) => {
    return req.userId || req.ip;
  },
});

module.exports = {
  apiLimiter,
  scanLimiter,
};