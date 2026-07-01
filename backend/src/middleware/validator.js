const { body, validationResult } = require('express-validator');
const appConfig = require('../config/app.config');

/**
 * Input Validation Middleware
 * Validates and sanitizes user input to prevent injection attacks
 */

/**
 * Validation rules for code scan request
 */
const scanValidationRules = () => {
  return [
    // Code validation
    body('code')
      .notEmpty()
      .withMessage('Code is required')
      .isString()
      .withMessage('Code must be a string')
      .isLength({ max: appConfig.codeLimits.maxCodeLength })
      .withMessage(`Code must not exceed ${appConfig.codeLimits.maxCodeLength} characters`)
      .trim()
      .customSanitizer((value) => {
        // Count lines
        const lineCount = value.split('\n').length;
        if (lineCount > appConfig.codeLimits.maxLineCount) {
          throw new Error(`Code must not exceed ${appConfig.codeLimits.maxLineCount} lines`);
        }
        return value;
      }),

    // Language validation
    body('language')
      .notEmpty()
      .withMessage('Language is required')
      .isString()
      .withMessage('Language must be a string')
      .toLowerCase()
      .isIn(appConfig.codeLimits.supportedLanguages)
      .withMessage(`Language must be one of: ${appConfig.codeLimits.supportedLanguages.join(', ')}`),
  ];
};

/**
 * Middleware to check validation results
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }
  
  next();
};

/**
 * Security sanitization middleware
 * Additional layer of protection against common attacks
 */
const sanitizeInput = (req, res, next) => {
  // Remove null bytes (used in path traversal attacks)
  if (req.body.code) {
    req.body.code = req.body.code.replace(/\0/g, '');
  }

  // Normalize language to lowercase
  if (req.body.language) {
    req.body.language = req.body.language.toLowerCase().trim();
  }

  next();
};

module.exports = {
  scanValidationRules,
  validate,
  sanitizeInput,
};