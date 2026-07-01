const express = require('express');
const router = express.Router();
const {
  scanCode,
  getScan,
  getRecentScans,
  getStatistics,
  getDetectors,
} = require('../controllers/scanController');
const {
  scanValidationRules,
  validate,
  sanitizeInput,
} = require('../middleware/validator');
const { scanLimiter } = require('../middleware/rateLimiter');

/**
 * Scan Routes
 * All routes are prefixed with /api/scan
 */

/**
 * @route   POST /api/scan
 * @desc    Scan code for vulnerabilities
 * @access  Public
 */
router.post(
  '/',
  scanLimiter,
  scanValidationRules(),
  validate,
  sanitizeInput,
  scanCode
);

/**
 * @route   GET /api/scan/:id
 * @desc    Get specific scan result
 * @access  Public
 */
router.get('/:id', getScan);

/**
 * @route   GET /api/scan/recent
 * @desc    Get recent scans
 * @access  Public
 */
router.get('/list/recent', getRecentScans);

/**
 * @route   GET /api/scan/stats
 * @desc    Get overall statistics
 * @access  Public
 */
router.get('/list/stats', getStatistics);

/**
 * @route   GET /api/scan/detectors
 * @desc    Get list of available detectors
 * @access  Public
 */
router.get('/info/detectors', getDetectors);

module.exports = router;