const express = require('express');
const router = express.Router();
const {
  generateReport,
  previewReport,
} = require('../controllers/reportController');

/**
 * Report Routes
 * All routes are prefixed with /api/report
 */

/**
 * @route   GET /api/report/:scanId
 * @desc    Generate and download PDF report
 * @access  Public
 */
router.get('/:scanId', generateReport);

/**
 * @route   GET /api/report/:scanId/preview
 * @desc    Preview PDF report inline
 * @access  Public
 */
router.get('/:scanId/preview', previewReport);

module.exports = router;