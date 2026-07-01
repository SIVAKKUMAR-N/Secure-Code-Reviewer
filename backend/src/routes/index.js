const express = require('express');
const router = express.Router();
const scanRoutes = require('./scanRoutes');
const reportRoutes = require('./reportRoutes');

/**
 * Main API Routes
 * All routes are prefixed with /api
 */

/**
 * Health check endpoint
 * Useful for monitoring and load balancers
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * API information endpoint
 */
router.get('/info', (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      name: 'Secure Code Reviewer API',
      version: '1.0.0',
      description: 'AI-powered security vulnerability scanner',
      endpoints: {
        scan: '/api/scan',
        report: '/api/report',
        health: '/api/health',
      },
    },
  });
});

// Mount route modules
router.use('/scan', scanRoutes);
router.use('/report', reportRoutes);

module.exports = router;