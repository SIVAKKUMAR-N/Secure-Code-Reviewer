const ScannerEngine = require('../core/ScannerEngine');
const MongoStorage = require('../storage/MongoStorage');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');

/**
 * Scan Controller
 * Handles code scanning and vulnerability detection for Web API
 */

const scanner = new ScannerEngine();
const mongoStorage = new MongoStorage();

/**
 * POST /api/scan
 * Scan code snippet for security vulnerabilities
 */
const scanCode = asyncHandler(async (req, res) => {
  const { code, language } = req.body;
  
  logger.info(`Received Web API scan request for ${language} code`);

  // Run vulnerability scanner with core engine
  const scanResults = await scanner.scan(code, language);

  // Persist to MongoDB (with memory cache fallback)
  const savedDoc = await mongoStorage.save({
    code,
    language: scanResults.language,
    scanDuration: scanResults.scanDuration,
    findings: scanResults.vulnerabilities,
    summary: scanResults.summary,
    aiProvider: scanner.aiService ? scanner.aiService.getProvider() : 'none'
  });

  // Return response in format expected by React Frontend
  res.status(200).json({
    success: true,
    data: {
      scanId: savedDoc._id,
      language: savedDoc.language,
      summary: savedDoc.summary,
      vulnerabilities: scanResults.vulnerabilities,
      scanDuration: scanResults.scanDuration,
      timestamp: savedDoc.createdAt,
    },
  });
});

/**
 * GET /api/scan/:id
 * Retrieve a specific scan result by ID
 */
const getScan = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const scan = await mongoStorage.findById(id);

  if (!scan) {
    return res.status(404).json({
      success: false,
      error: 'Scan not found',
    });
  }

  res.status(200).json({
    success: true,
    data: {
      scanId: scan._id,
      language: scan.language,
      summary: scan.summary,
      vulnerabilities: scan.vulnerabilities,
      scanDuration: scan.scanDuration,
      timestamp: scan.createdAt,
    },
  });
});

/**
 * GET /api/scan/recent
 * Get recent scans
 */
const getRecentScans = asyncHandler(async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const recentScans = await mongoStorage.getRecent(limit);

  res.status(200).json({
    success: true,
    data: recentScans,
  });
});

/**
 * GET /api/scan/stats
 * Get overall statistics
 */
const getStatistics = asyncHandler(async (req, res) => {
  const recentScans = await mongoStorage.getRecent(1000);
  const totalScans = recentScans.length;
  const vulnerabilities = {
    totalVulnerabilities: 0,
    totalCritical: 0,
    totalHigh: 0,
    totalMedium: 0,
    totalLow: 0,
  };
  
  recentScans.forEach(scan => {
    const summary = scan.summary || {};
    vulnerabilities.totalVulnerabilities += summary.total || 0;
    vulnerabilities.totalCritical += summary.critical || 0;
    vulnerabilities.totalHigh += summary.high || 0;
    vulnerabilities.totalMedium += summary.medium || 0;
    vulnerabilities.totalLow += summary.low || 0;
  });

  res.status(200).json({
    success: true,
    data: {
      totalScans,
      vulnerabilities,
    },
  });
});

/**
 * GET /api/scan/detectors
 * Get list of available detectors
 */
const getDetectors = asyncHandler(async (req, res) => {
  const detectors = scanner.getDetectors();

  res.status(200).json({
    success: true,
    data: {
      detectors,
      count: detectors.length,
      supportedLanguages: scanner.getSupportedLanguages(),
    },
  });
});

module.exports = {
  scanCode,
  getScan,
  getRecentScans,
  getStatistics,
  getDetectors,
};