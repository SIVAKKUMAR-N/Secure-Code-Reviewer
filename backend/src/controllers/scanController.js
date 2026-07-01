const ScannerEngine = require('../services/scanner');
const AIService = require('../services/ai');
const Scan = require('../models/Scan');
const logger = require('../utils/logger');
const { asyncHandler } = require('../middleware/errorHandler');

/**
 * Scan Controller
 * Handles code scanning and vulnerability detection
 */

// Initialize services
const scanner = new ScannerEngine();
let aiService = null;

// Try to initialize AI service (may fail if no API key configured)
try {
  aiService = new AIService();
} catch (error) {
  logger.warn(`AI service not available: ${error.message}`);
}

/**
 * POST /api/scan
 * Scan code for security vulnerabilities
 */
const scanCode = asyncHandler(async (req, res) => {
  const { code, language } = req.body;
  
  logger.info(`Received scan request for ${language} code`);

  // Run vulnerability scanner
  const scanResults = await scanner.scan(code, language);

  // Enrich vulnerabilities with AI (if available)
  let enrichedVulnerabilities = scanResults.vulnerabilities;
  let aiEnriched = false;
  
  if (aiService && scanResults.vulnerabilities.length > 0) {
    try {
      logger.info('Enriching vulnerabilities with AI analysis');
      enrichedVulnerabilities = await aiService.enrichVulnerabilities(
        scanResults.vulnerabilities,
        code,
        language
      );
      aiEnriched = true;
    } catch (aiError) {
      logger.error(`AI enrichment failed: ${aiError.message}`);
      // Continue without AI enrichment
    }
  }

  if (!aiEnriched) {
    // Map static recommendations to the expected AI properties as a fallback
    enrichedVulnerabilities = enrichedVulnerabilities.map(vuln => ({
      ...vuln,
      aiExplanation: vuln.aiExplanation || 'AI analysis temporarily unavailable',
      secureFix: vuln.secureFix || vuln.recommendation || 'Unable to generate fix suggestion',
      attackExample: vuln.attackExample || 'Unable to generate attack example',
      recommendations: vuln.recommendations || [vuln.recommendation].filter(Boolean),
    }));
  }

  // Save scan results to database
  const scanDocument = new Scan({
    code,
    language,
    scanDuration: scanResults.scanDuration,
    vulnerabilities: enrichedVulnerabilities,
    aiProvider: aiService ? aiService.getProvider() : 'none',
    ipAddress: req.ip,
  });

  // Calculate summary and set timestamps manually in case DB is offline/bypassed
  scanDocument.summary = {
    total: enrichedVulnerabilities.length,
    critical: enrichedVulnerabilities.filter(v => v.severity === 'Critical').length,
    high: enrichedVulnerabilities.filter(v => v.severity === 'High').length,
    medium: enrichedVulnerabilities.filter(v => v.severity === 'Medium').length,
    low: enrichedVulnerabilities.filter(v => v.severity === 'Low').length,
    info: enrichedVulnerabilities.filter(v => v.severity === 'Info').length,
  };
  scanDocument.createdAt = new Date();
  scanDocument.updatedAt = new Date();

  // Always cache in memory
  Scan.saveInMemory(scanDocument);

  try {
    await scanDocument.save();
    logger.info(`Scan completed and saved to database with ID: ${scanDocument._id}`);
  } catch (dbError) {
    logger.warn(`Scan completed but failed to save to database: ${dbError.message}`);
  }
  
  // Return response
  res.status(200).json({
    success: true,
    data: {
      scanId: scanDocument._id,
      language: scanDocument.language,
      summary: scanDocument.summary,
      vulnerabilities: enrichedVulnerabilities,
      scanDuration: scanResults.scanDuration,
      timestamp: scanDocument.createdAt,
    },
  });
});

/**
 * GET /api/scan/:id
 * Retrieve a specific scan result by ID
 */
const getScan = asyncHandler(async (req, res) => {
  const { id } = req.params;

  let scan = null;
  try {
    scan = await Scan.findById(id);
  } catch (dbError) {
    logger.warn(`Failed to retrieve scan from database: ${dbError.message}`);
  }

  // Fallback to in-memory cache
  if (!scan) {
    scan = Scan.findInMemory(id);
  }

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
 * Get recent scans (for dashboard statistics)
 */
const getRecentScans = asyncHandler(async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;

  let recentScans = [];
  try {
    recentScans = await Scan.getRecentScans(limit);
  } catch (error) {
    logger.warn(`Failed to fetch recent scans from DB: ${error.message}`);
    recentScans = Scan.getRecentFromMemory(limit);
  }

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
  try {
    // Aggregate statistics from database
    const totalScans = await Scan.countDocuments();
    
    const pipeline = [
      {
        $group: {
          _id: null,
          totalVulnerabilities: { $sum: '$summary.total' },
          totalCritical: { $sum: '$summary.critical' },
          totalHigh: { $sum: '$summary.high' },
          totalMedium: { $sum: '$summary.medium' },
          totalLow: { $sum: '$summary.low' },
        }
      }
    ];

    const stats = await Scan.aggregate(pipeline);

    res.status(200).json({
      success: true,
      data: {
        totalScans,
        vulnerabilities: stats[0] || {
          totalVulnerabilities: 0,
          totalCritical: 0,
          totalHigh: 0,
          totalMedium: 0,
          totalLow: 0,
        },
      },
    });
  } catch (error) {
    logger.warn(`Failed to fetch statistics from DB, falling back to cache statistics: ${error.message}`);
    const cachedScans = Scan.getRecentFromMemory(1000);
    const totalScans = cachedScans.length;
    const vulnerabilities = {
      totalVulnerabilities: 0,
      totalCritical: 0,
      totalHigh: 0,
      totalMedium: 0,
      totalLow: 0,
    };
    
    cachedScans.forEach(scan => {
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
  }
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