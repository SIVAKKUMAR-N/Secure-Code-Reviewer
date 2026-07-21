const StorageAdapter = require('./StorageAdapter');
const Scan = require('../models/Scan');
const logger = require('../utils/logger');

/**
 * MongoStorage
 * MongoDB persistence adapter wrapping Scan Mongoose model with in-memory caching fallback.
 */
class MongoStorage extends StorageAdapter {
  async save(scanData) {
    const vulnerabilities = scanData.findings || scanData.vulnerabilities || [];
    const scanDocument = new Scan({
      code: scanData.code || '',
      language: scanData.language || 'multi-file',
      scanDuration: scanData.scanDuration || (scanData.scan ? scanData.scan.durationMs : 0),
      vulnerabilities,
      aiProvider: scanData.aiProvider || 'none',
      summary: scanData.summary || {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
        high: vulnerabilities.filter(v => v.severity === 'High').length,
        medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
        low: vulnerabilities.filter(v => v.severity === 'Low').length
      }
    });

    scanDocument.createdAt = new Date();
    scanDocument.updatedAt = new Date();

    // Cache in memory
    Scan.saveInMemory(scanDocument);

    try {
      await scanDocument.save();
      logger.info(`Scan saved to MongoDB with ID: ${scanDocument._id}`);
    } catch (err) {
      logger.warn(`Failed to save scan to database: ${err.message}`);
    }

    return scanDocument;
  }

  async findById(id) {
    let scan = null;
    try {
      scan = await Scan.findById(id);
    } catch (err) {
      logger.warn(`Failed to retrieve scan from DB: ${err.message}`);
    }

    if (!scan) {
      scan = Scan.findInMemory(id);
    }
    return scan;
  }

  async getRecent(limit = 10) {
    try {
      return await Scan.getRecentScans(limit);
    } catch (err) {
      logger.warn(`Failed to retrieve recent scans from DB: ${err.message}`);
      return Scan.getRecentFromMemory(limit);
    }
  }
}

module.exports = MongoStorage;
