const MongoStorage = require('../storage/MongoStorage');
const PDFReporter = require('../reporters/PDFReporter');
const logger = require('../utils/logger');
const { asyncHandler, AppError } = require('../middleware/errorHandler');

/**
 * Report Controller
 * Handles PDF report generation and download for Web API
 */

const mongoStorage = new MongoStorage();

/**
 * GET /api/report/:scanId
 * Generate and download PDF report for a scan
 */
const generateReport = asyncHandler(async (req, res) => {
  const { scanId } = req.params;

  logger.info(`Generating PDF report for scan: ${scanId}`);

  const scan = await mongoStorage.findById(scanId);
  if (!scan) {
    throw new AppError('Scan not found', 404);
  }

  const pdfBuffer = await PDFReporter.generateBuffer(scan);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="security-report-${scanId}.pdf"`
  );
  res.setHeader('Content-Length', pdfBuffer.length);

  res.send(pdfBuffer);
  logger.info(`PDF report generated successfully for scan: ${scanId}`);
});

/**
 * GET /api/report/:scanId/preview
 * Generate PDF report for preview (inline display)
 */
const previewReport = asyncHandler(async (req, res) => {
  const { scanId } = req.params;

  logger.info(`Generating PDF preview for scan: ${scanId}`);

  const scan = await mongoStorage.findById(scanId);
  if (!scan) {
    throw new AppError('Scan not found', 404);
  }

  const pdfBuffer = await PDFReporter.generateBuffer(scan);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Content-Length', pdfBuffer.length);

  res.send(pdfBuffer);
});

module.exports = {
  generateReport,
  previewReport,
};