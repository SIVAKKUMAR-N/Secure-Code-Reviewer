const Scan = require('../models/Scan');
const PDFGenerator = require('../utils/pdfGenerator');
const logger = require('../utils/logger');
const { asyncHandler, AppError } = require('../middleware/errorHandler');

/**
 * Report Controller
 * Handles PDF report generation and download
 */

/**
 * GET /api/report/:scanId
 * Generate and download PDF report for a scan
 */
const generateReport = asyncHandler(async (req, res) => {
  const { scanId } = req.params;

  logger.info(`Generating PDF report for scan: ${scanId}`);

  // Fetch scan from database
  let scan = null;
  try {
    scan = await Scan.findById(scanId);
  } catch (dbError) {
    logger.warn(`Failed to retrieve scan from database for PDF: ${dbError.message}`);
  }

  // Fallback to in-memory cache
  if (!scan) {
    scan = Scan.findInMemory(scanId);
  }

  if (!scan) {
    throw new AppError('Scan not found', 404);
  }

  // Generate PDF
  const pdfBuffer = await PDFGenerator.generateReport(scan);

  // Set response headers for PDF download
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="security-report-${scanId}.pdf"`
  );
  res.setHeader('Content-Length', pdfBuffer.length);

  // Send PDF
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

  let scan = null;
  try {
    scan = await Scan.findById(scanId);
  } catch (dbError) {
    logger.warn(`Failed to retrieve scan from database for PDF preview: ${dbError.message}`);
  }

  // Fallback to in-memory cache
  if (!scan) {
    scan = Scan.findInMemory(scanId);
  }

  if (!scan) {
    throw new AppError('Scan not found', 404);
  }

  const pdfBuffer = await PDFGenerator.generateReport(scan);

  // Set headers for inline display
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Content-Length', pdfBuffer.length);

  res.send(pdfBuffer);
});

module.exports = {
  generateReport,
  previewReport,
};