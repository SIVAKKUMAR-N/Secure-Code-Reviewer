/**
 * Severity Utility
 * Handles CVSS scoring and overall risk calculations
 */

/**
 * Calculate numeric CVSS score based on qualitative severity and confidence score
 * @param {string} severity - Critical, High, Medium, Low, Info
 * @param {number} confidence - 0 to 100 confidence score
 * @returns {number} CVSS score (0.0 - 10.0)
 */
function calculateCVSS(severity, confidence = 80) {
  const normalizedSeverity = (severity || 'Medium').toLowerCase().trim();
  
  let baseScore = 5.5;
  let min = 4.0;
  let max = 6.9;

  switch (normalizedSeverity) {
    case 'critical':
      min = 9.0;
      max = 10.0;
      baseScore = 9.5;
      break;
    case 'high':
      min = 7.0;
      max = 8.9;
      baseScore = 8.0;
      break;
    case 'medium':
      min = 4.0;
      max = 6.9;
      baseScore = 5.5;
      break;
    case 'low':
      min = 1.0;
      max = 3.9;
      baseScore = 2.5;
      break;
    case 'info':
    default:
      min = 0.0;
      max = 0.9;
      baseScore = 0.5;
      break;
  }

  // Adjust CVSS slightly within its range based on confidence
  const confidenceFactor = (confidence - 80) / 100; // -0.8 to 0.2 offset relative to standard 80
  const rangeSize = max - min;
  
  let adjustedScore = baseScore + (confidenceFactor * rangeSize * 0.4);
  
  // Clamp between min and max
  adjustedScore = Math.max(min, Math.min(max, adjustedScore));
  
  // Return rounded to 1 decimal place
  return parseFloat(adjustedScore.toFixed(1));
}

/**
 * Calculate overall risk score (0-100) based on all findings
 * @param {Array} findings - Scan findings
 * @returns {number} Overall risk score
 */
function calculateRiskScore(findings) {
  if (!findings || findings.length === 0) {
    return 0;
  }

  // Weights for overall risk calculation
  const weights = {
    critical: 40,
    high: 25,
    medium: 10,
    low: 5,
    info: 1
  };

  let totalPoints = 0;
  findings.forEach(finding => {
    const sev = (finding.severity || 'Medium').toLowerCase().trim();
    totalPoints += weights[sev] || weights.medium;
  });

  // Normalize and cap at 100
  return Math.min(100, Math.round(totalPoints));
}

module.exports = {
  calculateCVSS,
  calculateRiskScore
};
