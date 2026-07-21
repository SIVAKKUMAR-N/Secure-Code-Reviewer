/**
 * FindingNormalizer
 * Normalizes raw plugin findings from various sources (AST, Regex, external tools)
 * into a single unified enterprise schema format.
 */
class FindingNormalizer {
  static SEVERITY_MAP = {
    'CRITICAL': 'Critical',
    'HIGH': 'High',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
    'INFO': 'Info',
    'ERROR': 'High',
    'WARNING': 'Medium',
    'NOTE': 'Low',
    '1': 'Critical',
    '2': 'High',
    '3': 'Medium',
    '4': 'Low'
  };

  /**
   * Normalizes a list of raw finding objects
   * @param {Array<Object>} rawFindings - Raw finding objects from plugins
   * @param {string} [defaultFilePath] - Optional default file path
   * @returns {Array<Object>} Normalized findings
   */
  static normalize(rawFindings = [], defaultFilePath = 'snippet.js') {
    return rawFindings.map(raw => FindingNormalizer.normalizeSingle(raw, defaultFilePath));
  }

  /**
   * Normalizes a single finding object
   * @param {Object} raw - Raw finding object
   * @param {string} defaultFilePath - Default relative file path
   * @returns {Object} Normalized finding object
   */
  static normalizeSingle(raw, defaultFilePath = 'snippet.js') {
    // 1. Normalize severity
    let severity = 'Medium';
    if (raw.severity) {
      const upper = String(raw.severity).toUpperCase().trim();
      severity = FindingNormalizer.SEVERITY_MAP[upper] || FindingNormalizer.capitalize(raw.severity);
    }

    // 2. Normalize confidence (numeric 0.0 to 1.0)
    let confidence = 0.6;
    if (typeof raw.confidence === 'number') {
      confidence = Math.max(0.0, Math.min(1.0, raw.confidence));
    } else if (raw.confidence) {
      const confStr = String(raw.confidence).toLowerCase();
      if (confStr === 'high') confidence = 1.0;
      else if (confStr === 'medium') confidence = 0.6;
      else if (confStr === 'low') confidence = 0.3;
    }

    // 3. Normalize CVSS score
    let cvssScore = raw.cvssScore;
    if (typeof cvssScore !== 'number') {
      cvssScore = FindingNormalizer.estimateCvss(severity, confidence);
    }

    // 4. Construct normalized object
    return {
      id: raw.id || `VULN-${Math.floor(Math.random() * 10000)}`,
      type: raw.type || 'Security Vulnerability',
      severity,
      confidence,
      cvssScore,
      cweId: raw.cweId || 'CWE-20',
      owaspCategory: raw.owaspCategory || 'A03:2021 - Injection',
      filePath: raw.filePath || raw.file || defaultFilePath,
      line: parseInt(raw.line, 10) || 1,
      message: raw.message || raw.description || `${raw.type || 'Vulnerability'} detected`,
      codeSnippet: raw.codeSnippet || raw.snippet || '',
      sink: raw.sink || '',
      reason: raw.reason || raw.message || '',
      source: raw.source || 'scanner',
      recommendation: raw.recommendation || 'Validate and sanitize inputs.',
      aiExplanation: raw.aiExplanation || null,
      secureFix: raw.secureFix || null,
      attackExample: raw.attackExample || null,
      recommendations: raw.recommendations || [raw.recommendation].filter(Boolean)
    };
  }

  static capitalize(str) {
    if (!str) return 'Medium';
    const lower = String(str).toLowerCase();
    return lower.charAt(0).toUpperCase() + lower.slice(1);
  }

  static estimateCvss(severity, confidence) {
    const baseMap = {
      'Critical': 9.5,
      'High': 8.0,
      'Medium': 5.5,
      'Low': 3.0,
      'Info': 1.0
    };
    const base = baseMap[severity] || 5.0;
    return parseFloat((base * (0.8 + confidence * 0.2)).toFixed(1));
  }
}

module.exports = FindingNormalizer;
