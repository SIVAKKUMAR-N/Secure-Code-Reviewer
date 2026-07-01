/**
 * Regex Heuristic Scanner
 * Orchestrates regex-based pattern matching detectors for vulnerability scanning.
 * 
 * Educational Context:
 * - Why regex scanning is essential:
 *   - Rapidly checks for signature patterns like hardcoded API keys, certificates, 
 *     short tokens, and weak cryptographic configurations.
 *   - Works out-of-the-box across all programming languages, serving as a language-agnostic
 *     security baseline.
 *   - Fast execution speed makes it great for immediate feedback during development.
 */

const SQLInjectionDetector = require('./detectors/sqlInjection');
const XSSDetector = require('./detectors/xss');
const SecretsDetector = require('./detectors/secrets');
const WeakHashingDetector = require('./detectors/weakHashing');
const JWTIssuesDetector = require('./detectors/jwtIssues');
const CommandInjectionDetector = require('./detectors/commandInjection');
const FileUploadDetector = require('./detectors/fileUpload');
const InputValidationDetector = require('./detectors/inputValidation');
const PathTraversalDetector = require('./detectors/pathTraversal');
const UnsafeDeserializationDetector = require('./detectors/unsafeDeserialization');
const ReDoSDetector = require('./detectors/redos');
const SSRFDetector = require('./detectors/ssrf');
const InsecureRandomnessDetector = require('./detectors/insecureRandomness');
const DangerousEvalDetector = require('./detectors/dangerousEval');
const logger = require('../../../utils/logger');

class RegexScanner {
  constructor() {
    // Instantiate all 14 regex-based detectors
    this.detectors = [
      new SQLInjectionDetector(),
      new XSSDetector(),
      new SecretsDetector(),
      new WeakHashingDetector(),
      new JWTIssuesDetector(),
      new CommandInjectionDetector(),
      new FileUploadDetector(),
      new InputValidationDetector(),
      new PathTraversalDetector(),
      new UnsafeDeserializationDetector(),
      new ReDoSDetector(),
      new SSRFDetector(),
      new InsecureRandomnessDetector(),
      new DangerousEvalDetector(),
    ];
    
    logger.debug(`RegexScanner initialized with ${this.detectors.length} detectors`);
  }

  /**
   * Run all regex detectors on the source code in parallel
   * @param {string} code - Source code text
   * @param {string} language - Target language string (e.g. javascript, python)
   * @returns {Promise<Array>} Combined array of findings
   */
  async scan(code, language) {
    const detectionPromises = this.detectors.map(async (detector) => {
      try {
        const findings = detector.detect(code, language);
        if (findings.length > 0) {
          logger.debug(`Regex Detector ${detector.name} found ${findings.length} issue(s)`);
        }
        return findings;
      } catch (error) {
        logger.error(`Regex Detector ${detector.name} failed: ${error.message}`);
        return []; // Do not fail the whole scan if one detector encounters issues
      }
    });

    const results = await Promise.all(detectionPromises);
    return results.flat();
  }
}

module.exports = RegexScanner;
