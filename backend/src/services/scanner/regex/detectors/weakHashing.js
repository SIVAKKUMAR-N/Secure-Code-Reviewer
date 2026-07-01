const BaseDetector = require('./BaseDetector');

class WeakHashingDetector extends BaseDetector {
  constructor() {
    super('Weak Password Hashing', 'weak_hashing', 'weakHashing');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 85;

    // Check if it's being used for password-related operations
    const passwordIndicators = ['password', 'passwd', 'pwd', 'credential', 'auth'];
    const hasPasswordContext = passwordIndicators.some(ind => 
      line.toLowerCase().includes(ind)
    );
    
    if (hasPasswordContext) {
      confidence = 95; // Very high confidence for password hashing
    } else {
      // Lower confidence if used for non-password purposes (checksums, etc.)
      confidence = 70;
    }

    // Check for secure alternatives in same line (less likely to be vulnerable)
    const secureAlternatives = ['bcrypt', 'scrypt', 'argon2', 'pbkdf2'];
    const hasSecureAlternative = secureAlternatives.some(alt => 
      line.toLowerCase().includes(alt)
    );
    
    if (hasSecureAlternative) {
      confidence -= 30;
    }

    return Math.max(50, Math.min(100, confidence));
  }
}

module.exports = WeakHashingDetector;
