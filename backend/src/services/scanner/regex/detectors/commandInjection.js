const BaseDetector = require('./BaseDetector');

class CommandInjectionDetector extends BaseDetector {
  constructor() {
    super('Command Injection', 'command_injection', 'commandInjection');
  }

  shouldSkipLine(line, language) {
    return this.isCommentLine(line, language);
  }

  calculateConfidence(line, match, language, rule) {
    let confidence = rule.confidence || 85;

    // Check for dangerous command execution functions
    const dangerousFunctions = {
      javascript: ['exec', 'spawn', 'execSync', 'spawnSync'],
      python: ['os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'],
      php: ['exec', 'shell_exec', 'system', 'passthru', 'popen'],
    };

    const dangerous = dangerousFunctions[language] || [];
    const hasDangerous = dangerous.some(func => line.includes(func));
    
    if (hasDangerous) {
      confidence += 10;
    }

    // Check for shell-specific characters that indicate injection risk
    const shellChars = ['|', ';', '&', '>', '<', '`', '$'];
    const hasShellChars = shellChars.some(char => line.includes(char));
    
    if (hasShellChars) {
      confidence += 5;
    }

    return Math.min(100, confidence);
  }
}

module.exports = CommandInjectionDetector;