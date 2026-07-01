const { getCalleeName, isDynamic, isStaticLiteral, isUserControlled, isSanitized } = require('../utils/nodeHelpers');
const { buildFinding } = require('../utils/findingBuilder');

/**
 * Command Injection AST Detector
 * Checks for child_process calls executing dynamic arguments.
 */
module.exports = {
  visitor(findings, codeLines) {
    return {
      CallExpression(path) {
        const calleeName = getCalleeName(path.node.callee);
        const shellSinks = ['exec', 'execSync'];
        const shellLessSinks = ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'spawnFile'];
        const allSinks = [...shellSinks, ...shellLessSinks];
        
        const isSink = allSinks.some(sink => 
          calleeName === sink || calleeName.endsWith(`.${sink}`)
        );

        if (isSink && path.node.arguments.length > 0) {
          const firstArg = path.node.arguments[0];
          const isShell = shellSinks.some(sink => calleeName === sink || calleeName.endsWith(`.${sink}`));
          
          let shouldFlag = false;
          let hasUserControlledArgs = false;

          // Check if first arg (the command itself) is dynamic
          if (isDynamic(firstArg)) {
            shouldFlag = true;
          } else {
            // Command is static. For shell-less execution, we only flag if arguments array contains user-controlled input.
            if (!isShell && path.node.arguments.length > 1) {
              const secondArg = path.node.arguments[1];
              
              if (secondArg.type === 'ArrayExpression') {
                hasUserControlledArgs = secondArg.elements.some(el => el && isUserControlled(el));
              } else {
                // If it's an Identifier or other dynamic node, check if it's user-controlled
                hasUserControlledArgs = isUserControlled(secondArg);
              }
              
              if (hasUserControlledArgs) {
                shouldFlag = true;
              }
            }
          }

          if (shouldFlag) {
            const isFirstArgUserControlled = isUserControlled(firstArg);
            const userControlled = isFirstArgUserControlled || hasUserControlledArgs;
            const sanitized = isSanitized(firstArg) || (path.node.arguments[1] && isSanitized(path.node.arguments[1]));

            let confidence = 0.6; // Medium
            let severity = 'Critical';
            let reason = 'Dynamic command string passed to process execution sink';

            if (userControlled && !sanitized) {
              confidence = 1.0; // High
              severity = 'Critical';
              reason = 'Dynamic user-controlled input passed directly to process execution sink';
            } else if (sanitized) {
              confidence = 0.2; // Low
              severity = 'Medium';
              reason = 'Dynamic process execution containing sanitized input';
            }

            findings.push(buildFinding({
              id: 'JS-CMD-101',
              type: 'Command Injection',
              severity,
              confidence,
              message: `AST-Command Injection: ${reason} (${calleeName})`,
              recommendation: 'Avoid dynamic execution of shell commands. Use child_process.execFile or execute commands with static, hardcoded arguments to prevent shell expansion.',
              cweId: 'CWE-78',
              owaspCategory: 'A03:2021 - Injection',
              node: path.node,
              codeLines,
              sink: calleeName,
              reason
            }));
          }
        }
      }
    };
  }
};
