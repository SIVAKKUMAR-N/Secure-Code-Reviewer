/**
 * AI Prompt Templates
 * Carefully crafted prompts for consistent and accurate security analysis
 */

/**
 * Generate explanation prompt for a vulnerability
 * @param {Object} vulnerability - Vulnerability finding
 * @param {string} code - Relevant code snippet
 * @returns {string} Formatted prompt
 */
const getExplanationPrompt = (vulnerability, code) => {
  return `You are a security expert analyzing a code vulnerability.

VULNERABILITY DETAILS:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- Message: ${vulnerability.message}
- Line: ${vulnerability.line}

VULNERABLE CODE:
\`\`\`
${code}
\`\`\`

Provide a clear, concise explanation of:
1. What this vulnerability is
2. Why it's dangerous (potential impact)
3. How an attacker could exploit it

Keep the response under 150 words and use simple language that a junior developer can understand.`;
};

/**
 * Generate secure fix prompt
 * @param {Object} vulnerability - Vulnerability finding
 * @param {string} code - Vulnerable code snippet
 * @param {string} language - Programming language
 * @returns {string} Formatted prompt
 */
const getSecureFixPrompt = (vulnerability, code, language) => {
  return `You are a security expert providing code fixes.

VULNERABILITY: ${vulnerability.type}
LANGUAGE: ${language}

VULNERABLE CODE:
\`\`\`${language}
${code}
\`\`\`

Provide a secure, production-ready fix for this vulnerability. Your response should:
1. Show the corrected code with proper syntax highlighting
2. Explain what changed and why it's more secure
3. Include any necessary imports or dependencies

Format your response as:
FIXED CODE:
\`\`\`${language}
[corrected code here]
\`\`\`

EXPLANATION:
[brief explanation of the fix]

Keep the entire response under 200 words.`;
};

/**
 * Generate attack example prompt
 * @param {Object} vulnerability - Vulnerability finding
 * @param {string} code - Vulnerable code snippet
 * @returns {string} Formatted prompt
 */
const getAttackExamplePrompt = (vulnerability, code) => {
  return `You are a security researcher demonstrating attack vectors.

VULNERABILITY: ${vulnerability.type}

VULNERABLE CODE:
\`\`\`
${code}
\`\`\`

Provide a realistic attack example showing how an attacker would exploit this vulnerability.
Include:
1. The malicious input/payload
2. Step-by-step attack execution
3. Expected outcome/impact

Keep it educational and under 150 words. Use markdown formatting for clarity.`;
};

/**
 * Generate OWASP mapping prompt
 * @param {Object} vulnerability - Vulnerability finding
 * @returns {string} Formatted prompt
 */
const getOwaspMappingPrompt = (vulnerability) => {
  return `Map this vulnerability to the OWASP Top 10 2021 categories.

VULNERABILITY: ${vulnerability.type}
DESCRIPTION: ${vulnerability.message}

Provide:
1. The most relevant OWASP Top 10 2021 category (e.g., "A03:2021 - Injection")
2. A one-sentence explanation of why it maps to this category

Response format:
OWASP Category: [category]
Reason: [brief explanation]`;
};

/**
 * Generate comprehensive analysis prompt (combines all)
 * @param {Object} vulnerability - Vulnerability finding
 * @param {string} code - Code snippet
 * @param {string} language - Programming language
 * @returns {string} Formatted prompt
 */
const getComprehensivePrompt = (vulnerability, code, language) => {
  return `You are a senior application security engineer analyzing code vulnerabilities.

VULNERABILITY DETAILS:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- Message: ${vulnerability.message}
- CWE ID: ${vulnerability.cweId}

VULNERABLE CODE (${language}):
\`\`\`${language}
${code}
\`\`\`

Provide a comprehensive security analysis in the following JSON format:

{
  "explanation": "Clear explanation of what this vulnerability is, why it's dangerous, and potential impact (max 150 words)",
  "secureFix": "Complete, production-ready code fix with explanation (max 200 words)",
  "attackExample": "Realistic attack demonstration showing exploitation (max 150 words)",
  "owaspCategory": "OWASP Top 10 2021 category (e.g., 'A03:2021 - Injection')",
  "recommendations": [
    "Specific actionable recommendation 1",
    "Specific actionable recommendation 2"
  ]
}

CRITICAL REQUIREMENT FOR JSON FORMATTING:
1. Ensure the response is valid, parseable JSON.
2. Inside the string values for keys ("explanation", "secureFix", "attackExample", "owaspCategory"), do NOT use raw literal unescaped newlines. Every newline inside the string values MUST be escaped as the character sequence \\n.
3. Every double quote inside the string values MUST be escaped as \\".
4. Return ONLY the JSON object, no additional text outside of it.`;
};

module.exports = {
  getExplanationPrompt,
  getSecureFixPrompt,
  getAttackExamplePrompt,
  getOwaspMappingPrompt,
  getComprehensivePrompt,
};
