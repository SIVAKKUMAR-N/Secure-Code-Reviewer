const tripleBacktick = '`' + '`' + '`';

const malformedJSON = tripleBacktick + 'json\n' +
'{\n' +
'  "explanation": "This vulnerability uses MD5, a cryptographically broken hash function, for password hashing. MD5 is extremely fast and vulnerable to pre-image and collision attacks, making it unsuitable for securing passwords. Attackers can leverage pre-computed rainbow tables or rapidly brute-force MD5 hashes to recover original passwords in seconds, even for moderately complex ones. This exposes user credentials, leading to account takeovers, unauthorized access to systems, and potential data breaches, severely impacting user trust and organizational security.",\n' +
'  "secureFix": "```javascript\\nconst bcrypt = require(\'bcrypt\'); // Ensure \'bcrypt\' is installed (npm install bcrypt)\\nconst saltRounds = 12; // Recommended cost factor, adjust based on server performance and evolving security landscape\\n\\nasync function hashPassword(password) {\\n  try {\\n    // bcrypt automatically generates a unique salt and includes it in the hash\\n    const hashedPassword = await bcrypt.hash(password, saltRounds);\\n    return hashedPassword;\\n  } catch (error) {\\n    console.error(\'Error hashing password:\', error);\\n    throw new Error(\'Failed to hash password\');\\n  }\\n}\\n\\n// Example usage:\\n// hashPassword(\'mySecureP@ssw0rd!\').then(hash => console.log(\'Hashed Password:\', hash));\\n// To verify a password later, use await bcrypt.compare(password, storedHash);\\n```\\nThis fix replaces MD5 with \`bcrypt\`, a strong, slow, and salt-aware password hashing algorithm. \`bcrypt.hash()\` automatically generates a unique cryptographically secure salt for each password and incorporates a configurable \'cost factor\' (\`saltRounds\`). This cost factor dictates the computational work required, making brute-force attacks exponentially more expensive and significantly enhancing security. Always store the full \`bcrypt\` output and use \`bcrypt.compare()\` for secure verification.",\n' +
'  "attackExample": "An attacker compromises the database and obtains a list of usernames and their corresponding MD5 password hashes. Due to MD5\'s speed and known weaknesses, the attacker uses an optimized tool like \`hashcat\` or readily available pre-computed rainbow tables tailored for MD5 to quickly reverse the hashes. \`hashcat\` can crack thousands of MD5 hashes per second. Within minutes or hours, many user passwords, including common or dictionary-based ones, are recovered. The attacker then uses these cleartext passwords to log into user accounts, escalating privileges or accessing other services where users reuse passwords.",\n' +
'  "owaspCategory": "A02:2021 - Cryptographic Failures",\n' +
'  "recommendations": [\n' +
'    "Migrate all password hashing to a modern, robust, and purpose-built algorithm such as Argon2 (preferred), bcrypt, or scrypt. Implement a strategy for users to update their passwords, re-hashing them with the new algorithm upon next login.",\n' +
'    "Ensure a unique, cryptographically strong random salt is generated for each password hash, and configure an appropriate cost factor (iterations/memory/time) to increase the computational effort required for brute-force attacks, balancing security with acceptable performance."\n' +
'  ]\n' +
'}\n' + tripleBacktick;

const malformedJSONWithRawNewlines = tripleBacktick + 'json\n' +
'{\n' +
'  "explanation": "This vulnerability uses MD5, a cryptographically broken hash function, for password hashing.\\nMD5 is extremely fast and vulnerable to pre-image and collision attacks, making it unsuitable for securing passwords.",\n' +
'  "secureFix": "const bcrypt = require(\'bcrypt\');\\nconst saltRounds = 12;",\n' +
'  "attackExample": "An attacker compromises the database and obtains a list of usernames and their corresponding MD5 password hashes.",\n' +
'  "owaspCategory": "A02:2021 - Cryptographic Failures",\n' +
'  "recommendations": [\n' +
'    "Migrate all password hashing.",\n' +
'    "Ensure a unique salt."\n' +
'  ]\n' +
'}\n' + tripleBacktick;

function parseRobustJSON(text) {
  let cleanText = text.trim();
  
  // Strip markdown code blocks
  if (cleanText.startsWith(tripleBacktick)) {
    const firstNewline = cleanText.indexOf('\n');
    const lastBackticks = cleanText.lastIndexOf(tripleBacktick);
    if (firstNewline !== -1 && lastBackticks !== -1 && lastBackticks > firstNewline) {
      cleanText = cleanText.substring(firstNewline + 1, lastBackticks).trim();
    }
  }

  // First try parsing as JSON
  try {
    const parsed = JSON.parse(cleanText);
    return {
      explanation: parsed.explanation || '',
      secureFix: parsed.secureFix || '',
      attackExample: parsed.attackExample || '',
      owaspCategory: parsed.owaspCategory || 'Not mapped',
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
    };
  } catch (error) {
    console.log("Direct JSON.parse failed. Using robust fallback...");
  }

  const result = {
    explanation: '',
    secureFix: '',
    attackExample: '',
    owaspCategory: 'Not mapped',
    recommendations: []
  };

  const extractField = (key, nextKeyPattern) => {
    const keyPattern = new RegExp('"' + key + '"\\s*:\\s*"', 'i');
    const keyMatch = cleanText.match(keyPattern);
    if (!keyMatch) return '';
    
    const keyIndex = cleanText.search(keyPattern);
    const valStart = keyIndex + keyMatch[0].length;
    
    let valEnd = -1;
    if (nextKeyPattern) {
      const nextKeyIndex = cleanText.search(nextKeyPattern);
      if (nextKeyIndex !== -1 && nextKeyIndex > valStart) {
        valEnd = cleanText.lastIndexOf('"', nextKeyIndex);
      }
    }
    
    if (valEnd === -1 || valEnd <= valStart) {
      valEnd = cleanText.lastIndexOf('"');
    }
    
    if (valEnd > valStart) {
      let val = cleanText.substring(valStart, valEnd).trim();
      
      if (val.endsWith(',')) {
        val = val.substring(0, val.length - 1).trim();
      }
      if (val.endsWith('"')) {
        val = val.substring(0, val.length - 1).trim();
      }
      
      try {
        return JSON.parse('"' + val + '"');
      } catch (parseErr) {
        return val
          .replace(/\\n/g, '\n')
          .replace(/\\"/g, '"')
          .replace(/\\'/g, "'")
          .replace(/\\\\/g, '\\');
      }
    }
    
    return '';
  };

  result.explanation = extractField('explanation', /"secureFix"\s*:/i);
  result.secureFix = extractField('secureFix', /"attackExample"\s*:/i);
  result.attackExample = extractField('attackExample', /"owaspCategory"\s*:/i);
  result.owaspCategory = extractField('owaspCategory', /"recommendations"\s*:/i);

  // Extract recommendations array
  const recMatch = cleanText.match(/"recommendations"\s*:\s*\[([\s\S]*?)\]/i);
  if (recMatch) {
    const arrContent = recMatch[1];
    const items = [];
    const itemRegex = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
    let match;
    while ((match = itemRegex.exec(arrContent)) !== null) {
      let item = match[1];
      try {
        item = JSON.parse('"' + item + '"');
      } catch (e) {
        item = item.replace(/\\"/g, '"').replace(/\\n/g, '\n');
      }
      items.push(item);
    }
    result.recommendations = items;
  }

  return result;
}

console.log('Testing with malformed JSON containing raw newlines:');
const parsedRaw = parseRobustJSON(malformedJSONWithRawNewlines);
console.log('Result:\n', JSON.stringify(parsedRaw, null, 2));

console.log('\nTesting with task-415 JSON structure:');
const parsed415 = parseRobustJSON(malformedJSON);
console.log('Result:\n', JSON.stringify(parsed415, null, 2));
