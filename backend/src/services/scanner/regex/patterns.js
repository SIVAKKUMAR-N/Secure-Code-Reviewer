/**
 * Vulnerability Detection Patterns
 * Regular expressions and rules for detecting common security vulnerabilities
 * across multiple supported languages (JS, TS, Python, PHP, Java, C#, Ruby, Go).
 * 
 * Rules are structured to perform Sink-Based Detection: checking for user inputs,
 * string concatenation, format specifiers, and interpolations inside dangerous APIs.
 */

const patterns = {
  // ==================== 1. SQL INJECTION (SQLI) ====================
  sqlInjection: {
    javascript: [
      {
        id: 'JS-SQLI-001',
        regex: /(?:query|execute|find|findOne|findAll|where|raw)\s*\(\s*[`'"].*?\$\{.*?\}.*?[`'"]/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: Template literal interpolation in SQL query execution sink',
        recommendation: 'Use parameterized queries or ORM query builders (e.g., db.query("SELECT * FROM users WHERE id = ?", [id])) instead of string template interpolation.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'JS-SQLI-002',
        regex: /(?:query|execute)\s*\(\s*[^)]*?\+[^)]*?\)/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'SQL Injection: String concatenation in SQL query execution sink',
        recommendation: 'Replace string concatenation inside database queries with parameterized statements or query placeholders.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'JS-SQLI-003',
        regex: /(?:const|let|var)\s+(?:sql|query|cmd|command)\s*=\s*[`'"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?[`'"]\s*\+\s*[^;]*/gi,
        severity: 'Critical',
        confidence: 80,
        message: 'SQL Injection: String concatenation in SQL query variable construction',
        recommendation: 'Avoid building SQL command strings using plus (+) concatenation. Bind parameters directly when calling the execution sink.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    typescript: [
      {
        id: 'TS-SQLI-001',
        regex: /(?:query|execute|find|findOne|findAll|where|raw)\s*\(\s*[`'"].*?\$\{.*?\}.*?[`'"]/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: Template literal interpolation in SQL query execution sink',
        recommendation: 'Use parameterized queries or ORM query builders (e.g., db.query("SELECT * FROM users WHERE id = ?", [id])) instead of string template interpolation.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'TS-SQLI-002',
        regex: /(?:query|execute)\s*\(\s*[^)]*?\+[^)]*?\)/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'SQL Injection: String concatenation in SQL query execution sink',
        recommendation: 'Replace string concatenation inside database queries with parameterized statements or query placeholders.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'TS-SQLI-003',
        regex: /(?:const|let|var)\s+(?:sql|query|cmd|command)\s*=\s*[`'"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?[`'"]\s*\+\s*[^;]*/gi,
        severity: 'Critical',
        confidence: 80,
        message: 'SQL Injection: String concatenation in SQL query variable construction',
        recommendation: 'Avoid building SQL command strings using plus (+) concatenation. Bind parameters directly when calling the execution sink.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    python: [
      {
        id: 'PY-SQLI-001',
        regex: /(?:execute|executemany|cursor\.execute|raw|execute_query)\s*\(\s*(?:[f'"].*?(?:\{|\%|\+).*?['"]|[^)]*?\+[^)]*?)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: Dynamic string construction in SQL execute sink',
        recommendation: 'Use database query placeholders (e.g., cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))) instead of python f-strings or string concatenation.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'PY-SQLI-002',
        regex: /(?:sql|query|cmd|command)\s*=\s*[f'"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?(?:\{|\%|\+)/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'SQL Injection: Unsafe SQL query string construction using f-strings',
        recommendation: 'Avoid using f-strings or percent-formatting to construct SQL statements. Pass arguments separately as a tuple.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    php: [
      {
        id: 'PHP-SQLI-001',
        regex: /(?:mysql_query|mysqli_query|pg_query|query|execute|exec)\s*\(\s*[^)]*?\.\s*(?:\$_|\$[a-zA-Z_])/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'SQL Injection: Direct variable concatenation in SQL query execution sink',
        recommendation: 'Use prepared statements with PDO (PHP Data Objects) and fetch variables using execute(array(":id" => $id)) to separate data from query structure.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'PHP-SQLI-002',
        regex: /\$_(?:GET|POST|REQUEST)\[[^\]]+\]\s*;?\s*\)?;?\s*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: Unsanitized request variables embedded in SQL command context',
        recommendation: 'Never pass raw HTTP request variables straight into queries. Use PDO prepared statements with binding.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    java: [
      {
        id: 'JV-SQLI-001',
        regex: /\.(?:execute|executeQuery|executeUpdate|rawQuery)\s*\(\s*[^)]*?\+[^)]*?\)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: String concatenation in database query execution sink',
        recommendation: 'Use java.sql.PreparedStatement with bind parameters (e.g. pstmt.setString(1, id)) instead of building queries via concatenation.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'JV-SQLI-002',
        regex: /(?:String\s+(?:sql|query|cmd|command|strSql)|(?:sql|query|cmd|command|strSql)\s*=)\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+\s*[^;]*/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'SQL Injection: String concatenation in SQL query variable construction',
        recommendation: 'Construct SQL commands with PreparedStatement placeholder parameters ("?") instead of java string concatenations.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    csharp: [
      {
        id: 'CS-SQLI-001',
        regex: /(?:\.CommandText\s*=\s*[^;]*?(?:\+|\$["']))|(?:\.(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(\s*[^)]*?(?:\+|\$["']))/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: String concatenation/interpolation inside SQL Command execution context',
        recommendation: 'Utilize SqlParameter class inside SqlCommand (e.g., command.Parameters.AddWithValue("@id", id)) to secure query parameters.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'CS-SQLI-002',
        regex: /(?:string\s+(?:sql|query|cmd|command)|(?:sql|query|cmd|command)\s*=)\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+\s*[^;]*/gi,
        severity: 'Critical',
        confidence: 80,
        message: 'SQL Injection: Unsafe SQL string concatenation detected',
        recommendation: 'Define queries using parameterized place-markers and append SqlParameters to the command object.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    ruby: [
      {
        id: 'RB-SQLI-001',
        regex: /(?:\.where|\.find_by_sql|execute)\s*\(\s*["'].*?#\{[^}]+\}.*?["']\)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: String interpolation in ActiveRecord/Database query execution',
        recommendation: 'Pass arguments as array placeholders (e.g., User.where("id = ?", id)) to leverage Rails built-in SQL injection defense.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'RB-SQLI-002',
        regex: /(?:sql|query|cmd|command)\s*=\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*?#\{[^}]+\}.*?["']/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'SQL Injection: Unsafe SQL query string construction using string interpolation',
        recommendation: 'Do not interpolate user-controlled variables inside ActiveRecord queries. Bind parameters explicitly.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    go: [
      {
        id: 'GO-SQLI-001',
        regex: /\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(\s*(?:fmt\.Sprintf|.*?fmt\.Sprintf|[^,)]*?\+[^,)]*?)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'SQL Injection: fmt.Sprintf or concatenation in database query execution sink',
        recommendation: 'Utilize placeholder tokens (?) inside sql query arguments (e.g., db.Query("SELECT * FROM users WHERE id = ?", id)) instead of format printing.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'GO-SQLI-002',
        regex: /(?:sql|query|cmd|command)\s*:=\s*(?:fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*?%[s|d|v].*?["']|["'](?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*\+\s*)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'SQL Injection: SQL string construction using unsafe string formatting/concatenation',
        recommendation: 'Write raw SQL statements with positional parameters ($1, $2 or ?) and pass data as interface arguments during command execution.',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
      }
    ]
  },

  // ==================== 2. CROSS-SITE SCRIPTING (XSS) ====================
  xss: {
    javascript: [
      {
        id: 'JS-XSS-001',
        regex: /(?:innerHTML|outerHTML)\s*=\s*(?!['"`])[^;]+/gi,
        severity: 'High',
        confidence: 80,
        message: 'XSS: Dangerous assignment to innerHTML or outerHTML using dynamic variables',
        recommendation: 'Use document.createTextNode() or element.textContent instead of innerHTML to automatically escape tags. Otherwise, pass variables through DOMPurify.sanitize().',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'JS-XSS-002',
        regex: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: React dangerouslySetInnerHTML used without sanitization',
        recommendation: 'Avoid dangerouslySetInnerHTML. If required, sanitize variables using a library like DOMPurify first.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'JS-XSS-003',
        regex: /document\.write\s*\([^)]*?(?:req|params|query|body|input)/gi,
        severity: 'High',
        confidence: 85,
        message: 'XSS: document.write() containing request-based inputs',
        recommendation: 'Do not write raw HTML strings from request headers or inputs to document.write(). Construct the elements dynamically using DOM APIs.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    typescript: [
      {
        id: 'TS-XSS-001',
        regex: /(?:innerHTML|outerHTML)\s*=\s*(?!['"`])[^;]+/gi,
        severity: 'High',
        confidence: 80,
        message: 'XSS: Dangerous assignment to innerHTML or outerHTML using dynamic variables',
        recommendation: 'Use element.textContent instead of innerHTML to avoid parsing variables as HTML elements.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'TS-XSS-002',
        regex: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: React dangerouslySetInnerHTML used without sanitization',
        recommendation: 'Sanitize content before assigning it to dangerouslySetInnerHTML.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    python: [
      {
        id: 'PY-XSS-001',
        regex: /render_template_string\s*\([^)]*?(?:request|input|args|form)/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: Flask template string compiled dynamically with request parameters',
        recommendation: 'Pass request inputs as context variables to HTML templates instead of dynamic template string rendering.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'PY-XSS-002',
        regex: /mark_safe\s*\(\s*[^)]*?(?:request|input|args|form)/gi,
        severity: 'High',
        confidence: 85,
        message: 'XSS: Django mark_safe utilized with raw request parameters',
        recommendation: 'Avoid mark_safe with input variable concatenations. Rely on Django auto-escaping instead.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    php: [
      {
        id: 'PHP-XSS-001',
        regex: /(?:echo|print|printf)\s*(?!\s*(?:htmlspecialchars|htmlentities|strip_tags))\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/gi,
        severity: 'High',
        confidence: 95,
        message: 'XSS: Printing user requests parameters directly without escaping',
        recommendation: 'Pass PHP parameters through htmlspecialchars($var, ENT_QUOTES, "UTF-8") before sending output to the browser.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    java: [
      {
        id: 'JV-XSS-001',
        regex: /\.(?:print|println|write)\s*\(\s*[^)]*?(?:request|req)\.getParameter/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: Direct writing of request parameter into response writer sink',
        recommendation: 'Use OWASP Java Encoder library to encode outputs (e.g. Encoder.forHtml(userInput)) prior to printing.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    csharp: [
      {
        id: 'CS-XSS-001',
        regex: /Response\.Write\s*\(\s*[^)]*?(?:Request|QueryString|Form)/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: Direct printing of request attributes using Response.Write sink',
        recommendation: 'Use Microsoft AntiXSSLibrary to sanitize dynamic output, or use Razor templates which auto-escape parameters.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    ruby: [
      {
        id: 'RB-XSS-001',
        regex: /(?:html_safe|raw)\s*(?:\([^)]*?(?:params|session)[^)]*?\)|[^a-zA-Z0-9_\s]*?(?:params|session))/gi,
        severity: 'High',
        confidence: 85,
        message: 'XSS: Declaring HTTP parameters as html_safe or raw output',
        recommendation: 'Avoid bypass helpers like raw or html_safe. Allow Rails ERB framework to perform default HTML escaping.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    go: [
      {
        id: 'GO-XSS-001',
        regex: /\.Write\s*\(\s*\[\]byte\s*\(\s*[^)]*?(?:r\.FormValue|r\.URL\.Query\(\))/gi,
        severity: 'High',
        confidence: 90,
        message: 'XSS: Writing unescaped raw HTTP values to response body',
        recommendation: 'Escape output strings using standard html.EscapeString() prior to writing to the client buffer.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
      }
    ]
  },

  // ==================== 3. COMMAND INJECTION (CMD) ====================
  commandInjection: {
    javascript: [
      {
        id: 'JS-CMD-001',
        regex: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*(?:[`'"].*?\$\{.*?\}.*?[`'"]|[^)]*?\+[^)]*?)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Command Injection: Dynamic string variable inside child_process shell execution sink',
        recommendation: 'Avoid child_process.exec. Use execFile or spawn with argument arrays, which prevents shell metacharacter injection.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    typescript: [
      {
        id: 'TS-CMD-001',
        regex: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*(?:[`'"].*?\$\{.*?\}.*?[`'"]|[^)]*?\+[^)]*?)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Command Injection: Dynamic string variable inside child_process shell execution sink',
        recommendation: 'Use spawn or execFile and provide command arguments as separate elements of an array.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    python: [
      {
        id: 'PY-CMD-001',
        regex: /(?:os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:[f'"].*?(?:\{|\%|\+).*?['"]|[^)]*?\+[^)]*?)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Command Injection: Unsafe execution of dynamic formatting inside system shell sink',
        recommendation: 'Avoid shell=True. Pass arguments as a list of strings: subprocess.run(["ping", "-c", "1", host]) with shell=False.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    php: [
      {
        id: 'PHP-CMD-001',
        regex: /(?:exec|shell_exec|system|passthru)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+\s*\.\s*)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Command Injection: Unsanitized user variable passed to shell execution command',
        recommendation: 'Pass shell arguments through escapeshellcmd() or escapeshellarg() before sending to command sinks.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    java: [
      {
        id: 'JV-CMD-001',
        regex: /Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*?(?:getParameter|args|query|input|\+)[^)]*?\)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Command Injection: Java runtime exec execution using concatenated parameters',
        recommendation: 'Avoid runtime string command invocation. Pass parameters as string arrays to ProcessBuilder: new ProcessBuilder("ping", host).',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    csharp: [
      {
        id: 'CS-CMD-001',
        regex: /Process\.Start\s*\(\s*[^)]*?(?:Request|Query|args|input|\+)[^)]*?\)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Command Injection: System Process initialized using request variables',
        recommendation: 'Define ProcessStartInfo.Arguments explicitly. Sanitize or validate string arguments against a whitelist before launch.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    ruby: [
      {
        id: 'RB-CMD-001',
        regex: /(?:system|exec)\s*\(\s*["'].*?#\{[^}]+\}.*?["']\)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Command Injection: Dynamic string execution using ruby system/exec call',
        recommendation: 'Provide arguments as separate strings: system("ping", "-c", "1", host) to execute safely without a shell context.',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    go: [
      {
        id: 'GO-CMD-001',
        regex: /exec\.Command(?:Context)?\s*\(\s*(?:["']sh["']|["']bash["'])\s*,\s*["']-c["']\s*,\s*[^)]*?(?:FormValue|Query|r\.|input|\+)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Command Injection: Shell invocation cmd utilizing HTTP query input variables',
        recommendation: 'Execute binary applications directly without invoking a shell wrapper. Use exec.Command(binary, arg1, arg2).',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
      },
      {
        id: 'GO-CMD-002',
        regex: /exec\.Command(?:Context)?\s*\(\s*[^,)]+?\s*,\s*[^)]*?(?:FormValue|Query|r\.|input|\+)/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'Command/Argument Injection: Command executed with user-supplied inputs',
        recommendation: 'Ensure all command-line arguments are sanitized and validated against a strict whitelist before passing to exec.Command.',
        cweId: 'CWE-88',
        owaspCategory: 'A03:2021 - Injection',
      }
    ]
  },

  // ==================== 4. HARDCODED SECRETS (SEC) ====================
  secrets: {
    all: [
      {
        id: 'ALL-SEC-001',
        regex: /(?:password|passwd|pwd|private_key)\s*=\s*['"'](?![a-zA-Z0-9_{}$]+['"'])([^'"\s]{8,})['"']/gi,
        severity: 'Critical',
        confidence: 85,
        message: 'Hardcoded Secret: Plaintext credential assignment detected',
        recommendation: 'Remove credential strings from code. Load sensitive credentials dynamically from environment variables (e.g. process.env.DB_PASSWORD).',
        cweId: 'CWE-798',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
      },
      {
        id: 'ALL-SEC-002',
        regex: /(?:api[_-]?key|apikey|access[_-]?key)\s*=\s*['"']([a-zA-Z0-9]{20,})['"']/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Hardcoded API Key: Exposed application credentials detected',
        recommendation: 'Use key management vaults or local environment files to inject keys at runtime instead of hardcoding.',
        cweId: 'CWE-798',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      },
      {
        id: 'ALL-SEC-003',
        regex: /(?:secret|token|auth_token)\s*=\s*['"']([a-zA-Z0-9+/=_-]{30,})['"']/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Hardcoded Secret Token: Insecure auth tokens stored in source code',
        recommendation: 'Inject auth tokens from secure vault engines or standard configuration directories at runtime.',
        cweId: 'CWE-798',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      },
      {
        id: 'ALL-SEC-004',
        regex: /(?:aws|amazon)[_-]?(?:access|secret)[_-]?key['"']?\s*[:=]\s*['"']([A-Z0-9]{20,})['"']/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Hardcoded AWS Credentials: AWS access key exposed in source code',
        recommendation: 'Inject AWS credentials using AWS IAM Instance Profiles or standard ~/.aws/credentials configs.',
        cweId: 'CWE-798',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ]
  },

  // ==================== 5. WEAK HASHING (HASH) ====================
  weakHashing: {
    javascript: [
      {
        id: 'JS-HASH-001',
        regex: /createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: Insecure MD5/SHA1 cryptographic algorithm initialized',
        recommendation: 'Replace MD5 or SHA1 with secure, collision-resistant hash functions like SHA-256 or SHA-512.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    typescript: [
      {
        id: 'TS-HASH-001',
        regex: /createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: Insecure MD5/SHA1 cryptographic algorithm initialized',
        recommendation: 'Use SHA-256 or Argon2 algorithms for cryptographic operations.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    python: [
      {
        id: 'PY-HASH-001',
        regex: /hashlib\.(?:md5|sha1)\s*\(/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: Insecure hashlib.md5 or hashlib.sha1 instantiated',
        recommendation: 'Migrate to hashlib.sha256() or use bcrypt/argon2 for password storage requirements.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    php: [
      {
        id: 'PHP-HASH-001',
        regex: /(?:md5|sha1)\s*\(\s*[^)]*/gi,
        severity: 'High',
        confidence: 90,
        message: 'Weak Hashing: MD5 or SHA1 hash functions executed',
        recommendation: 'Use password_hash($password, PASSWORD_BCRYPT) to compute secure passwords.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    java: [
      {
        id: 'JV-HASH-001',
        regex: /MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1|SHA1)['"]\s*\)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: MessageDigest loaded MD5 or SHA-1 instance',
        recommendation: 'Instantiate MessageDigest using secure algorithms: MessageDigest.getInstance("SHA-256").',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    csharp: [
      {
        id: 'CS-HASH-001',
        regex: /(?:MD5|SHA1)\.Create\s*\(\s*\)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: Insecure MD5 or SHA1 cryptoprovider initialized',
        recommendation: 'Create SHA256 hashes instead: SHA256.Create().',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    ruby: [
      {
        id: 'RB-HASH-001',
        regex: /Digest::(?:MD5|SHA1)\.(?:hexdigest|digest)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: Insecure Digest::MD5 or Digest::SHA1 hashing executed',
        recommendation: 'Use Digest::SHA256 or bcrypt gems for secure, slow hashes.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    go: [
      {
        id: 'GO-HASH-001',
        regex: /(?:md5|sha1)\.(?:New|Sum)\s*\(/gi,
        severity: 'High',
        confidence: 95,
        message: 'Weak Hashing: md5 or sha1 crypto module package referenced',
        recommendation: 'Import and use the crypto/sha256 package (sha256.New()) instead.',
        cweId: 'CWE-327',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ]
  },

  // ==================== 6. DANGEROUS EVAL() (EVAL) ====================
  dangerousEval: {
    javascript: [
      {
        id: 'JS-EVAL-001',
        regex: /(?:eval|Function)\s*\(\s*[^)]*(?:req|query|body|params|input)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Dangerous Eval: Dynamic code evaluation using request parameters',
        recommendation: 'Never pass user-controlled variables into eval() or new Function(). Parse requests using JSON.parse() instead.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    typescript: [
      {
        id: 'TS-EVAL-001',
        regex: /(?:eval|Function)\s*\(\s*[^)]*(?:req|query|body|params|input)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Dangerous Eval: Dynamic code evaluation using request parameters',
        recommendation: 'Do not parse inputs dynamically using eval(). Map parameters to strict logic paths.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    python: [
      {
        id: 'PY-EVAL-001',
        regex: /(?:eval|exec)\s*\(\s*[^)]*(?:request|input|args|form)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Dangerous Eval: Insecure code execution using Python eval() or exec()',
        recommendation: 'Avoid eval() and exec(). Use ast.literal_eval() if deserializing data structures statically.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    php: [
      {
        id: 'PHP-EVAL-001',
        regex: /(?:eval|assert)\s*\(\s*.*?(?:\$_GET|\$_POST|\$_REQUEST)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Dangerous Eval: Dynamic scripting evaluation using request parameters',
        recommendation: 'Do not use eval() or assert() with raw inputs. Implement static router methods instead.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    java: [
      {
        id: 'JV-EVAL-001',
        regex: /\.eval\s*\(\s*[^)]*?(?:getParameter|args|query|input)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Dangerous Eval: Dynamic ScriptEngine execution parsing client values',
        recommendation: 'Sanitize script contents or isolate ScriptEngine operations. Restrict dynamic execution models.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    csharp: [
      {
        id: 'CS-EVAL-001',
        regex: /CSharpScript\.Evaluate(?:Async)?\s*\(\s*[^)]*?(?:Request|Query|Form)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Dangerous Eval: Roslyn compilation of dynamic script containing input parameters',
        recommendation: 'Isolate dynamic script execution in highly sandbox processes. Validate variables strictly.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    ruby: [
      {
        id: 'RB-EVAL-001',
        regex: /(?:\.eval|instance_eval)\s*\(\s*.*?(?:params|session)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Dangerous Eval: Ruby dynamic evaluation of request values',
        recommendation: 'Avoid dynamic string evaluations. Validate parameters and map them to structural routes.',
        cweId: 'CWE-95',
        owaspCategory: 'A03:2021 - Injection',
      }
    ]
  },

  // ==================== 7. UNSAFE FILE UPLOAD (UPL) ====================
  fileUpload: {
    javascript: [
      {
        id: 'JS-UPL-001',
        regex: /multer\s*\([^)]*\)\.(?:single|array|fields)\s*\([^)]*\)(?!.*fileFilter)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Unsafe File Upload: Multer initialized without fileFilter type validation',
        recommendation: 'Configure fileFilter inside multer options checking against a strict whitelist of file types and MIME values.',
        cweId: 'CWE-434',
        owaspCategory: 'A04:2021 - Insecure Design',
      }
    ],
    typescript: [
      {
        id: 'TS-UPL-001',
        regex: /multer\s*\([^)]*\)\.(?:single|array|fields)\s*\([^)]*\)(?!.*fileFilter)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Unsafe File Upload: Multer initialized without fileFilter type validation',
        recommendation: 'Always enforce validation on file sizes and mime type whitelisting.',
        cweId: 'CWE-434',
        owaspCategory: 'A04:2021 - Insecure Design',
      }
    ],
    python: [
      {
        id: 'PY-UPL-001',
        regex: /\.save\s*\(\s*[^)]*?(?:request\.files|filename)(?!.*secure_filename)/gi,
        severity: 'High',
        confidence: 90,
        message: 'Unsafe File Upload: Flask file save without secure_filename protection',
        recommendation: 'Pass raw filenames through werkzeug.utils.secure_filename() to remove path traversal control characters.',
        cweId: 'CWE-434',
        owaspCategory: 'A04:2021 - Insecure Design',
      }
    ],
    php: [
      {
        id: 'PHP-UPL-001',
        regex: /move_uploaded_file\s*\(\s*\$_FILES[^)]*\)(?!.*(?:getimagesize|mime_content_type|in_array))/gi,
        severity: 'High',
        confidence: 90,
        message: 'Unsafe File Upload: move_uploaded_file called without mime validation checks',
        recommendation: 'Check $_FILES["file"]["tmp_name"] using mime_content_type() and match it to a strict whitelist before saving.',
        cweId: 'CWE-434',
        owaspCategory: 'A04:2021 - Insecure Design',
      }
    ]
  },

  // ==================== 8. PATH TRAVERSAL (TRAV) ====================
  pathTraversal: {
    javascript: [
      {
        id: 'JS-TRAV-001',
        regex: /fs\.(?:readFile|writeFile|createReadStream|createWriteStream|readFileSync|writeFileSync)\s*\(\s*[^)]*?\+[^)]*?(?:req|query|body|params|input)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Path Traversal: Unsafe file system access utilizing parameter concatenation',
        recommendation: 'Use path.resolve() or path.basename() to sanitize filenames, ensuring users cannot request files with standard path operations ("..").',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    typescript: [
      {
        id: 'TS-TRAV-001',
        regex: /fs\.(?:readFile|writeFile|createReadStream|createWriteStream|readFileSync|writeFileSync)\s*\(\s*[^)]*?\+[^)]*?(?:req|query|body|params|input)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Path Traversal: Unsafe file system access utilizing parameter concatenation',
        recommendation: 'Sanitize target paths using path.resolve and block any directories outside a whitelist destination.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    python: [
      {
        id: 'PY-TRAV-001',
        regex: /open\s*\(\s*[^)]*?(?:\+|,).*?(?:request|input|args|form)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Path Traversal: Dynamic file open containing concatenated HTTP request inputs',
        recommendation: 'Use os.path.basename() on target file parameters to restrict users to a single directory folder.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    php: [
      {
        id: 'PHP-TRAV-001',
        regex: /(?:include|require|include_once|require_once|file_get_contents|readfile)\s*\(\s*[^)]*?\.\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi,
        severity: 'High',
        confidence: 95,
        message: 'Path Traversal / Local File Inclusion: Dynamic file reference utilizing request parameter',
        recommendation: 'Avoid dynamic file inclusions. Use basename() to filter parameters, or map options to a rigid key-value array.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    java: [
      {
        id: 'JV-TRAV-001',
        regex: /new\s+(?:File|FileInputStream|FileOutputStream)\s*\(\s*[^)]*?(?:getParameter|args|query|input|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Path Traversal: New File instance created using request parameters',
        recommendation: 'Call getCanonicalPath() on the file and ensure it starts with the expected base directory path.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    csharp: [
      {
        id: 'CS-TRAV-001',
        regex: /File\.(?:ReadAllText|ReadAllBytes|WriteAllText|OpenRead)\s*\(\s*[^)]*?(?:Request|Query|Form|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 90,
        message: 'Path Traversal: File read/write executed using concatenated parameters',
        recommendation: 'Obtain the full path via Path.GetFullPath(userInput) and verify it is located inside the intended boundary folder.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    ruby: [
      {
        id: 'RB-TRAV-001',
        regex: /File\.(?:read|open|readlines)\s*\(\s*["'].*?#\{[^}]+\}.*?["']\)/gi,
        severity: 'High',
        confidence: 85,
        message: 'Path Traversal: File open executed using dynamic string interpolation',
        recommendation: 'Strip path operator symbols using File.basename(userInput) to enforce localized folder access.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ],
    go: [
      {
        id: 'GO-TRAV-001',
        regex: /(?:os\.Open|ioutil\.ReadFile|os\.Create)\s*\(\s*[^)]*?(?:FormValue|Query|r\.|input|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 90,
        message: 'Path Traversal: Go os.Open or file read using request parameters',
        recommendation: 'Use filepath.Clean(userInput) and verify that the target directory hierarchy matches base expectations.',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
      }
    ]
  },

  // ==================== 9. UNSAFE DESERIALIZATION (DESER) ====================
  unsafeDeserialization: {
    javascript: [
      {
        id: 'JS-DESER-001',
        regex: /(?:\bserialize|\bunserialize|node-serialize['"]\)?)\.unserialize\s*\(/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: Unsafe node-serialize method executed',
        recommendation: 'Avoid unserialize methods. Use standard JSON.parse() and validate schemas to parse request objects.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    typescript: [
      {
        id: 'TS-DESER-001',
        regex: /(?:\bserialize|\bunserialize|node-serialize['"]\)?)\.unserialize\s*\(/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: Unsafe node-serialize method executed',
        recommendation: 'Parse request streams strictly as type-safe JSON objects.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    python: [
      {
        id: 'PY-DESER-001',
        regex: /(?:pickle|marshal|shelve)\.(?:loads|load)\s*\(/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: Pickle/Marshal data deserialization',
        recommendation: 'Avoid loading pickle data from untrusted sources. Use json or protobuf to exchange data securely.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      },
      {
        id: 'PY-DESER-002',
        regex: /yaml\.load\s*\(\s*[^)]*(?!.*SafeLoader)/gi,
        severity: 'Critical',
        confidence: 90,
        message: 'Unsafe Deserialization: Unsafe PyYAML loading detected',
        recommendation: 'Use yaml.safe_load() or configure yaml.load() strictly using yaml.SafeLoader to block code executions.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    php: [
      {
        id: 'PHP-DESER-001',
        regex: /unserialize\s*\(\s*.*?(?:\$_GET|\$_POST|\$_REQUEST)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: PHP unserialize executed with request parameters',
        recommendation: 'Replace unserialize() with json_decode(). Do not allow untrusted parameters to instantiate server-side objects.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    java: [
      {
        id: 'JV-DESER-001',
        regex: /\.readObject\s*\(\s*\)/gi,
        severity: 'Critical',
        confidence: 80,
        message: 'Unsafe Deserialization: ObjectInputStream.readObject executed (potential deserialization exploit)',
        recommendation: 'Configure strict class filters using ObjectInputFilter on standard input streams before reading objects.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    csharp: [
      {
        id: 'CS-DESER-001',
        regex: /(?:BinaryFormatter|NetDataContractSerializer)\.Deserialize\s*\(/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: BinaryFormatter class instance deserialization',
        recommendation: 'Do not use BinaryFormatter. Use secure alternative serializing engines like System.Text.Json.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ],
    ruby: [
      {
        id: 'RB-DESER-001',
        regex: /(?:Marshal\.load|YAML\.load)\s*\(\s*.*?(?:params|session)/gi,
        severity: 'Critical',
        confidence: 95,
        message: 'Unsafe Deserialization: Unsafe Marshal or YAML loading of HTTP inputs',
        recommendation: 'Use SafeYAML or replace Marshal streams with standard JSON parse formats.',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
      }
    ]
  },

  // ==================== 10. JWT ISSUES (JWT) ====================
  jwtIssues: {
    javascript: [
      {
        id: 'JS-JWT-001',
        regex: /jwt\.sign\s*\([^)]*,\s*['"'][^'"]{1,8}['"']/gi,
        severity: 'High',
        confidence: 90,
        message: 'Weak JWT Secret: Cryptographic key length is dangerously short (< 8 characters)',
        recommendation: 'Generate long secrets (> 32 high-entropy characters) and import them via environment variables.',
        cweId: 'CWE-326',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      },
      {
        id: 'JS-JWT-002',
        regex: /jwt\.verify\s*\([^)]*\)\s*;?\s*(?!.*catch)/gi,
        severity: 'Medium',
        confidence: 75,
        message: 'JWT Verification: jwt.verify() called without catch handler block',
        recommendation: 'Wrap verification methods inside try-catch blocks to catch and reject expired or modified tokens.',
        cweId: 'CWE-754',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
      }
    ],
    typescript: [
      {
        id: 'TS-JWT-001',
        regex: /jwt\.sign\s*\([^)]*,\s*['"'][^'"]{1,8}['"']/gi,
        severity: 'High',
        confidence: 90,
        message: 'Weak JWT Secret: Cryptographic key length is dangerously short (< 8 characters)',
        recommendation: 'Use long, robust configuration keys.',
        cweId: 'CWE-326',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ]
  },

  // ==================== 11. MISSING INPUT VALIDATION (VAL) ====================
  inputValidation: {
    javascript: [
      {
        id: 'JS-VAL-001',
        regex: /req\.(?:body|query|params)\.[a-zA-Z0-9_]+(?!\s*(?:&&|if|===|!==|\?|\.test|\.match|validate|check|sanitize))/gi,
        severity: 'Medium',
        confidence: 70,
        message: 'Missing Input Validation: Accessing request variables directly without checking guards',
        recommendation: 'Filter and validate all inputs using robust validator models (e.g., express-validator schemas) before usage.',
        cweId: 'CWE-20',
        owaspCategory: 'A03:2021 - Injection',
      }
    ],
    typescript: [
      {
        id: 'TS-VAL-001',
        regex: /req\.(?:body|query|params)\.[a-zA-Z0-9_]+(?!\s*(?:&&|if|===|!==|\?|\.test|\.match|validate|check|sanitize))/gi,
        severity: 'Medium',
        confidence: 70,
        message: 'Missing Input Validation: Accessing request variables directly without checking guards',
        recommendation: 'Enforce type-safe request parsing and validation.',
        cweId: 'CWE-20',
        owaspCategory: 'A03:2021 - Injection',
      }
    ]
  },

  // ==================== 12. ReDoS (REDOS) ====================
  redos: {
    javascript: [
      {
        id: 'JS-REDOS-001',
        regex: /new\s+RegExp\s*\(\s*[^)]*?(?:req|query|body|params|input)/gi,
        severity: 'Medium',
        confidence: 85,
        message: 'ReDoS: Dynamic RegExp initialized with user input variables',
        recommendation: 'Avoid dynamic RegExp generation from request parameters. If necessary, escape variables using escape-string-regexp first.',
        cweId: 'CWE-1333',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
      }
    ],
    typescript: [
      {
        id: 'TS-REDOS-001',
        regex: /new\s+RegExp\s*\(\s*[^)]*?(?:req|query|body|params|input)/gi,
        severity: 'Medium',
        confidence: 85,
        message: 'ReDoS: Dynamic RegExp initialized with user input variables',
        recommendation: 'Do not compile regular expressions from raw HTTP parameters.',
        cweId: 'CWE-1333',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
      }
    ],
    python: [
      {
        id: 'PY-REDOS-001',
        regex: /re\.compile\s*\(\s*[^)]*?(?:request|input|args|form)/gi,
        severity: 'Medium',
        confidence: 85,
        message: 'ReDoS: Regular expression compiled using request input',
        recommendation: 'Enforce string limits and escape pattern inputs prior to re.compile() execution.',
        cweId: 'CWE-1333',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
      }
    ]
  },

  // ==================== 13. SSRF (SSRF) ====================
  ssrf: {
    javascript: [
      {
        id: 'JS-SSRF-001',
        regex: /(?:axios|axios\.get|axios\.post|fetch|http\.get|http\.request)\s*\(\s*(?:[`'"].*?\$\{.*?\}.*?[`'"]|[^)]*?\+[^)]*?(?:req|query|body|params|input))/gi,
        severity: 'High',
        confidence: 85,
        message: 'SSRF: HTTP client request targeting a concatenated parameter host',
        recommendation: 'Enforce a domain whitelist for outbound connections. Never allow clients to configure full outbound destination addresses.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    typescript: [
      {
        id: 'TS-SSRF-001',
        regex: /(?:axios|axios\.get|axios\.post|fetch|http\.get|http\.request)\s*\(\s*(?:[`'"].*?\$\{.*?\}.*?[`'"]|[^)]*?\+[^)]*?(?:req|query|body|params|input))/gi,
        severity: 'High',
        confidence: 85,
        message: 'SSRF: HTTP client request targeting a concatenated parameter host',
        recommendation: 'Whitelist outbound connection destination scopes.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    python: [
      {
        id: 'PY-SSRF-001',
        regex: /(?:requests\.get|requests\.post|requests\.request|urllib\.request\.urlopen)\s*\(\s*[^)]*?(?:request|input|args|form|\+)/gi,
        severity: 'High',
        confidence: 90,
        message: 'SSRF: Dynamic HTTP request executed using request parameter variables',
        recommendation: 'Isolate network request handlers. Enforce whitelist checks on request destination hostnames.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    php: [
      {
        id: 'PHP-SSRF-001',
        regex: /(?:curl_setopt|curl_init|file_get_contents)\s*\(\s*[^)]*?(?:\$_GET|\$_POST|\$_REQUEST)/gi,
        severity: 'High',
        confidence: 95,
        message: 'SSRF: Outbound request handler target variable contains request parameters',
        recommendation: 'Filter URLs through filter_var($url, FILTER_VALIDATE_URL) and match hostnames to local whitelists.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    java: [
      {
        id: 'JV-SSRF-001',
        regex: /new\s+URL\s*\(\s*[^)]*?(?:getParameter|args|query|input|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 85,
        message: 'SSRF: URL constructor contains request connection inputs',
        recommendation: 'Validate URLs strictly, checking hostnames against allowed target server addresses.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    csharp: [
      {
        id: 'CS-SSRF-001',
        regex: /(?:HttpClient|WebRequest).*?(?:GetAsync|Create|CreateHttp)\s*\(\s*[^)]*?(?:Request|Query|Form|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 90,
        message: 'SSRF: Outbound WebRequest targets client-controlled hosts',
        recommendation: 'Never pass raw parameters into URL client configurations. Enforce whitelist structures.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    ruby: [
      {
        id: 'RB-SSRF-001',
        regex: /(?:Net::HTTP|open)\s*\(\s*[^)]*?(?:params|session)/gi,
        severity: 'High',
        confidence: 85,
        message: 'SSRF: HTTP client call contains ruby parameter interpolations',
        recommendation: 'Filter URI hosts against a static server list before requesting.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ],
    go: [
      {
        id: 'GO-SSRF-001',
        regex: /http\.(?:Get|Post|NewRequest)\s*\(\s*[^)]*?(?:FormValue|Query|r\.|input|\+)[^)]*?\)/gi,
        severity: 'High',
        confidence: 90,
        message: 'SSRF: Go http client execution utilizing request variables',
        recommendation: 'Parse the URL using net/url.Parse() and verify hostname satisfies white-list checks.',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery (SSRF)',
      }
    ]
  },

  // ==================== 14. INSECURE RANDOMNESS (RAND) ====================
  insecureRandomness: {
    javascript: [
      {
        id: 'JS-RAND-001',
        regex: /Math\.random\s*\(\s*\)/gi,
        severity: 'Medium',
        confidence: 70,
        message: 'Insecure Randomness: Math.random() is cryptographically weak',
        recommendation: 'Use crypto.getRandomValues() or crypto.randomUUID() for sensitive operations (tokens, sessions, passwords).',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    typescript: [
      {
        id: 'TS-RAND-001',
        regex: /Math\.random\s*\(\s*\)/gi,
        severity: 'Medium',
        confidence: 70,
        message: 'Insecure Randomness: Math.random() is cryptographically weak',
        recommendation: 'Use crypto.getRandomValues() for secure random numbers.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    python: [
      {
        id: 'PY-RAND-001',
        regex: /random\.(?:random|randint|choice|randrange|uniform)\s*\(/gi,
        severity: 'Medium',
        confidence: 75,
        message: 'Insecure Randomness: standard random package used in security contexts',
        recommendation: 'Use the python secrets module (e.g., secrets.choice() or secrets.token_hex()) for cryptographically secure values.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    php: [
      {
        id: 'PHP-RAND-001',
        regex: /(?:\brand|mt_rand)\s*\(/gi,
        severity: 'Medium',
        confidence: 80,
        message: 'Insecure Randomness: rand() or mt_rand() is pseudo-random and weak',
        recommendation: 'Use secure random integer functions: random_int() or random_bytes().',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    java: [
      {
        id: 'JV-RAND-001',
        regex: /new\s+Random\s*\(\s*\)/gi,
        severity: 'Medium',
        confidence: 80,
        message: 'Insecure Randomness: java.util.Random is not cryptographically secure',
        recommendation: 'Instantiate java.security.SecureRandom for generating authorization tokens or session keys.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    csharp: [
      {
        id: 'CS-RAND-001',
        regex: /new\s+Random\s*\(\s*\)/gi,
        severity: 'Medium',
        confidence: 80,
        message: 'Insecure Randomness: System.Random instantiated',
        recommendation: 'Use System.Security.Cryptography.RandomNumberGenerator to obtain cryptographically strong byte outputs.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    ruby: [
      {
        id: 'RB-RAND-001',
        regex: /\brand\b/gi,
        severity: 'Medium',
        confidence: 70,
        message: 'Insecure Randomness: standard Kernel#rand is pseudo-random',
        recommendation: 'Use SecureRandom class (e.g. SecureRandom.hex) for session/security credentials.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ],
    go: [
      {
        id: 'GO-RAND-001',
        regex: /math\/rand/gi,
        severity: 'Medium',
        confidence: 85,
        message: 'Insecure Randomness: Import of math/rand instead of crypto/rand',
        recommendation: 'Always import crypto/rand (rand.Read) to construct securely random tokens or passwords.',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      }
    ]
  }
};

module.exports = patterns;