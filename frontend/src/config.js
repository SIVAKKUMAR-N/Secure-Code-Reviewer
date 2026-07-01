/**
 * Frontend Configuration
 * Central configuration for the React application
 */

const config = {
  // API configuration
  api: {
    baseURL: import.meta.env.VITE_API_URL || '/api',
    timeout: 60000, // 60 seconds (AI processing can take time)
  },

  // Supported programming languages
  languages: [
    { value: 'javascript', label: 'JavaScript', icon: '🟨' },
    { value: 'typescript', label: 'TypeScript', icon: '🔷' },
    { value: 'python', label: 'Python', icon: '🐍' },
    { value: 'java', label: 'Java', icon: '☕' },
    { value: 'php', label: 'PHP', icon: '🐘' },
    { value: 'csharp', label: 'C#', icon: '🔷' },
    { value: 'ruby', label: 'Ruby', icon: '💎' },
    { value: 'go', label: 'Go', icon: '🔵' },
  ],

  // Severity levels configuration
  severity: {
    critical: {
      color: 'critical',
      bgColor: 'bg-critical-50',
      textColor: 'text-critical-700',
      borderColor: 'border-critical-500',
      icon: '🔴',
    },
    high: {
      color: 'high',
      bgColor: 'bg-high-50',
      textColor: 'text-high-700',
      borderColor: 'border-high-500',
      icon: '🟠',
    },
    medium: {
      color: 'medium',
      bgColor: 'bg-medium-50',
      textColor: 'text-medium-700',
      borderColor: 'border-medium-500',
      icon: '🟡',
    },
    low: {
      color: 'low',
      bgColor: 'bg-low-50',
      textColor: 'text-low-700',
      borderColor: 'border-low-500',
      icon: '🔵',
    },
  },

  // Monaco Editor configuration
  editor: {
    theme: 'vs-dark',
    options: {
      fontSize: 14,
      lineNumbers: 'on',
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      automaticLayout: true,
      tabSize: 2,
      wordWrap: 'on',
    },
  },

  // Code examples/placeholders for each language
  examples: {
    javascript: `// Paste your JavaScript code here to analyze...
// Example:
// function checkUser(id) {
//   const query = "SELECT * FROM users WHERE id = '" + id + "'";
//   db.execute(query);
// }
`,
    typescript: `// Paste your TypeScript code here to analyze...
// Example:
// function checkUser(id: string) {
//   const query = "SELECT * FROM users WHERE id = '" + id + "'";
//   db.execute(query);
// }
`,
    python: `# Paste your Python code here to analyze...
# Example:
# def check_user(user_id):
#     query = f"SELECT * FROM users WHERE id = '{user_id}'"
#     db.execute(query)
`,
    java: `// Paste your Java code here to analyze...
// Example:
// public void checkUser(String id) {
//     String query = "SELECT * FROM users WHERE id = '" + id + "'";
//     statement.executeQuery(query);
// }
`,
    php: `<?php
// Paste your PHP code here to analyze...
// Example:
// $id = $_GET['id'];
// $query = "SELECT * FROM users WHERE id = " . $id;
// mysql_query($query);
?>`,
    csharp: `// Paste your C# code here to analyze...
// Example:
// public void CheckUser(string id) {
//     string query = "SELECT * FROM users WHERE id = '" + id + "'";
//     SqlCommand cmd = new SqlCommand(query);
// }
`,
    ruby: `# Paste your Ruby code here to analyze...
# Example:
# def check_user(id)
#   User.where("id = '#{id}'")
# end
`,
    go: `package main

// Paste your Go code here to analyze...
// Example:
// func checkUser(id string) {
//     query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
//     db.Query(query)
// }
`,
  },
};

export default config;
