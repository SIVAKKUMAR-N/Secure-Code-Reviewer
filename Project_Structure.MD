# Secure Code Reviewer - Project Structure

## Overview
AI-powered web application for detecting security vulnerabilities in source code with real-time scanning, severity scoring, and secure fix suggestions.

## Tech Stack
- **Frontend**: React 18, TailwindCSS, Monaco Editor
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **AI**: Gemini API / OpenAI API
- **PDF**: PDFKit

---

## Folder Structure

```
Secure Code reviewer/
├── backend/                        # Backend Node.js application
│   ├── src/
│   │   ├── config/                # Configuration files
│   │   │   ├── database.js        # MongoDB connection config
│   │   │   ├── ai.config.js       # AI API keys and settings
│   │   │   └── app.config.js      # General app configuration
│   │   │
│   │   ├── controllers/           # Request handlers
│   │   │   ├── scanController.js  # Handles code scanning requests
│   │   │   └── reportController.js# Handles report generation
│   │   │
│   │   ├── middleware/            # Express middleware
│   │   │   ├── validator.js       # Input validation
│   │   │   ├── rateLimiter.js     # Rate limiting
│   │   │   └── errorHandler.js    # Global error handler
│   │   │
│   │   ├── models/                # MongoDB schemas
│   │   │   ├── Scan.js            # Scan session model
│   │   │   └── Vulnerability.js   # Vulnerability finding model
│   │   │
│   │   ├── routes/                # API routes
│   │   │   ├── scanRoutes.js      # /api/scan routes
│   │   │   ├── reportRoutes.js    # /api/report routes
│   │   │   └── index.js           # Main router
│   │   │
│   │   ├── services/              # Business logic layer
│   │   │   ├── ai/                # AI service layer
│   │   │   │   ├── gemini.js      # Gemini API integration
│   │   │   │   ├── openai.js      # OpenAI API integration
│   │   │   ├── prompts.js         # AI prompt templates
│   │   │   │   ├── index.js       # AI service interface
│   │   │   │   ├── test-gemini-connection.js
│   │   │   │   ├── test-parser.js
│   │   │   │   └── test-python-enrichment.js
│   │   │   └── scanner/           # Scanner engine
│   │   │       ├── index.js       # Main scanner orchestrator
│   │   │       ├── test-all-categories.js
│   │   │       ├── test-ast-detection.js
│   │   │       ├── test-multi-language.js
│   │   │       └── test-python-scanner.js
│   │   │       ├── ast/
│   │   │       │   ├── parser.js
│   │   │       │   ├── traversal.js
│   │   │       │   ├── detectors/
│   │   │       │   └── utils/
│   │   │       └── regex/
│   │   │           ├── regexScanner.js
│   │   │           ├── patterns.js
│   │   │           ├── detectors/
│   │   │           └── utils/
│   │   │
│   │   ├── utils/                 # Utility functions
│   │   │   ├── logger.js          # Logging utility
│   │   │   ├── pdfGenerator.js    # PDF report generation
│   │   │   └── owaspMapper.js     # OWASP Top 10 mapping
│   │   │
│   │   └── app.js                 # Express app setup
│   │
│   ├── tests/                     # Unit and integration tests
│   │   ├── api.test.js
│   │   └── scanner.test.js
│   │
│   ├── .env
│   ├── .env.example               # Environment variables template
│   ├── .gitignore
│   ├── package-lock.json
│   ├── package.json
│   └── server.js                  # Entry point
│
├── frontend/                      # React frontend application
│   ├── public/
│   │   └── index.html
│   │
│   ├── src/
│   │   ├── components/            # React components
│   │   │   ├── editor/
│   │   │   │   ├── CodeEditor.jsx    # Monaco editor wrapper
│   │   │   │   └── LanguageSelector.jsx
│   │   │   │
│   │   │   ├── dashboard/
│   │   │   │   ├── Dashboard.jsx     # Main dashboard
│   │   │   │   ├── ScanResults.jsx   # Results display
│   │   │   │   ├── VulnerabilityCard.jsx
│   │   │   │   └── StatisticsPanel.jsx
│   │   │   │
│   │   │   └── report/
│   │   │       ├── ReportViewer.jsx  # PDF report viewer
│   │   │       └── ExportButton.jsx
│   │   │
│   │   ├── services/              # Frontend services
│   │   │   ├── api.js             # API client
│   │   │   └── storage.js         # Local storage utils
│   │   │
│   │   ├── utils/                 # Utility functions
│   │   │   ├── formatters.js      # Data formatters
│   │   │   └── validators.js      # Input validation
│   │   │
│   │   ├── styles/                # Global styles
│   │   │   └── index.css          # Tailwind imports
│   │   │
│   │   ├── App.jsx                # Main App component
│   │   ├── config.js              # Frontend config
│   │   ├── index.js               # React entry point
│   │   └── index.jsx
│   │
│   ├── .env
│   │
│   ├── .env.example
│   ├── .gitignore
│   ├── package-lock.json
│   ├── package.json
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   └── vite.config.js             # Vite bundler config
│
├── docs/                          # Documentation
│   ├── API.md                     # API documentation
│   ├── DEPLOYMENT.md              # Deployment guide
│   └── ARCHITECTURE.md            # Architecture details
│
├── .gitignore
└── Project_Structure.MD
```

---

## Component Responsibilities

### Backend Architecture

#### Scanner Engine (`services/scanner/`)
**Purpose**: Core vulnerability detection using both AST and regex analysis

**Components**:
- `index.js`: Orchestrates scanner execution and combines AST/regex findings
- `ast/`: Language-aware parsing and traversal logic
- `ast/parser.js`: Builds ASTs from source code
- `ast/traversal.js`: Walks AST nodes to identify risky patterns
- `ast/detectors/`: AST-based vulnerability detectors
- `regex/`: Pattern-based scanning for code snippets
- `regex/regexScanner.js`: Runs regex detectors against source code
- `regex/patterns.js`: Regex patterns for vulnerability detection
- `regex/detectors/`: Regex detector modules
- `utils/`: Scanner helper utilities

**How it works**:
1. Receives code and language from controller
2. Parses code into an AST when supported
3. Runs AST detectors and regex detectors
4. Each detector returns findings with line numbers and severity
5. Aggregates results and applies enrichment
6. Returns structured vulnerability data

#### AI Service (`services/ai/`)
**Purpose**: Enhance findings with AI-generated explanations and fixes

**Components**:
- `index.js`: Abstraction layer, provider-agnostic interface
- `gemini.js`: Google Gemini API integration
- `openai.js`: OpenAI GPT integration
- `prompts.js`: Carefully crafted prompts for consistent output

**How it works**:
1. Receives vulnerability finding from scanner
2. Constructs context-aware prompt with code snippet
3. Calls AI API (Gemini or OpenAI based on config)
4. Parses AI response into structured format
5. Returns explanation, secure fix, and OWASP mapping

### Frontend Architecture

#### Editor Component (`components/editor/`)
- Monaco Editor integration for syntax highlighting
- Language selection dropdown
- Line number highlighting for vulnerabilities
- Real-time validation

#### Dashboard Component (`components/dashboard/`)
- Overview statistics (total vulns, severity breakdown)
- Interactive vulnerability cards
- Filtering and sorting capabilities
- Export functionality

---

## Data Flow

### Scan Request Flow
```
1. User pastes code in Monaco Editor
2. Frontend validates input
3. POST /api/scan with { code, language }
4. Backend middleware validates request
5. Scanner Engine runs detectors
6. AI Service generates explanations
7. Results saved to MongoDB
8. Response sent to frontend
9. Dashboard displays results
```

### Vulnerability Detection Flow
```
1. Scanner receives code
2. Tokenizes/parses based on language
3. Runs regex patterns against code
4. Checks for dangerous functions
5. Analyzes data flow patterns
6. Calculates severity score
7. Generates finding object
8. AI enriches with explanation
9. Returns complete vulnerability report
```

---

## Security Considerations

### Backend Security
- **Input validation**: All user input sanitized
- **Rate limiting**: Prevents abuse (10 requests/min per IP)
- **API key protection**: Environment variables only
- **Error handling**: No sensitive data in error messages
- **CORS**: Configured for frontend domain only

### Frontend Security
- **Content Security Policy**: Strict CSP headers
- **XSS prevention**: React's built-in escaping
- **HTTPS only**: All API calls over HTTPS
- **No secrets in client**: API calls proxied through backend

---

## Database Schema

### Scan Collection
```javascript
{
  _id: ObjectId,
  code: String,           // Submitted code
  language: String,       // Programming language
  timestamp: Date,
  vulnerabilities: [      // Array of findings
    {
      type: String,
      severity: String,   // Critical, High, Medium, Low
      line: Number,
      column: Number,
      snippet: String,
      message: String,
      aiExplanation: String,
      secureFix: String,
      owaspCategory: String,
      attackExample: String
    }
  ],
  summary: {
    total: Number,
    critical: Number,
    high: Number,
    medium: Number,
    low: Number
  }
}
```

---

## Development Workflow

### Backend Development
```bash
cd backend
npm install
cp .env.example .env
# Add your API keys to .env
npm run dev     # Starts with nodemon
npm test        # Runs tests
```

### Frontend Development
```bash
cd frontend
npm install
cp .env.example .env
npm run dev     # Starts Vite dev server
npm run build   # Production build
```

---

## Deployment Checklist

- [ ] Environment variables configured
- [ ] MongoDB connection string added
- [ ] AI API keys added
- [ ] CORS origins updated
- [ ] Rate limiting configured
- [ ] Frontend built for production
- [ ] Backend process manager (PM2)
- [ ] SSL certificates installed
- [ ] Domain DNS configured
- [ ] Error logging enabled

---

## Next Steps

1. **Backend Setup** - Install dependencies, configure database
2. **Scanner Engine** - Implement detection rules
3. **AI Integration** - Connect Gemini/OpenAI API
4. **Frontend Setup** - Initialize React app
5. **Integration** - Connect frontend to backend
6. **Testing** - Unit and integration tests
7. **Documentation** - API docs and user guide
8. **Deployment** - Production deployment