const mongoose = require('mongoose');

/**
 * Vulnerability Schema
 * Represents a single security vulnerability finding
 */
const vulnerabilitySchema = new mongoose.Schema({
  // Vulnerability type (e.g., SQL Injection, XSS)
  type: {
    type: String,
    required: true,
    index: true,
  },

  // Severity level
  severity: {
    type: String,
    required: true,
    enum: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    index: true,
  },

  // Location in code
  line: {
    type: Number,
    required: true,
  },
  column: {
    type: Number,
    default: 0,
  },

  // Code context
  snippet: {
    type: String,
    required: true,
  },

  // Detection details
  message: {
    type: String,
    required: true,
  },
  pattern: {
    type: String, // The regex pattern that matched
  },
  confidence: {
    type: Number, // 0-100 confidence score
    default: 80,
  },

  // AI-generated content
  aiExplanation: {
    type: String,
    default: '',
  },
  secureFix: {
    type: String,
    default: '',
  },
  attackExample: {
    type: String,
    default: '',
  },

  // OWASP mapping
  owaspCategory: {
    type: String,
    index: true,
  },

  // CWE (Common Weakness Enumeration) ID
  cweId: {
    type: String,
  },
});

/**
 * Scan Schema
 * Represents a complete code scan session
 */
const scanSchema = new mongoose.Schema(
  {
    // Submitted code
    code: {
      type: String,
      required: true,
    },

    // Programming language
    language: {
      type: String,
      required: true,
      index: true,
    },

    // Scan metadata
    scanDuration: {
      type: Number, // milliseconds
      default: 0,
    },
    
    // Array of vulnerabilities found
    vulnerabilities: [vulnerabilitySchema],

    // Summary statistics
    summary: {
      total: { type: Number, default: 0 },
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
    },

    // AI provider used
    aiProvider: {
      type: String,
      enum: ['gemini', 'openai', 'none'],
      default: 'none',
    },

    // User information (optional, for future auth)
    userId: {
      type: String,
      index: true,
    },

    // IP address for rate limiting
    ipAddress: {
      type: String,
    },
  },
  {
    // Automatic timestamps
    timestamps: true,
  }
);

// Indexes for query performance
scanSchema.index({ createdAt: -1 });
scanSchema.index({ 'summary.total': -1 });
scanSchema.index({ language: 1, createdAt: -1 });

// Pre-save hook to calculate summary
scanSchema.pre('save', function (next) {
  if (this.isModified('vulnerabilities')) {
    this.summary = {
      total: this.vulnerabilities.length,
      critical: this.vulnerabilities.filter(v => v.severity === 'Critical').length,
      high: this.vulnerabilities.filter(v => v.severity === 'High').length,
      medium: this.vulnerabilities.filter(v => v.severity === 'Medium').length,
      low: this.vulnerabilities.filter(v => v.severity === 'Low').length,
      info: this.vulnerabilities.filter(v => v.severity === 'Info').length,
    };
  }
  next();
});

// Instance method to get severity breakdown
scanSchema.methods.getSeverityBreakdown = function () {
  return {
    critical: this.summary.critical,
    high: this.summary.high,
    medium: this.summary.medium,
    low: this.summary.low,
    info: this.summary.info,
  };
};

// Local cache for in-memory scans (e.g. if DB is offline)
const inMemoryCache = new Map();

// Save in cache (limit to 100 scans to avoid memory leak)
scanSchema.statics.saveInMemory = function(scan) {
  if (inMemoryCache.size >= 100) {
    // Delete oldest entry (Map keeps insertion order)
    const firstKey = inMemoryCache.keys().next().value;
    inMemoryCache.delete(firstKey);
  }
  inMemoryCache.set(scan._id.toString(), scan);
};

scanSchema.statics.findInMemory = function(id) {
  return inMemoryCache.get(id.toString());
};

// Keep track of recent scans in-memory
scanSchema.statics.getRecentFromMemory = function(limit = 10) {
  const values = Array.from(inMemoryCache.values());
  return values
    .sort((a, b) => {
      const aTime = a.createdAt ? a.createdAt.getTime() : 0;
      const bTime = b.createdAt ? b.createdAt.getTime() : 0;
      return bTime - aTime;
    })
    .slice(0, limit)
    .map(scan => {
      const obj = scan.toObject ? scan.toObject() : scan;
      const { code, ...rest } = obj;
      return rest;
    });
};

// Static method to get recent scans
scanSchema.statics.getRecentScans = function (limit = 10) {
  return this.find()
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('-code') // Exclude code for privacy
    .exec();
};

const Scan = mongoose.model('Scan', scanSchema);

module.exports = Scan;