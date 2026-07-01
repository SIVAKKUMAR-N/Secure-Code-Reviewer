const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const appConfig = require('./config/app.config');
const logger = require('./utils/logger');
const routes = require('./routes');
const { apiLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

/**
 * Express Application Setup
 * Configures middleware, routes, and error handling
 */

const app = express();

// ==================== SECURITY MIDDLEWARE ====================

/**
 * Helmet - Sets various HTTP headers for security
 * Protects against common web vulnerabilities
 */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

/**
 * CORS - Cross-Origin Resource Sharing
 * Configure allowed origins for frontend access
 */
app.use(cors({
  origin: appConfig.cors.origins,
  credentials: appConfig.cors.credentials,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ==================== BODY PARSING MIDDLEWARE ====================

/**
 * Parse JSON bodies (limit: 10MB for code submissions)
 */
app.use(express.json({ limit: '10mb' }));

/**
 * Parse URL-encoded bodies
 */
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== COMPRESSION ====================

/**
 * Compress all responses
 * Reduces bandwidth usage and improves performance
 */
app.use(compression());

// ==================== LOGGING MIDDLEWARE ====================

/**
 * HTTP request logging with Morgan
 * Different formats for development and production
 */
if (appConfig.env === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', { stream: logger.stream }));
}

// ==================== RATE LIMITING ====================

/**
 * Apply rate limiting to all API routes
 * Prevents abuse and DOS attacks
 */
app.use('/api', apiLimiter);
app.set('trust proxy', 1);
// ==================== CUSTOM MIDDLEWARE ====================

/**
 * Request ID middleware
 * Adds unique ID to each request for tracking
 */
app.use((req, res, next) => {
  req.id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  res.setHeader('X-Request-ID', req.id);
  next();
});

/**
 * Request timing middleware
 * Logs request duration
 */
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.debug(`${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
});

// ==================== API ROUTES ====================

/**
 * Root endpoint
 */
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Welcome to Secure Code Reviewer API',
    version: '1.0.0',
    documentation: '/api/info',
  });
});

/**
 * Mount API routes
 */
app.use('/api', routes);

// ==================== ERROR HANDLING ====================

/**
 * 404 handler - Route not found
 * Must be after all valid routes
 */
app.use(notFoundHandler);

/**
 * Global error handler
 * Must be the last middleware
 */
app.use(errorHandler);

// ==================== GRACEFUL SHUTDOWN ====================

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  logger.error('UNCAUGHT EXCEPTION! Shutting down...');
  logger.error(error);
  process.exit(1);
});

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (error) => {
  logger.error('UNHANDLED REJECTION! Shutting down...');
  logger.error(error);
  process.exit(1);
});

module.exports = app;
