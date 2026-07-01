import axios from 'axios';
import config from '../config';

/**
 * API Service
 * Handles all HTTP requests to the backend API
 */

// Create axios instance with default config
const api = axios.create({
  baseURL: config.api.baseURL,
  timeout: config.api.timeout,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add request timestamp for logging
    config.metadata = { startTime: new Date() };
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    // Log request duration
    const duration = new Date() - response.config.metadata.startTime;
    console.log(`API ${response.config.method.toUpperCase()} ${response.config.url} - ${duration}ms`);
    return response;
  },
  (error) => {
    // Handle errors
    if (error.response) {
      // Server responded with error status
      console.error('API Error:', error.response.data);
    } else if (error.request) {
      // Request made but no response
      console.error('Network Error:', error.message);
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

/**
 * API Methods
 */

const apiService = {
  /**
   * Scan code for vulnerabilities
   * @param {string} code - Source code to scan
   * @param {string} language - Programming language
   * @returns {Promise} Scan results
   */
  scanCode: async (code, language) => {
    const response = await api.post('/scan', { code, language });
    return response.data;
  },

  /**
   * Get scan result by ID
   * @param {string} scanId - Scan ID
   * @returns {Promise} Scan result
   */
  getScan: async (scanId) => {
    const response = await api.get(`/scan/${scanId}`);
    return response.data;
  },

  /**
   * Get recent scans
   * @param {number} limit - Number of scans to retrieve
   * @returns {Promise} Recent scans
   */
  getRecentScans: async (limit = 10) => {
    const response = await api.get(`/scan/list/recent?limit=${limit}`);
    return response.data;
  },

  /**
   * Get statistics
   * @returns {Promise} Statistics
   */
  getStatistics: async () => {
    const response = await api.get('/scan/list/stats');
    return response.data;
  },

  /**
   * Get available detectors
   * @returns {Promise} Detector information
   */
  getDetectors: async () => {
    const response = await api.get('/scan/info/detectors');
    return response.data;
  },

  /**
   * Generate PDF report
   * @param {string} scanId - Scan ID
   * @returns {Promise} Blob
   */
  generateReport: async (scanId) => {
    const response = await api.get(`/report/${scanId}`, {
      responseType: 'blob',
    });
    return response.data;
  },

  /**
   * Get report preview URL
   * @param {string} scanId - Scan ID
   * @returns {string} Preview URL
   */
  getReportPreviewUrl: (scanId) => {
    return `${config.api.baseURL}/report/${scanId}/preview`;
  },

  /**
   * Health check
   * @returns {Promise} Health status
   */
  healthCheck: async () => {
    const response = await api.get('/health');
    return response.data;
  },
};

export default apiService;

