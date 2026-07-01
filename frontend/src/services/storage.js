/**
 * Storage Service
 * Handles persistence of scans and settings in localStorage
 */

const KEYS = {
  RECENT_SCANS: 'scr_recent_scans',
  DEFAULT_LANGUAGE: 'scr_default_language',
};

const storageService = {
  /**
   * Save scan result to history
   * @param {Object} scan - Scan object
   */
  saveScan: (scan) => {
    try {
      const scans = storageService.getRecentScans();
      // Avoid duplicate scans in local history
      const filtered = scans.filter(s => s.scanId !== scan.scanId);
      
      const scanMeta = {
        scanId: scan.scanId,
        language: scan.language,
        summary: scan.summary,
        scanDuration: scan.scanDuration,
        timestamp: scan.timestamp || new Date().toISOString(),
        vulnerabilitiesCount: scan.vulnerabilities ? scan.vulnerabilities.length : 0,
      };
      
      const updated = [scanMeta, ...filtered].slice(0, 10); // Keep last 10 scans
      localStorage.setItem(KEYS.RECENT_SCANS, JSON.stringify(updated));
      return updated;
    } catch (e) {
      console.error('Error saving scan to local storage:', e);
      return [];
    }
  },

  /**
   * Get all recent scans from history
   * @returns {Array} Scan list
   */
  getRecentScans: () => {
    try {
      const data = localStorage.getItem(KEYS.RECENT_SCANS);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      console.error('Error retrieving scans from local storage:', e);
      return [];
    }
  },

  /**
   * Clear all scan history
   */
  clearHistory: () => {
    localStorage.removeItem(KEYS.RECENT_SCANS);
  },

  /**
   * Save default language preference
   * @param {string} lang - Selected language
   */
  saveDefaultLanguage: (lang) => {
    localStorage.setItem(KEYS.DEFAULT_LANGUAGE, lang);
  },

  /**
   * Get default language preference
   * @returns {string|null} Language value
   */
  getDefaultLanguage: () => {
    return localStorage.getItem(KEYS.DEFAULT_LANGUAGE);
  }
};

export default storageService;
