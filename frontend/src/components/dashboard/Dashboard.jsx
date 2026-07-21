import React, { useState } from 'react';
import { Play, RotateCcw, AlertTriangle, Cpu, Terminal, ShieldAlert } from 'lucide-react';
import CodeEditor from '../editor/CodeEditor';
import LanguageSelector from '../editor/LanguageSelector';
import StatisticsPanel from './StatisticsPanel';
import ScanResults from './ScanResults';
import ExportButton from '../report/ExportButton';
import ReportViewer from '../report/ReportViewer';
import apiService from '../../services/api';
import config from '../../config';
import storageService from '../../services/storage';
import toast from 'react-hot-toast';
import clsx from 'clsx';

/**
 * Dashboard Component
 * Serves as the primary workspace orchestrating Monaco Code Editor, Selector dropdowns,
 * Loading triggers, Scan API calls, Statistics counters, and Export buttons.
 */
const Dashboard = ({ activeScan, setActiveScan, onScanComplete, backendHealth }) => {
  const [language, setLanguage] = useState(() => {
    return storageService.getDefaultLanguage() || 'javascript';
  });
  
  const [code, setCode] = useState(() => {
    return config.examples[language] || '// Paste your source code here to analyze...';
  });

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState('');
  const [error, setError] = useState(null);

  // Update default code template when language changes
  const handleLanguageChange = (newLang) => {
    setLanguage(newLang);
    storageService.saveDefaultLanguage(newLang);
    
    // Check if the current code is empty or matches any of the default placeholder examples
    const isAnyExample = Object.values(config.examples).some(ex => {
      return code.trim().replace(/\s/g, '') === ex.trim().replace(/\s/g, '');
    });
    
    const isGenericPlaceholder = 
      !code.trim() || 
      code.startsWith('// Paste your') || 
      code.startsWith('# Paste your') || 
      code.startsWith('<?php\n// Paste your') || 
      code.startsWith('package main\n\n// Paste your') ||
      code.startsWith('// Paste your source code here') ||
      code.startsWith('// Example vulnerable code');

    if (isAnyExample || isGenericPlaceholder) {
      setCode(config.examples[newLang] || `// Paste your ${newLang} code here to analyze...`);
    }
  };

  // Run the security scan
  const handleScan = async () => {
    if (!code.trim()) {
      toast.error('Please enter some code to scan');
      return;
    }

    if (backendHealth === 'unhealthy') {
      toast.error('Scan service is offline. Please make sure the backend is running.');
      return;
    }

    setIsScanning(true);
    setError(null);
    setScanProgress('Tokenizing source files...');

    const progressSteps = [
      'Tokenizing source files...',
      'Running AST & pattern-matching rules...',
      'Detecting potential OWASP vulnerabilities...',
      'Invoking AI secure engine for fix suggestion...',
      'Saving results to MongoDB...'
    ];

    let stepIndex = 0;
    const progressInterval = setInterval(() => {
      if (stepIndex < progressSteps.length - 1) {
        stepIndex++;
        setScanProgress(progressSteps[stepIndex]);
      }
    }, 1500);

    try {
      const result = await apiService.scanCode(code, language);
      clearInterval(progressInterval);
      
      if (result && result.success) {
        onScanComplete(result.data);
        toast.success(`Scan completed in ${result.data.scanDuration}ms! Found ${result.data.summary.total} vulnerabilities.`);
      } else {
        throw new Error(result.error || 'Scan failed');
      }
    } catch (err) {
      clearInterval(progressInterval);
      console.error('Scan Error:', err);
      const apiErrMessage = err.response?.data?.error || err.message || 'Unknown scanning error';
      setError(apiErrMessage);
      toast.error(`Scanning failed: ${apiErrMessage}`);
    } finally {
      setIsScanning(false);
      setScanProgress('');
    }
  };

  // Reset/Start new scan
  const handleReset = () => {
    setActiveScan(null);
    setError(null);
    setCode(config.examples[language] || `// Paste your ${language} code here...`);
  };

  // Lines to highlight in the Monaco editor
  const highlightedLines = activeScan && activeScan.vulnerabilities
    ? activeScan.vulnerabilities.map(v => v.line)
    : [];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top action grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Editor column */}
        <div className={clsx(
          "space-y-4 transition-all duration-300",
          activeScan ? "lg:col-span-6" : "lg:col-span-12"
        )}>
          <div className="card border border-gray-800 bg-gray-900 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Terminal className="text-primary-500" size={20} />
                <h2 className="text-lg font-semibold text-white">Source Code Input</h2>
              </div>
              <LanguageSelector value={language} onChange={handleLanguageChange} />
            </div>

            {/* Monaco Editor Wrapper */}
            <div className="relative border border-gray-800 rounded-lg overflow-hidden">
              <CodeEditor
                value={code}
                onChange={setCode}
                language={language}
                height="500px"
                highlightedLines={highlightedLines}
              />
              
              {/* Scanning loading overlay */}
              {isScanning && (
                <div className="absolute inset-0 bg-gray-950/80 backdrop-blur-sm flex flex-col items-center justify-center text-center p-6 z-10">
                  <div className="relative mb-6">
                    <div className="w-16 h-16 border-2 border-primary-500 rounded-full animate-ping absolute opacity-25"></div>
                    <div className="w-16 h-16 border border-primary-500 rounded-full flex items-center justify-center bg-gray-900">
                      <Cpu size={28} className="text-primary-500 animate-spin" />
                    </div>
                  </div>
                  <h3 className="text-lg font-bold text-white mb-1">Scanning Code...</h3>
                  <p className="text-sm font-mono text-primary-400 h-6">{scanProgress}</p>
                </div>
              )}
            </div>

            {/* Controls Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mt-4 pt-4 border-t border-gray-800">
              <div className="text-xs text-gray-500 font-mono">
                {code.split('\n').length} lines • {code.length} characters
              </div>
              
              <div className="flex items-center gap-3">
                {activeScan && (
                  <button
                    onClick={handleReset}
                    className="btn-secondary flex items-center gap-2 border border-gray-700 bg-gray-850 hover:bg-gray-800 text-gray-300"
                  >
                    <RotateCcw size={16} />
                    <span>Reset Editor</span>
                  </button>
                )}
                <button
                  onClick={handleScan}
                  disabled={isScanning || !code.trim() || backendHealth === 'unhealthy'}
                  className="btn-primary flex items-center gap-2 bg-primary-600 hover:bg-primary-500 shadow-md shadow-primary-900/30 text-white font-semibold"
                >
                  <Play size={16} />
                  <span>{isScanning ? 'Scanning...' : 'Scan Code'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Local Scanning errors */}
          {error && (
            <div className="p-4 bg-critical-950/30 border border-critical-500/20 rounded-xl flex gap-3 text-critical-400">
              <AlertTriangle className="flex-shrink-0 mt-0.5" size={18} />
              <div>
                <h4 className="font-semibold text-sm">Scan Diagnostics Alert</h4>
                <p className="text-xs mt-1 font-mono">{error}</p>
              </div>
            </div>
          )}
        </div>

        {/* Results & Stats Column */}
        {activeScan && (
          <div className="lg:col-span-6 space-y-6">
            
            {/* Action Bar (Export/Preview) */}
            <div className="card border border-gray-800 bg-gray-900 shadow-xl flex flex-wrap items-center justify-between gap-4 p-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="text-high-500" size={20} />
                <span className="text-sm font-semibold text-white">Scan Session Loaded</span>
              </div>
              <div className="flex items-center gap-3">
                <ReportViewer scanId={activeScan.scanId} />
                <ExportButton scanId={activeScan.scanId} />
              </div>
            </div>

            {/* Statistics */}
            <StatisticsPanel summary={activeScan.summary} />

            {/* Vulnerabilities breakdown list */}
            <div className="card border border-gray-800 bg-gray-900 shadow-xl">
              <h3 className="text-md font-bold text-white mb-4">Detected Vulnerabilities</h3>
              <ScanResults vulnerabilities={activeScan.vulnerabilities} />
            </div>

          </div>
        )}
      </div>

      {/* Intro landing panel when no scan has been performed */}
      {!activeScan && !isScanning && (
        <div className="card border border-gray-800 bg-gray-900/50 text-center py-12 px-6 rounded-2xl max-w-2xl mx-auto shadow-xl">
          <div className="w-16 h-16 bg-primary-950/50 border border-primary-500/30 text-primary-500 rounded-full flex items-center justify-center mx-auto mb-4">
            <Cpu size={32} />
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Ready for Security Review</h3>
          <p className="text-gray-400 text-sm leading-relaxed mb-6">
            Paste your source code in the editor above, choose the language template, and click <strong className="text-white">Scan Code</strong>. NoVuln will run hybrid AST + Regex static analysis matching OWASP patterns and leverage AI LLMs to enrich results with secure code fixes and exploit examples.
          </p>
          <div className="flex justify-center gap-8 text-xs font-mono text-gray-500">
            <div>
              <span className="block text-primary-400 text-lg font-bold">8+</span>
              <span>Languages</span>
            </div>
            <div className="border-r border-gray-800"></div>
            <div>
              <span className="block text-high-400 text-lg font-bold">Rule + AI</span>
              <span>Hybrid Scanner</span>
            </div>
            <div className="border-r border-gray-800"></div>
            <div>
              <span className="block text-success-400 text-lg font-bold">OWASP</span>
              <span>Top 10 Mapped</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
