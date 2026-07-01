import React, { useState, useEffect } from 'react';
import { Shield, History, PlusCircle, Trash2, CheckCircle2, AlertCircle } from 'lucide-react';
import { Toaster, toast } from 'react-hot-toast';
import apiService from './services/api';
import storageService from './services/storage';
import Dashboard from './components/dashboard/Dashboard';

/**
 * App Layout Container
 * Manages side drawer cache history, connection health status, and active selection state.
 */
function App() {
  const [activeScan, setActiveScan] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [backendHealth, setBackendHealth] = useState('checking'); // checking, healthy, unhealthy

  useEffect(() => {
    // 1. Check API Health
    const checkHealth = async () => {
      try {
        await apiService.healthCheck();
        setBackendHealth('healthy');
      } catch (err) {
        console.error('Backend health check failed:', err);
        setBackendHealth('unhealthy');
        toast.error('Cannot connect to the backend server. Please verify it is running.');
      }
    };

    checkHealth();

    // 2. Load recent scans from localStorage cache
    const cachedScans = storageService.getRecentScans();
    setRecentScans(cachedScans);
  }, []);

  // Handler for when a scan completes
  const handleScanComplete = (scanResult) => {
    const updatedHistory = storageService.saveScan(scanResult);
    setRecentScans(updatedHistory);
    setActiveScan(scanResult);
  };

  // Load a historical scan from sidebar
  const loadHistoricalScan = async (scanId) => {
    const toastId = toast.loading('Retrieving scan details...');
    try {
      const scanData = await apiService.getScan(scanId);
      if (scanData && scanData.success) {
        setActiveScan(scanData.data);
        toast.success('Loaded past scan results', { id: toastId });
      } else {
        throw new Error('Scan not found');
      }
    } catch (error) {
      console.error('Error loading historical scan:', error);
      toast.error('Failed to load past scan from server', { id: toastId });
    }
  };

  const handleClearHistory = () => {
    if (window.confirm('Are you sure you want to clear scan history?')) {
      storageService.clearHistory();
      setRecentScans([]);
      toast.success('Scan history cleared');
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-950 text-gray-100 font-sans">
      <Toaster position="top-right" reverseOrder={false} />

      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 bg-gray-900 border-b border-gray-800 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary-900/50 border border-primary-500/30 rounded-lg text-primary-500">
            <Shield size={28} className="animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-gray-200 to-primary-400">
              ShieldAI
            </h1>
            <p className="text-xs text-gray-400 font-mono">Secure Code Reviewer</p>
          </div>
        </div>

        {/* Backend health indicator */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400 hidden sm:inline">Backend Status:</span>
          {backendHealth === 'checking' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-800 text-gray-300">
              <span className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-pulse"></span>
              Checking...
            </span>
          )}
          {backendHealth === 'healthy' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-success-900/30 text-success-500 border border-success-500/20">
              <CheckCircle2 size={12} />
              Online
            </span>
          )}
          {backendHealth === 'unhealthy' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-critical-900/30 text-critical-500 border border-critical-500/20">
              <AlertCircle size={12} />
              Offline
            </span>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-80 bg-gray-900 border-r border-gray-800 flex flex-col hidden lg:flex">
          {/* Action Bar */}
          <div className="p-4 border-b border-gray-800">
            <button
              onClick={() => setActiveScan(null)}
              className="w-full btn-primary flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 border-none py-2.5 shadow-lg shadow-primary-900/20 text-white font-semibold transition-all"
            >
              <PlusCircle size={18} />
              <span>New Security Scan</span>
            </button>
          </div>

          {/* History List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
              <span className="flex items-center gap-1">
                <History size={14} />
                Scan History
              </span>
              {recentScans.length > 0 && (
                <button
                  onClick={handleClearHistory}
                  className="hover:text-critical-500 transition-colors"
                  title="Clear history"
                >
                  <Trash2 size={14} />
                </button>
              )}
            </div>

            {recentScans.length === 0 ? (
              <div className="text-center py-8 px-4 border border-dashed border-gray-800 rounded-lg text-gray-600">
                <p className="text-sm">No recent scans</p>
                <p className="text-xs mt-1 font-mono">Your scanning history will appear here.</p>
              </div>
            ) : (
              recentScans.map((scan) => {
                const isActive = activeScan?.scanId === scan.scanId;
                const riskLevel = scan.summary.critical > 0 ? 'CRITICAL' : scan.summary.high > 0 ? 'HIGH' : scan.summary.medium > 0 ? 'MEDIUM' : scan.summary.low > 0 ? 'LOW' : 'SECURE';
                const riskBadgeStyles = {
                  CRITICAL: 'bg-critical-900/40 text-critical-400 border border-critical-500/20',
                  HIGH: 'bg-high-900/40 text-high-400 border border-high-500/20',
                  MEDIUM: 'bg-medium-900/40 text-medium-400 border border-medium-500/20',
                  LOW: 'bg-low-900/40 text-low-400 border border-low-500/20',
                  SECURE: 'bg-success-900/40 text-success-400 border border-success-500/20',
                };
                
                return (
                  <div
                    key={scan.scanId}
                    onClick={() => loadHistoricalScan(scan.scanId)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 ${
                      isActive
                        ? 'bg-gray-800 border-primary-500/50 shadow-md'
                        : 'bg-gray-950/40 border-gray-800 hover:bg-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <span className="font-mono text-xs text-gray-400 capitalize">
                        {scan.language}
                      </span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${riskBadgeStyles[riskLevel]}`}>
                        {riskLevel}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-gray-500">
                        {new Date(scan.timestamp).toLocaleDateString()}
                      </span>
                      <span className="font-semibold text-gray-300">
                        {scan.vulnerabilitiesCount} issue{scan.vulnerabilitiesCount !== 1 ? 's' : ''}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div className="p-4 border-t border-gray-800 bg-gray-950/40 text-center text-xs text-gray-600 font-mono">
            v1.0.0 • AI-SecEngine v1.0
          </div>
        </aside>

        {/* Workspace Panel */}
        <main className="flex-1 overflow-y-auto bg-gray-950">
          <Dashboard 
            activeScan={activeScan}
            setActiveScan={setActiveScan}
            onScanComplete={handleScanComplete}
            backendHealth={backendHealth}
          />
        </main>
      </div>
    </div>
  );
}

export default App;
