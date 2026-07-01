import React, { useState } from 'react';
import { Eye, X, Loader } from 'lucide-react';
import apiService from '../../services/api';

/**
 * ReportViewer Component
 * Renders an inline modal showing the PDF report preview
 */
const ReportViewer = ({ scanId }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  if (!scanId) return null;

  const previewUrl = apiService.getReportPreviewUrl(scanId);

  return (
    <>
      <button
        onClick={() => {
          setIsOpen(true);
          setIsLoading(true);
        }}
        className="btn-primary flex items-center justify-center gap-2"
      >
        <Eye size={18} />
        <span>Preview Report</span>
      </button>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-5xl h-[85vh] bg-gray-900 border border-gray-700 rounded-xl overflow-hidden shadow-2xl flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950">
              <h3 className="text-lg font-semibold text-white">Security Report Preview</h3>
              <button
                onClick={() => setIsOpen(false)}
                className="text-gray-400 hover:text-white hover:bg-gray-800 p-2 rounded-lg transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Frame Content */}
            <div className="flex-1 bg-gray-950 relative">
              {isLoading && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-950 text-white">
                  <div className="flex flex-col items-center gap-3">
                    <Loader size={36} className="animate-spin text-primary-500" />
                    <p className="text-sm text-gray-400">Loading report viewer...</p>
                  </div>
                </div>
              )}
              <iframe
                src={previewUrl}
                title="Security Report Preview"
                className="w-full h-full border-none bg-white"
                onLoad={() => setIsLoading(false)}
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default ReportViewer;
