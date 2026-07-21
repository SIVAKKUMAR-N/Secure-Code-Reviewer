import React, { useState } from 'react';
import { Download, Loader } from 'lucide-react';
import apiService from '../../services/api';
import toast from 'react-hot-toast';

/**
 * ExportButton Component
 * Triggers PDF generation and download for a specific scan ID
 */
const ExportButton = ({ scanId }) => {
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    if (!scanId) {
      toast.error('No scan ID found to export');
      return;
    }

    setIsExporting(true);
    const toastId = toast.loading('Generating PDF report...');

    try {
      const blob = await apiService.generateReport(scanId);
      
      // Create download link for the blob
      const url = window.URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `novuln-report-${scanId.slice(-6)}.pdf`);
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success('PDF report downloaded successfully!', { id: toastId });
    } catch (error) {
      console.error('Error exporting PDF:', error);
      toast.error('Failed to generate PDF report. Please try again.', { id: toastId });
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <button
      onClick={handleExport}
      disabled={isExporting}
      className="btn-secondary flex items-center justify-center gap-2 hover:bg-gray-300 disabled:opacity-50 text-gray-800"
    >
      {isExporting ? (
        <>
          <Loader size={18} className="animate-spin text-gray-800" />
          <span>Exporting...</span>
        </>
      ) : (
        <>
          <Download size={18} className="text-gray-800" />
          <span>Export PDF Report</span>
        </>
      )}
    </button>
  );
};

export default ExportButton;
