import React, { useState } from 'react';
import { Filter, Search } from 'lucide-react';
import VulnerabilityCard from './VulnerabilityCard';

/**
 * ScanResults Component
 * Displays list of vulnerabilities with filtering
 */

const ScanResults = ({ vulnerabilities }) => {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Filter vulnerabilities
  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    // Filter by severity
    if (filter !== 'all' && vuln.severity.toLowerCase() !== filter) {
      return false;
    }

    // Filter by search term
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        vuln.type.toLowerCase().includes(term) ||
        vuln.message.toLowerCase().includes(term) ||
        vuln.owaspCategory?.toLowerCase().includes(term)
      );
    }

    return true;
  });

  return (
    <div className="space-y-6">
      {/* Filters and Search */}
      <div className="border border-gray-800 bg-gray-950/40 rounded-xl p-4">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Severity Filter */}
          <div className="flex items-center gap-2 flex-1">
            <Filter size={18} className="text-gray-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-primary-500 cursor-pointer flex-1 transition-all duration-200"
              style={{ backgroundColor: '#1f2937', color: '#ffffff' }}
            >
              <option value="all" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>All Severities</option>
              <option value="critical" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Critical Only</option>
              <option value="high" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>High Only</option>
              <option value="medium" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Medium Only</option>
              <option value="low" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Low Only</option>
            </select>
          </div>

          {/* Search */}
          <div className="flex items-center gap-2 flex-1">
            <Search size={18} className="text-gray-400" />
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-primary-500 flex-1 transition-all duration-200"
              style={{ backgroundColor: '#1f2937', color: '#ffffff' }}
            />
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between text-sm text-gray-400">
          <span>
            Showing {filteredVulnerabilities.length} of {vulnerabilities.length} vulnerabilities
          </span>
          {filter !== 'all' && (
            <button
              onClick={() => setFilter('all')}
              className="text-primary-400 hover:text-primary-300 font-medium"
            >
              Clear filter
            </button>
          )}
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="space-y-4">
        {filteredVulnerabilities.length > 0 ? (
          filteredVulnerabilities.map((vuln, index) => (
            <VulnerabilityCard
              key={index}
              vulnerability={vuln}
              index={index + 1}
            />
          ))
        ) : (
          <div className="border border-gray-800 bg-gray-950/20 text-center py-12 rounded-xl">
            <div className="text-gray-500 mb-4">
              <Filter size={48} className="mx-auto" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">
              No vulnerabilities found
            </h3>
            <p className="text-gray-400">
              {searchTerm || filter !== 'all'
                ? 'Try adjusting your filters'
                : 'Your code appears to be secure!'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanResults;