import React from 'react';
import { Shield, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import clsx from 'clsx';

/**
 * StatisticsPanel Component
 * Displays summary statistics of vulnerabilities
 */

const StatisticsPanel = ({ summary }) => {
  const stats = [
    {
      label: 'Critical',
      value: summary.critical || 0,
      icon: AlertTriangle,
      color: 'critical',
      bgColor: 'bg-critical-50',
      textColor: 'text-critical-700',
      iconColor: 'text-critical-600',
    },
    {
      label: 'High',
      value: summary.high || 0,
      icon: AlertCircle,
      color: 'high',
      bgColor: 'bg-high-50',
      textColor: 'text-high-700',
      iconColor: 'text-high-600',
    },
    {
      label: 'Medium',
      value: summary.medium || 0,
      icon: AlertCircle,
      color: 'medium',
      bgColor: 'bg-medium-50',
      textColor: 'text-medium-700',
      iconColor: 'text-medium-600',
    },
    {
      label: 'Low',
      value: summary.low || 0,
      icon: Info,
      color: 'low',
      bgColor: 'bg-low-50',
      textColor: 'text-low-700',
      iconColor: 'text-low-600',
    },
  ];

  const totalVulnerabilities = summary.total || 0;
  const riskLevel = getRiskLevel(summary);

  return (
    <div className="space-y-4">
      {/* Overall Summary */}
      <div className="card bg-gradient-to-br from-primary-600 to-primary-700 text-white">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm opacity-90 mb-1">Total Vulnerabilities</p>
            <h2 className="text-4xl font-bold">{totalVulnerabilities}</h2>
          </div>
          <Shield size={48} className="opacity-50" />
        </div>
        <div className="mt-4 pt-4 border-t border-white/20">
          <div className="flex items-center justify-between">
            <span className="text-sm opacity-90">Risk Level</span>
            <span className={clsx(
              'px-3 py-1 rounded-full text-xs font-semibold',
              getRiskLevelStyle(riskLevel)
            )}>
              {riskLevel}
            </span>
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div 
              key={stat.label}
              className={clsx('card', stat.bgColor)}
            >
              <div className="flex items-center justify-between mb-2">
                <Icon size={24} className={stat.iconColor} />
                <span className={clsx('text-2xl font-bold', stat.textColor)}>
                  {stat.value}
                </span>
              </div>
              <p className={clsx('text-sm font-medium', stat.textColor)}>
                {stat.label}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};

/**
 * Calculate risk level based on vulnerability counts
 */
const getRiskLevel = (summary) => {
  const score = (summary.critical || 0) * 40 + 
                (summary.high || 0) * 25 + 
                (summary.medium || 0) * 10 + 
                (summary.low || 0) * 5;
  
  if (score >= 100) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 20) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'SECURE';
};

/**
 * Get risk level styling
 */
const getRiskLevelStyle = (level) => {
  const styles = {
    'CRITICAL': 'bg-critical-100 text-critical-700',
    'HIGH': 'bg-high-100 text-high-700',
    'MEDIUM': 'bg-medium-100 text-medium-700',
    'LOW': 'bg-low-100 text-low-700',
    'SECURE': 'bg-success-100 text-success-700',
  };
  return styles[level] || styles.SECURE;
};

export default StatisticsPanel;

