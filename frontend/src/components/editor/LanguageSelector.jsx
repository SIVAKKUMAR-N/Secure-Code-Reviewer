import React from 'react';
import { Code2 } from 'lucide-react';
import config from '../../config';

/**
 * LanguageSelector Component
 * Dropdown to select programming language
 */

const LanguageSelector = ({ value, onChange }) => {
  return (
    <div className="flex items-center gap-3">
      <label className="flex items-center gap-2 text-sm font-medium text-gray-400">
        <Code2 className="text-primary-400" size={18} />
        <span>Language:</span>
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-gray-800 border border-gray-700 text-white rounded-lg px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-primary-500 cursor-pointer min-w-[160px] transition-all duration-200"
        style={{ backgroundColor: '#1f2937', color: '#ffffff' }}
      >
        {config.languages.map((lang) => (
          <option
            key={lang.value}
            value={lang.value}
            className="bg-gray-800 text-white"
            style={{ backgroundColor: '#1f2937', color: '#ffffff' }}
          >
            {lang.icon} {lang.label}
          </option>
        ))}
      </select>
    </div>
  );
};

export default LanguageSelector;

