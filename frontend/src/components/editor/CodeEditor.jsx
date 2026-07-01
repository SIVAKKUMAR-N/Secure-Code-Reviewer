import React from 'react';
import Editor from '@monaco-editor/react';
import config from '../../config';

/**
 * CodeEditor Component
 * Monaco-based code editor with syntax highlighting
 */

const CodeEditor = ({ 
  value, 
  onChange, 
  language = 'javascript',
  height = '500px',
  highlightedLines = [],
}) => {
  const handleEditorDidMount = (editor, monaco) => {
    // Configure editor instance
    editor.updateOptions({
      ...config.editor.options,
    });

    // Highlight vulnerable lines if provided
    if (highlightedLines.length > 0) {
      const decorations = highlightedLines.map(line => ({
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: 'highlighted-line',
          glyphMarginClassName: 'highlighted-glyph',
          linesDecorationsClassName: 'highlighted-decoration',
        },
      }));
      
      editor.deltaDecorations([], decorations);
    }
  };

  return (
    <div className="monaco-editor-wrapper">
      <Editor
        height={height}
        language={language}
        value={value}
        onChange={onChange}
        theme={config.editor.theme}
        onMount={handleEditorDidMount}
        options={config.editor.options}
        loading={
          <div className="flex items-center justify-center h-full bg-gray-900">
            <div className="text-white">
              <div className="spinner mb-2"></div>
              <p>Loading editor...</p>
            </div>
          </div>
        }
      />
      
      <style jsx>{`
        .highlighted-line {
          background: rgba(255, 0, 0, 0.1);
        }
        
        .highlighted-glyph {
          background: #dc2626;
          width: 3px !important;
          margin-left: 3px;
        }
        
        .highlighted-decoration {
          background: rgba(220, 38, 38, 0.3);
          width: 5px !important;
        }
      `}</style>
    </div>
  );
};

export default CodeEditor;