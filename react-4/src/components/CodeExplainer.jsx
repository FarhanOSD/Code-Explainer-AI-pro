
import { useState, useEffect } from 'react';
import { axiosInstance, setAuthToken } from '../components/api';

const CodeExplainer = ({ token }) => {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('JavaScript');
  const [explanation, setExplanation] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setAuthToken(token);
  }, [token]);

  const handleExplain = async () => {
    if (!code.trim()) {
      setExplanation('Please enter some code to explain.');
      return;
    }
    setLoading(true);
    setExplanation('');
    try {
      const res = await axiosInstance.post('/api/explain-code', {
        code,
        language,
      });
      setExplanation(res.data.explanation);
    } catch (err) {
      setExplanation(err.response?.data?.error || 'Error explaining code');
    } finally {
      setLoading(false);
    }
  };

  const languages = [
    'JavaScript',
    'Python',
    'Java',
    'C++',
    'C#',
    'Ruby',
    'Go',
    'Rust',
    'PHP',
    'TypeScript',
    'Swift',
    'Kotlin',
  ];

  return (
    <div className="main-card">
      <div className="input-group">
        <label className="label">Programming Language</label>
        <select
          className="select-input"
          value={language}
          onChange={e => setLanguage(e.target.value)}
        >
          {languages.map(lang => (
            <option key={lang} value={lang}>
              {lang}
            </option>
          ))}
        </select>
      </div>

      <div className="input-group">
        <label className="label">Your Code</label>
        <textarea
          className="textarea-input"
          placeholder="Paste your code here..."
          value={code}
          onChange={e => setCode(e.target.value)}
          onKeyDown={e => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
              handleExplain();
            }
          }}
        />
      </div>

      <button className="btn" onClick={handleExplain} disabled={loading}>
        {loading ? 'Explaining...' : 'Explain Code'}
      </button>

      {loading && (
        <div className="loading">
          <div className="loading-dot"></div>
          <div className="loading-dot"></div>
          <div className="loading-dot"></div>
        </div>
      )}

      {explanation && (
        <div className="result-card">
          <div className="result-header">
            <div className="result-title">💡 Explanation ({language})</div>
          </div>
          <div className="result-content">{explanation}</div>
        </div>
      )}
    </div>
  );
};

export default CodeExplainer;


