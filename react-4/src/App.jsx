import { useState } from 'react';
import Register from './components/Register';
import Login from './components/Login';
import CodeExplainer from './components/CodeExplainer';
import History from './components/History';

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem('token') || null
  );
  const [showLogin, setShowLogin] = useState(true);

  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('token');
  };

  if (!token) {
    return (
      <>
        <style>{`
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }

          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e6ed;
          }

          .auth-container {
            position: relative;
            z-index: 1;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }

          .auth-card {
            background: rgba(26, 32, 53, 0.85);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 50px 40px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(102, 126, 234, 0.2);
            animation: fadeInUp 0.8s ease-out;
          }

          .auth-form {
            width: 100%;
          }

          .form-title {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            margin-bottom: 8px;
          }

          .form-subtitle {
            color: #a0aec0;
            font-size: 0.95rem;
            text-align: center;
            margin-bottom: 30px;
          }

          .form-group {
            margin-bottom: 20px;
          }

          .form-label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.9rem;
            color: #a0aec0;
            font-weight: 500;
          }

          .form-input {
            width: 100%;
            padding: 14px 18px;
            background: rgba(15, 20, 35, 0.9);
            border: 2px solid rgba(102, 126, 234, 0.2);
            border-radius: 12px;
            color: #e0e6ed;
            font-size: 1rem;
            transition: all 0.3s ease;
          }

          .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
          }

          .form-input::placeholder {
            color: #4a5568;
          }

          .auth-btn {
            width: 100%;
            padding: 16px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            margin-top: 10px;
          }

          .auth-btn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
          }

          .auth-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
          }

          .toggle-text {
            text-align: center;
            margin-top: 25px;
            color: #a0aec0;
            font-size: 0.9rem;
          }

          .toggle-link {
            color: #667eea;
            cursor: pointer;
            font-weight: 600;
            transition: color 0.3s;
          }

          .toggle-link:hover {
            color: #764ba2;
          }

          .alert {
            padding: 12px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            animation: fadeInDown 0.4s ease-out;
          }

          .alert-error {
            background: rgba(245, 101, 101, 0.1);
            border: 1px solid rgba(245, 101, 101, 0.3);
            color: #fc8181;
          }

          .alert-success {
            background: rgba(72, 187, 120, 0.1);
            border: 1px solid rgba(72, 187, 120, 0.3);
            color: #68d391;
          }

          .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
          }

          @keyframes fadeInUp {
            from {
              opacity: 0;
              transform: translateY(30px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          @keyframes fadeInDown {
            from {
              opacity: 0;
              transform: translateY(-10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        `}</style>

        
        <div className="auth-container">
          <div className="auth-card">
            {showLogin ? (
              <Login
                setToken={setToken}
                onSwitchToRegister={() => setShowLogin(false)}
              />
            ) : (
              <Register
                setToken={setToken}
                onSwitchToLogin={() => setShowLogin(true)}
              />
            )}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <style>{`
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }

        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: #0a0e27;
          color: #e0e6ed;
        }

        .app-container {
          position: relative;
          z-index: 1;
          min-height: 100vh;
          padding: 40px 20px;
        }

        .header {
          text-align: center;
          margin-bottom: 50px;
          animation: fadeInDown 0.8s ease-out;
        }

        .main-title {
          font-size: 3.5rem;
          font-weight: 700;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-bottom: 10px;
        }

        .logout-btn {
          position: fixed;
          top: 20px;
          right: 20px;
          padding: 12px 24px;
          background: rgba(245, 101, 101, 0.2);
          border: 2px solid rgba(245, 101, 101, 0.4);
          border-radius: 10px;
          color: #fc8181;
          cursor: pointer;
          font-weight: 600;
          transition: all 0.3s ease;
          z-index: 100;
        }

        .logout-btn:hover {
          background: rgba(245, 101, 101, 0.3);
          transform: translateY(-2px);
        }

        .main-card, .history-card {
          background: rgba(26, 32, 53, 0.8);
          backdrop-filter: blur(20px);
          border-radius: 24px;
          padding: 40px;
          max-width: 900px;
          margin: 0 auto 30px;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
          border: 1px solid rgba(102, 126, 234, 0.2);
          animation: fadeInUp 0.8s ease-out;
        }

        .input-group {
          margin-bottom: 25px;
        }

        .label {
          display: block;
          margin-bottom: 10px;
          font-size: 0.95rem;
          color: #a0aec0;
          font-weight: 500;
        }

        .select-input, .textarea-input {
          width: 100%;
          padding: 14px 18px;
          background: rgba(15, 20, 35, 0.9);
          border: 2px solid rgba(102, 126, 234, 0.2);
          border-radius: 12px;
          color: #e0e6ed;
          font-size: 1rem;
          transition: all 0.3s ease;
          font-family: 'Consolas', 'Monaco', monospace;
        }

        .select-input:focus, .textarea-input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .textarea-input {
          min-height: 200px;
          resize: vertical;
          line-height: 1.6;
        }

        .btn {
          width: 100%;
          padding: 16px 32px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border: none;
          border-radius: 12px;
          font-size: 1.1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          position: relative;
          overflow: hidden;
        }

        .btn:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }

        .btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .loading {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          margin-top: 20px;
        }

        .loading-dot {
          width: 12px;
          height: 12px;
          background: #667eea;
          border-radius: 50%;
          animation: loadingPulse 1.4s infinite ease-in-out both;
        }

        .loading-dot:nth-child(1) { animation-delay: -0.32s; }
        .loading-dot:nth-child(2) { animation-delay: -0.16s; }

        .result-card {
          margin-top: 30px;
          background: rgba(15, 20, 35, 0.95);
          border-radius: 16px;
          padding: 30px;
          border: 1px solid rgba(102, 126, 234, 0.2);
          animation: fadeInUp 0.5s ease-out;
        }

        .result-header {
          margin-bottom: 20px;
          padding-bottom: 15px;
          border-bottom: 2px solid rgba(102, 126, 234, 0.2);
        }

        .result-title {
          font-size: 1.3rem;
          font-weight: 600;
          color: #667eea;
        }

        .result-content {
          line-height: 1.8;
          color: #cbd5e0;
          font-size: 1.05rem;
          white-space: pre-wrap;
        }

        .history-title {
          font-size: 1.8rem;
          color: #667eea;
          margin-bottom: 25px;
        }

        .history-item {
          background: rgba(15, 20, 35, 0.6);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 20px;
          border: 1px solid rgba(102, 126, 234, 0.15);
        }

        .history-meta {
          margin-bottom: 15px;
        }

        .history-language {
          display: inline-block;
          padding: 6px 12px;
          background: rgba(102, 126, 234, 0.2);
          border-radius: 6px;
          font-size: 0.85rem;
          font-weight: 600;
          color: #667eea;
        }

        .history-section {
          margin-top: 15px;
        }

        .history-section strong {
          color: #a0aec0;
          display: block;
          margin-bottom: 8px;
        }

        .history-code {
          background: rgba(10, 14, 27, 0.8);
          padding: 15px;
          border-radius: 8px;
          overflow-x: auto;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 0.9rem;
          line-height: 1.5;
          color: #e0e6ed;
        }

        .history-explanation {
          color: #cbd5e0;
          line-height: 1.6;
        }

        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes fadeInDown {
          from {
            opacity: 0;
            transform: translateY(-30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes loadingPulse {
          0%, 80%, 100% {
            transform: scale(0);
          }
          40% {
            transform: scale(1);
          }
        }

        @media (max-width: 768px) {
          .main-title {
            font-size: 2.5rem;
          }
          .main-card, .history-card {
            padding: 25px;
          }
        }
      `}</style>

      
      <div className="app-container">
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>

        <img src="/ai.png" className='w-[70px] h-[70px] ml-[50px] rounded-lg' />

        <header className="header">
          <h1 className="main-title">Code Explainer AI</h1>
          <p style={{ color: '#a0aec0', fontSize: '1.2rem', fontWeight: 300 }}>
            Understand your code in simple terms with AI
          </p>
        </header>

        <CodeExplainer token={token} />
        

        <History token={token} />
      </div>
    </>
  );
}

export default App;

