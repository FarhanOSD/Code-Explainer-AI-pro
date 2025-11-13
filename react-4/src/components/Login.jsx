import { useState } from 'react';
import { axiosInstance, setAuthToken } from '../components/api';

const Login = ({ setToken, onSwitchToRegister }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async e => {
    e.preventDefault();
    if (!username || !password) {
      setMessage('Please fill in all fields');
      return;
    }
    setLoading(true);
    setMessage('');
    try {
      const res = await axiosInstance.post('/api/login', {
        username,
        password,
      });
      const token = res.data.token;
      localStorage.setItem('token', token);
      setAuthToken(token);
      setToken(token);
    } catch (err) {
      setMessage(err.response?.data?.error || 'Error during login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-form">
      <h2 className="form-title">Welcome Back</h2>
      <p className="form-subtitle">Enter your credentials to continue</p>

      {message && <div className="alert alert-error">{message}</div>}

      <div className="form-group">
        <label className="form-label">Username</label>
        <input
          className="form-input"
          placeholder="Enter username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          onKeyPress={e => e.key === 'Enter' && handleLogin(e)}
        />
      </div>

      <div className="form-group">
        <label className="form-label">Password</label>
        <input
          type="password"
          className="form-input"
          placeholder="Enter password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyPress={e => e.key === 'Enter' && handleLogin(e)}
        />
      </div>

      <button className="auth-btn" onClick={handleLogin} disabled={loading}>
        {loading ? 'Signing In...' : 'Sign In'}
      </button>

      <div className="toggle-text">
        Don't have an account?{' '}
        <span className="toggle-link" onClick={onSwitchToRegister}>
          Sign Up
        </span>
      </div>
    </div>
  );
};

export default Login;


