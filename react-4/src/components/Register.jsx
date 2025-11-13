import { useState } from 'react';
import { axiosInstance } from '../components/api';

const Register = ({ onSwitchToLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async e => {
    e.preventDefault();
    if (!username || !password) {
      setMessage('Please fill in all fields');
      return;
    }
    setLoading(true);
    setMessage('');
    try {
      const res = await axiosInstance.post('/api/register', {
        username,
        password,
      });
      setMessage(res.data.message);
      setTimeout(() => onSwitchToLogin(), 1500);
    } catch (err) {
      setMessage(err.response?.data?.error || 'Error during registration');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-form">
      <h2 className="form-title">Create Account</h2>
      <p className="form-subtitle">Sign up to get started</p>

      {message && (
        <div
          className={
            message.includes('success')
              ? 'alert alert-success'
              : 'alert alert-error'
          }
        >
          {message}
        </div>
      )}

      <div className="form-group">
        <label className="form-label">Username</label>
        <input
          className="form-input"
          placeholder="Enter username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          onKeyPress={e => e.key === 'Enter' && handleRegister(e)}
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
          onKeyPress={e => e.key === 'Enter' && handleRegister(e)}
        />
      </div>

      <button className="auth-btn" onClick={handleRegister} disabled={loading}>
        {loading ? 'Creating Account...' : 'Sign Up'}
      </button>

      <div className="toggle-text">
        Already have an account?{' '}
        <span className="toggle-link" onClick={onSwitchToLogin}>
          Sign In
        </span>
      </div>
    </div>
  );
};

export default Register;

// import { useState } from 'react';
// import { axiosInstance, setAuthToken } from '../components/api';

// export default function Register({ setToken }) {
//   const [username, setUsername] = useState('');
//   const [password, setPassword] = useState('');
//   const [message, setMessage] = useState('');

//   const handleRegister = async e => {
//     e.preventDefault();
//     try {
//       const res = await axiosInstance.post('/api/register', {
//         username,
//         password,
//       });
//       setMessage(res.data.message);
//     } catch (err) {
//       setMessage(err.response?.data?.error || 'Error');
//     }
//   };

//   return (
//     <form onSubmit={handleRegister} className="auth-form">
//       <h2>Register</h2>
//       <input
//         placeholder="Username"
//         value={username}
//         onChange={e => setUsername(e.target.value)}
//       />
//       <input
//         type="password"
//         placeholder="Password"
//         value={password}
//         onChange={e => setPassword(e.target.value)}
//       />
//       <button type="submit">Register</button>
//       {message && <p>{message}</p>}
//     </form>
//   );
// }
