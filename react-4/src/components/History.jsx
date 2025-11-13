import { useState, useEffect } from 'react';
import { axiosInstance, setAuthToken } from '../components/api';

const History = ({ token }) => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) return;
    setAuthToken(token);
    fetchHistory();
  }, [token]);

  const fetchHistory = async () => {
    try {
      const res = await axiosInstance.get('/api/my-explanations');
      setHistory(res.data.explanations);
    } catch (err) {
      console.error(err);
      setError('Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async id => {
    if (!window.confirm('Are you sure you want to delete this explanation?'))
      return;

    // Optimistic removal
    const updatedHistory = history.filter(item => item.id !== id);
    setHistory(updatedHistory);

    try {
      await axiosInstance.delete(`/api/explanations/${id}`);
      // Refetch to ensure sync (optional but safe)
      fetchHistory();
    } catch (err) {
      console.error(err);
      setError('Failed to delete explanation');
      // Revert on error
      fetchHistory();
    }
  };

  if (loading)
    return (
      <div className="history-card">
        <div className="loading">
          <div className="loading-dot"></div>
          <div className="loading-dot"></div>
          <div className="loading-dot"></div>
        </div>
      </div>
    );

  if (error)
    return (
      <div className="history-card">
        <p className="alert alert-error">{error}</p>
      </div>
    );

  if (!history.length)
    return (
      <div className="history-card">
        <p className="empty-text">You have no saved explanations yet.</p>
      </div>
    );

  return (
    <div className="history-card">
      <h2 className="history-title">📚 Your Previous Explanations</h2>
      {history.map(item => (
        <div key={item.id} className="history-item">
          <div className="history-meta">
            <span className="history-language">{item.language}</span>
            <button
              className="bg-red-600 text-white rounded p-1 ml-3"
              onClick={() => handleDelete(item.id)}
            >
              Delete
            </button>
          </div>
          <div className="history-section">
            <strong>Code:</strong>
            <pre className="history-code">{item.code}</pre>
          </div>
          <div className="history-section">
            <strong>Explanation:</strong>
            <div className="history-explanation">{item.explanation}</div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default History;

// import { useState, useEffect } from 'react';
// import { axiosInstance, setAuthToken } from '../components/api';

// const History = ({ token }) => {
//   const [history, setHistory] = useState([]);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState('');

//   useEffect(() => {
//     if (!token) return;
//     setAuthToken(token);
//     fetchHistory();
//   }, [token]);

//   const fetchHistory = async () => {
//     try {
//       const res = await axiosInstance.get('/api/my-explanations');
//       setHistory(res.data.explanations);
//     } catch (err) {
//       console.error(err);
//       setError('Failed to load history');
//     } finally {
//       setLoading(false);
//     }
//   };

//   if (loading)
//     return (
//       <div className="history-card">
//         <div className="loading">
//           <div className="loading-dot"></div>
//           <div className="loading-dot"></div>
//           <div className="loading-dot"></div>
//         </div>
//       </div>
//     );

//   if (error)
//     return (
//       <div className="history-card">
//         <p className="alert alert-error">{error}</p>
//       </div>
//     );

//   if (!history.length)
//     return (
//       <div className="history-card">
//         <p className="empty-text">You have no saved explanations yet.</p>
//       </div>
//     );

//   return (
//     <div className="history-card">
//       <h2 className="history-title">📚 Your Previous Explanations</h2>
//       {history.map(item => (
//         <div key={item.id} className="history-item">
//           <div className="history-meta">
//             <span className="history-language">{item.language}</span>
//           </div>
//           <div className="history-section">
//             <strong>Code:</strong>
//             <pre className="history-code">{item.code}</pre>
//           </div>
//           <div className="history-section">
//             <strong>Explanation:</strong>
//             <div className="history-explanation">{item.explanation}</div>
//           </div>
//         </div>
//       ))}
//     </div>
//   );
// };

// export default History;
