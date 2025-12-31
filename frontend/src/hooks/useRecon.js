import { useState } from 'react';
import axios from 'axios';

export const useRecon = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const executeRecon = async (domain) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/v1/recon/${domain}`);
      setData(response.data);
    } catch (err) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, executeRecon };
};