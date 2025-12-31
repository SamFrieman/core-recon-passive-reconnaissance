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
      const API_BASE = import.meta.env.VITE_API_URL || '/api';
      const response = await axios.get(`${API_BASE}/v1/recon`, { params: { domain } });
      setData(response.data);
    } catch (err) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, executeRecon };
};