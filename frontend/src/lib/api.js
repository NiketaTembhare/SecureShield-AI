import axios from 'axios';

export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

export function getToken() {
  return localStorage.getItem('ss_token');
}

export function setToken(token) {
  localStorage.setItem('ss_token', token);
}

export function clearToken() {
  localStorage.removeItem('ss_token');
}

export const api = axios.create({
  baseURL: API_BASE,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

