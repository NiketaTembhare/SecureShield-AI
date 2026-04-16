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

export async function logoutUser() {
  try {
    await axios.post(`${API_BASE}/api/auth/logout`, {}, { withCredentials: true });
  } catch (e) {
    console.error('Logout failed on server');
  }
  clearToken();
}

export function isTokenValid(token) {
  if (!token) return false;
  try {
    // Decode the base64 payload (the middle part of the JWT)
    const payload = JSON.parse(atob(token.split('.')[1]));
    // Check if the expiration timestamp has passed
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      return false; 
    }
    return true;
  } catch (e) {
    return false;
  }
}

export function getUserRole(token) {
  if (!token) return 'user';
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.role || 'user';
  } catch (e) {
    return 'user';
  }
}

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Global Interceptor: If API call returns 401, try to refresh before failing
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Avoid intercepting the /login, /signup or /refresh routes themselves to prevent infinite loops
    if (originalRequest.url.includes('/auth/')) {
      return Promise.reject(error);
    }
    
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        // Attempt silent refresh using the HttpOnly cookie
        const res = await axios.post(`${API_BASE}/api/auth/refresh`, {}, { withCredentials: true });
        
        if (res.data && res.data.token) {
          // Success! Save new access token
          setToken(res.data.token);
          
          // Re-attach new token to the failed request and retry it transparently
          originalRequest.headers.Authorization = `Bearer ${res.data.token}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh token failed or is expired. Wipe state and send to login
        clearToken();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

