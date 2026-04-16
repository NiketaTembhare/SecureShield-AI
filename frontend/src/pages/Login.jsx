import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { api, setToken } from '../lib/api';

export default function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [fieldError, setFieldError] = useState('');
  const [loading, setLoading] = useState(false);

  const validate = () => {
    if (!email.trim()) return 'Email is required.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return 'Please enter a valid email address.';
    if (!password) return 'Password is required.';
    return '';
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    const validation = validate();
    if (validation) {
      setFieldError(validation);
      setError('');
      return;
    }
    setFieldError('');
    setError('');
    setLoading(true);
    try {
      const res = await api.post('/api/auth/login', { email, password });
      setToken(res.data.token);
      nav('/chat');
    } catch (err) {
      console.error('Login error:', err);
      const responseError = err?.response?.data?.error || err?.response?.data?.message;
      const status = err?.response?.status;
      if (responseError) {
        setError(responseError);
      } else if (status) {
        setError(`Login failed (status ${status}).`);
      } else {
        setError('Login failed. Cannot reach backend at http://localhost:8000.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#070b14] bg-[linear-gradient(to_right,#00ffcc05_1px,transparent_1px),linear-gradient(to_bottom,#00ffcc05_1px,transparent_1px)] bg-[size:4rem_4rem] text-cyan-50 px-4 font-mono">
      <div className="w-full max-w-md bg-[#0a1120]/80 border-2 border-cyan-500/30 rounded-2xl p-8 backdrop-blur-md shadow-[0_0_30px_rgba(0,255,204,0.15)] relative overflow-hidden">
        {/* Glow effect in corner */}
        <div className="absolute -top-10 -right-10 w-32 h-32 bg-cyan-500/20 rounded-full blur-[40px] pointer-events-none"></div>
        
        <div className="flex items-center gap-3 mb-2">
          <ShieldCheck className="w-8 h-8 text-cyan-400" />
          <h1 className="text-3xl font-bold tracking-tight text-white drop-shadow-[0_0_8px_rgba(0,255,204,0.5)]">SecureShield</h1>
        </div>
        <p className="text-sm text-cyan-400/80 mb-8 tracking-wide">Sign in to your enterprise gateway</p>

        <form onSubmit={onSubmit} className="space-y-5">
          <div className="group relative">
            <input
              className="w-full rounded-lg bg-black/40 border border-cyan-800/50 focus:border-cyan-400 px-4 py-3.5 outline-none transition-all placeholder:text-cyan-800/80 text-cyan-50 shadow-inner"
              placeholder="Email address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              type="email"
            />
          </div>

          <div className="relative group">
            <input
              className="w-full rounded-lg bg-black/40 border border-cyan-800/50 focus:border-cyan-400 px-4 py-3.5 outline-none transition-all placeholder:text-cyan-800/80 text-cyan-50 shadow-inner"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type={showPassword ? "text" : "password"}
            />
            <button 
              type="button" 
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-4 top-1/2 -translate-y-1/2 text-cyan-600 hover:text-cyan-400 transition-colors"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>

          <div className="flex justify-between items-center px-1">
             <div className="flex items-center gap-2">
               <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></div>
               <span className="text-xs text-cyan-500/80">Secure connection</span>
             </div>
          </div>

          {fieldError && <div className="text-sm font-semibold text-red-400 bg-red-900/40 border border-red-500/50 rounded-lg p-3">{fieldError}</div>}
          {error && <div className="text-sm font-semibold text-red-400 bg-red-900/40 border border-red-500/50 rounded-lg p-3">{error}</div>}

          <button
            disabled={loading}
            className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-800 disabled:opacity-60 px-4 py-3.5 font-bold tracking-widest text-white transition-all shadow-[0_0_15px_rgba(0,255,204,0.4)] hover:shadow-[0_0_25px_rgba(0,255,204,0.6)]"
            type="submit"
          >
            {loading ? 'Signing in...' : 'Login'}
          </button>
        </form>

        <div className="text-sm text-cyan-600/80 mt-6 text-center border-t border-cyan-900/50 pt-5">
          Don't have an account? <Link className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline" to="/signup">Sign up</Link>
        </div>
      </div>
    </div>
  );
}

