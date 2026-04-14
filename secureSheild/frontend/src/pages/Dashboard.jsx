import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { Link } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend, CartesianGrid } from 'recharts';
import { LayoutDashboard, ShieldCheck, Activity, Users, AlertTriangle, ArrowUpRight } from 'lucide-react';

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const [sumRes, logsRes] = await Promise.all([
          api.get('/api/analytics/summary'),
          api.get('/api/logs?limit=50')
        ]);
        if (mounted) {
          setSummary(sumRes.data);
          setLogs(logsRes.data.logs || []);
        }
      } catch (e) {
        if (mounted) {
          const errMsg = e?.response?.data?.error || '';
          if (errMsg === 'admin only' || e?.response?.status === 401) {
            setError('Dashboard requires Admin role. Please log in with an admin account.');
          } else {
            setError(errMsg || 'Failed to sync with security nodes.');
          }
        }
      }
    })();
    return () => { mounted = false; };
  }, []);

  const piiData = summary ? [
    { name: 'Blocked', value: summary.blocked_attempts },
    { name: 'Allowed', value: Math.max(0, summary.total_requests - summary.blocked_attempts) }
  ] : [];

  const riskByDeptScaled = summary ? summary.risk_by_department.map(d => ({
    ...d,
    avg_risk_pct: Math.min(100, Math.round((d.avg_risk || 0) * 100))
  })) : [];

  return (
    <div className="h-screen w-full overflow-hidden flex flex-col bg-[#070b14] bg-[linear-gradient(to_right,#00ffcc05_1px,transparent_1px),linear-gradient(to_bottom,#00ffcc05_1px,transparent_1px)] bg-[size:4rem_4rem] text-cyan-50 font-mono p-3 gap-3">
      
      {/* 🧩 Header */}
      <header className="flex items-center justify-between pb-2 border-b border-cyan-500/30 shrink-0">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-xl font-bold tracking-widest text-white uppercase drop-shadow-[0_0_8px_rgba(0,255,204,0.5)]">Security Dashboard</h1>
            <p className="text-xs text-cyan-600/80 tracking-widest mt-1 uppercase">Real-time Security Metrics</p>
          </div>
        </div>
        <Link to="/chat" className="px-4 py-2 bg-[#0a1120] border border-cyan-500/50 rounded-lg text-sm text-cyan-400 hover:bg-cyan-900/40 hover:shadow-[0_0_15px_rgba(0,255,204,0.3)] transition-all">
          Back to Chat
        </Link>
      </header>

      {error && <div className="text-sm text-red-400 bg-red-900/40 border border-red-500/50 rounded-xl p-3 shrink-0">{error}</div>}

      {!summary && !error && (
        <div className="flex-1 flex items-center justify-center text-cyan-400 animate-pulse font-bold tracking-widest">LOADING TELEMETRY...</div>
      )}

      {summary && (
        <div className="flex-1 flex flex-col gap-3 min-h-0">
          
          {/* Stats Row */}
          <div className="grid grid-cols-3 gap-3 shrink-0">
            <Card title="TOTAL REQUESTS" value={summary.total_requests} icon={<Activity />} />
            <Card title="BLOCKED THREATS" value={summary.blocked_attempts} icon={<ShieldCheck className="text-orange-400" />} overrideColor="text-orange-400" border="border-orange-500/30" />
            <Card title="PII DETECTIONS" value={summary.pii_detections} icon={<AlertTriangle className="text-red-400" />} overrideColor="text-red-400" border="border-red-500/30" />
          </div>

          <div className="flex-1 flex gap-3 min-h-0">
            
            {/* Left Column: Metrics & Entities (65%) */}
            <div className="w-[65%] flex flex-col gap-3 min-h-0">
              
              {/* Top Row: Side-by-Side Charts */}
              <div className="h-[240px] shrink-0 flex gap-3">
                {/* Risk by Department */}
                <div className="flex-1 min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-2 shrink-0">
                    <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></span>
                    <h2 className="font-bold text-[10px] tracking-widest text-cyan-100 uppercase">RISK BY DEPARTMENT</h2>
                  </div>
                  <div className="flex-1 min-h-0 font-mono">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={riskByDeptScaled} margin={{top: 5, right: 10, left: -25, bottom: 0}}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#164e63" opacity={0.3} />
                        <XAxis dataKey="department" stroke="#0891b2" tick={{fill: '#a5f3fc', fontSize: 9}} tickLine={false} axisLine={false} />
                        <YAxis stroke="#0891b2" tick={{fill: '#a5f3fc', fontSize: 9}} tickLine={false} axisLine={false} domain={[0, 100]} ticks={[50, 100]} tickFormatter={(v) => `${v}%`} />
                        <Tooltip cursor={{fill: '#164e63'}} contentStyle={{backgroundColor: '#0a1120', borderColor: '#0891b2', fontSize: 9}} />
                        <Bar dataKey="avg_risk_pct" fill="#00ffcc" radius={[2, 2, 0, 0]} maxBarSize={35} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Traffic Distribution */}
                <div className="w-[200px] shrink-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm shadow-inner">
                  <div className="flex items-center gap-2 shrink-0 mb-1 font-mono">
                    <h2 className="font-bold text-[10px] tracking-widest text-cyan-100 uppercase">TRAFFIC OVERVIEW</h2>
                  </div>
                  <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={piiData} cx="50%" cy="50%" innerRadius={35} outerRadius={50} paddingAngle={3} dataKey="value" stroke="none">
                          {piiData.map((e, index) => <Cell key={index} fill={e.name==='Blocked' ? '#f97316' : '#00ffcc'} />)}
                        </Pie>
                        <Tooltip contentStyle={{backgroundColor: '#0a1120', fontSize: 9}} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex justify-center gap-2 text-[8px] font-bold mt-1 uppercase opacity-60">
                     <span className="text-cyan-400 font-mono">ALLOW</span>
                     <span className="text-orange-500 font-mono">BLOCK</span>
                  </div>
                </div>
              </div>

              {/* Risky Entities Table */}
              <div className="flex-1 min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm relative">
                <div className="flex items-center gap-2 mb-2 shrink-0">
                  <Users className="w-4 h-4 text-cyan-500" />
                  <h2 className="font-bold text-xs tracking-widest text-cyan-100 uppercase">Risky Entities</h2>
                </div>
                <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-cyan-900 pr-1">
                  <table className="w-full text-left text-[10px] text-cyan-100/80">
                    <thead className="border-b border-cyan-900/50 text-cyan-600 sticky top-0 bg-[#0a1120]/90 uppercase font-mono">
                      <tr>
                        <th className="py-1">UUID</th>
                        <th className="py-1 text-right">Risk</th>
                        <th className="py-1 text-right">Block</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono">
                      {summary.top_risky_users?.map((u) => (
                        <tr key={u.user_id} className="border-b border-cyan-900/20 hover:bg-cyan-900/30 transition-all">
                          <td className="py-2 font-semibold text-cyan-50 truncate max-w-[150px]">{u.user_id}</td>
                          <td className="py-2 text-right font-bold text-cyan-400">{Math.min(100, Math.round((u.avg_risk ?? 0) * 100))}%</td>
                          <td className="py-2 text-right text-orange-400 font-black">[{u.blocked}]</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Right Column: Controls & Feed (40%) */}
            <div className="w-[35%] flex flex-col gap-3 min-h-0">
              
              {/* Custom Rules (Moved to top) */}
              <div className="h-[180px] shrink-0 bg-[#0a1120]/80 border border-orange-500/20 rounded-2xl p-4 overflow-hidden shadow-xl">
                 <DynamicRules />
              </div>

              {/* Activity Feed (Bottom) */}
              <div className="flex-1 min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm relative">
                <div className="flex items-center gap-2 mb-2 shrink-0">
                  <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                  <h2 className="font-bold text-xs tracking-widest text-cyan-100 uppercase">Live Activity</h2>
                </div>
                <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-cyan-900 pr-1 space-y-2">
                   {logs.map((log) => {
                     const dec = log.security_assessment?.action_taken || log.decision || 'ALLOW';
                     return (
                     <div key={log._id} className="text-[10px] border-l-2 pl-3 py-1.5 bg-black/20 rounded-r border-cyan-800">
                        <div className="flex justify-between items-center opacity-60 mb-0.5">
                          <span className="truncate max-w-[150px] text-cyan-200">{log.user?.email || log.user_id}</span>
                          <span className="text-[8px]">{new Date(log.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</span>
                        </div>
                        <div className="text-cyan-100/90 italic truncate">"{log.prompt || log.input?.prompt_preview}"</div>
                        <div className="flex justify-between items-center mt-1 uppercase font-black tracking-tighter">
                          <span className={`${dec === 'BLOCK' ? 'text-red-500 font-bold' : 'text-green-500'}`}>{dec}</span>
                          <span className="opacity-40 text-[9px] font-mono">RISK: {Math.round((log.security_assessment?.severity_score ?? log.risk_score ?? 0)*100)}%</span>
                        </div>
                     </div>
                   )})}
                </div>
              </div>

            </div>

          </div>
        </div>
      )}
    </div>
  );
}

function Card({ title, value, icon, overrideColor, border }) {
  return (
    <div className={`bg-[#0a1120]/80 border ${border || 'border-cyan-500/30'} rounded-2xl p-4 flex items-center justify-between backdrop-blur-md shadow-xl`}>
      <div>
        <div className="text-[10px] tracking-widest text-cyan-700 font-bold uppercase">{title}</div>
        <div className={`text-2xl font-black mt-1 ${overrideColor || 'text-cyan-400'}`}>{value ?? '0'}</div>
      </div>
      <div className={`p-2 rounded-xl bg-black/30 border border-white/5 ${overrideColor || 'text-cyan-400'}`}>{icon}</div>
    </div>
  );
}

function DynamicRules() {
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState('');

  const fetchRules = async () => {
    try {
      const res = await api.get('/api/admin/rules');
      setRules(res.data.rules || []);
    } catch (e) {}
  };

  useEffect(() => { fetchRules(); }, []);

  const addRule = async (e) => {
    e.preventDefault();
    if (!newRule.trim()) return;
    try {
      await api.post('/api/admin/rules', { phrase: newRule, attack_type: 'CUSTOM' });
      setNewRule('');
      fetchRules();
    } catch (e) { alert('Admin Access Required'); }
  };

  const deleteRule = async (p) => {
    try { await api.delete(`/api/admin/rules/${encodeURIComponent(p)}`); fetchRules(); } catch (e) {}
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 mb-2 shrink-0">
        <ShieldCheck size={14} className="text-orange-500" />
        <h2 className="font-bold text-xs text-orange-200 uppercase tracking-widest">Custom Rules</h2>
      </div>
      <form onSubmit={addRule} className="flex gap-2 mb-3 shrink-0">
        <input 
          value={newRule} onChange={e => setNewRule(e.target.value)}
          placeholder="New block phrase..." 
          className="flex-1 bg-black/50 border border-orange-900/30 rounded px-3 py-1.5 text-[11px] outline-none focus:border-orange-500 text-orange-100"
        />
        <button type="submit" className="bg-orange-600 text-white px-3 py-1.5 rounded text-[10px] font-black uppercase">Add</button>
      </form>
      <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-orange-900/30 space-y-1.5">
        {rules.map(r => (
          <div key={r.phrase} className="group flex justify-between items-center bg-orange-900/10 border border-orange-900/20 px-3 py-1 rounded text-[10px]">
             <span className="truncate max-w-[150px] text-orange-200">{r.phrase}</span>
             <button onClick={() => deleteRule(r.phrase)} className="text-red-500 font-bold hover:text-red-300 transition-colors">X</button>
          </div>
        ))}
      </div>
    </div>
  );
}

