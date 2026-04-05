import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { Link } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { LayoutDashboard, ShieldCheck, Activity, Users, AlertTriangle } from 'lucide-react';

const COLORS = ['#00ffcc', '#0891b2', '#3b82f6', '#8b5cf6'];

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const res = await api.get('/api/analytics/summary');
        if (mounted) setSummary(res.data);
      } catch (e) {
        if (mounted) setError(e?.response?.data?.error || 'Failed to initialize metric streams.');
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  // Format data for PieChart
  const piiData = summary ? [
    { name: 'Blocked', value: summary.blocked_attempts },
    { name: 'Allowed', value: Math.max(0, summary.total_requests - summary.blocked_attempts) }
  ] : [];

  return (
    <div className="h-screen w-full overflow-hidden flex flex-col bg-[#070b14] bg-[linear-gradient(to_right,#00ffcc05_1px,transparent_1px),linear-gradient(to_bottom,#00ffcc05_1px,transparent_1px)] bg-[size:4rem_4rem] text-cyan-50 font-mono p-4">
      <div className="max-w-7xl w-full mx-auto flex flex-col h-full gap-4">
        
        {/* Header (shrink-0 so it never shrinks) */}
        <div className="flex items-center justify-between pb-2 border-b border-cyan-500/30 shrink-0">
          <div className="flex items-center gap-3">
            <LayoutDashboard className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold tracking-widest text-white drop-shadow-[0_0_8px_rgba(0,255,204,0.5)]">Security Dashboard</h1>
              <p className="text-xs text-cyan-600/80 tracking-widest mt-1">Real-time AI Security Metrics</p>
            </div>
          </div>
          <Link to="/chat" className="px-4 py-2 bg-[#0a1120] border border-cyan-500/50 rounded-lg text-sm text-cyan-400 hover:bg-cyan-900/40 hover:shadow-[0_0_15px_rgba(0,255,204,0.3)] transition-all">
            Back to Chat
          </Link>
        </div>

        {error && <div className="text-sm text-red-400 bg-red-900/40 border border-red-500/50 rounded-xl p-3 shadow-[0_0_15px_rgba(255,0,0,0.2)] shrink-0">{error}</div>}

        {!summary && !error && (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-cyan-400 animate-pulse font-bold tracking-widest">Loading dashboard...</div>
          </div>
        )}

        {summary && (
          <div className="flex-1 min-h-0 flex flex-col gap-4">
            
            {/* Top Stat Cards Row */}
            <div className="grid grid-cols-3 gap-4 shrink-0">
              <Card title="Total Requests" value={summary.total_requests} icon={<Activity />} />
              <Card title="Blocked Threats" value={summary.blocked_attempts} icon={<ShieldCheck className="text-orange-400" />} overrideColor="text-orange-400" glow="shadow-[0_0_15px_rgba(255,165,0,0.15)]" border="border-orange-500/30" />
              <Card title="PII Detections" value={summary.pii_detections} icon={<AlertTriangle className="text-red-400" />} overrideColor="text-red-400" glow="shadow-[0_0_15px_rgba(255,0,0,0.15)]" border="border-red-500/30" />
            </div>

            {/* Bottom Content Row */}
            <div className="flex-1 min-h-0 flex gap-4">
              
              {/* Left Column (Charts and Tables) */}
              <div className="w-2/3 flex flex-col gap-4">
                
                {/* Risk by Department */}
                <div className="flex-1 min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm shadow-[0_4px_20px_rgba(0,255,204,0.05)] relative">
                  <div className="absolute top-0 right-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>
                  <div className="flex items-center gap-2 mb-2 shrink-0">
                    <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></span>
                    <h2 className="font-bold text-sm tracking-widest text-cyan-100">Risk by Department</h2>
                  </div>
                  <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={summary.risk_by_department}>
                        <XAxis dataKey="department" stroke="#0891b2" tick={{fill: '#a5f3fc', fontSize: 12}} tickLine={false} axisLine={{stroke: '#164e63'}} />
                        <YAxis stroke="#0891b2" tick={{fill: '#a5f3fc', fontSize: 12}} tickLine={false} axisLine={{stroke: '#164e63'}} />
                        <Tooltip cursor={{fill: '#164e63'}} contentStyle={{backgroundColor: '#0a1120', borderColor: '#0891b2', color: '#cffafe', borderRadius: '8px', fontFamily: 'monospace'}} />
                        <Bar dataKey="avg_risk" fill="#00ffcc" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Risky Users Table */}
                <div className="flex-1 min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm shadow-[0_4px_20px_rgba(0,255,204,0.05)] relative">
                  <div className="absolute top-0 right-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>
                  <div className="flex items-center gap-2 mb-2 shrink-0">
                    <Users className="w-4 h-4 text-cyan-500" />
                    <h2 className="font-bold text-sm tracking-widest text-cyan-100">Risky Users</h2>
                  </div>
                  <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-cyan-900 scrollbar-track-transparent">
                    <table className="w-full text-left text-xs text-cyan-100/80">
                      <thead className="border-b border-cyan-900 border-opacity-50 text-cyan-600 sticky top-0 bg-[#0a1120]/90 backdrop-blur-md">
                        <tr>
                          <th className="py-2">USER ID</th>
                          <th className="py-2 text-right">AVG RISK</th>
                          <th className="py-2 text-right">BLOCKED</th>
                          <th className="py-2 text-right">TOTAL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.top_risky_users?.map((u) => (
                          <tr key={u.user_id} className="border-b border-cyan-900/30 hover:bg-cyan-900/20 transition-colors">
                            <td className="py-2 font-semibold text-cyan-50">{u.user_id}</td>
                            <td className="py-2 text-right">{(u.avg_risk ?? 0).toFixed(3)}</td>
                            <td className="py-2 text-right">
                              <span className={`px-2 py-0.5 rounded bg-black/40 ${u.blocked > 0 ? 'text-orange-400 border border-orange-500/30' : 'text-cyan-600'}`}>{u.blocked}</span>
                            </td>
                            <td className="py-2 text-right">{u.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>

              {/* Right Column (Pie Chart and Rules) */}
              <div className="w-1/3 flex flex-col gap-4">
                
                {/* Traffic Pie Chart */}
                <div className="flex-[0.8] min-h-0 flex flex-col bg-[#0a1120]/80 border border-cyan-500/30 rounded-2xl p-4 backdrop-blur-sm shadow-[0_4px_20px_rgba(0,255,204,0.05)]">
                  <div className="flex items-center gap-2 shrink-0">
                    <h2 className="font-bold text-sm tracking-widest text-cyan-100">Traffic Overview</h2>
                  </div>
                  <div className="flex-1 min-h-0 mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={piiData} innerRadius="50%" outerRadius="80%" paddingAngle={5} dataKey="value" stroke="none">
                          {piiData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.name === 'Blocked' ? '#f97316' : '#00ffcc'} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{backgroundColor: '#0a1120', borderColor: '#0891b2', color: '#cffafe', borderRadius: '8px', fontSize: 12, fontFamily: 'monospace'}} />
                        <Legend verticalAlign="bottom" height={20} iconType="circle" wrapperStyle={{fontSize: 12}} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Custom Rules */}
                <div className="flex-[1.2] min-h-0 flex flex-col bg-[#0a1120]/80 border-2 border-red-900/40 rounded-2xl p-4 backdrop-blur-sm shadow-[0_0_20px_rgba(255,0,0,0.05)] overflow-hidden">
                  <DynamicRules />
                </div>

              </div>

            </div>
          </div>
        )}
      </div>
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
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const addRule = async (e) => {
    e.preventDefault();
    if (!newRule.trim()) return;
    try {
      await api.post('/api/admin/rules', { phrase: newRule, attack_type: 'CUSTOM_BLOCK' });
      setNewRule('');
      fetchRules();
    } catch (e) {
      alert('Failed to add rule (Admin only)');
    }
  };

  const deleteRule = async (phrase) => {
    try {
      await api.delete(`/api/admin/rules/${encodeURIComponent(phrase)}`);
      fetchRules();
    } catch (e) {
      alert('Failed to delete rule');
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 shrink-0 mb-1">
        <ShieldCheck className="w-4 h-4 text-red-500" />
        <h2 className="font-bold text-sm tracking-widest text-red-100">Custom Rules</h2>
      </div>
      <div className="text-[10px] text-red-400/80 tracking-widest mb-3 shrink-0">Block specific phrases instantly.</div>
      
      <form onSubmit={addRule} className="flex gap-2 shrink-0 mb-3">
        <input 
          value={newRule} 
          onChange={e => setNewRule(e.target.value)}
          placeholder="Phrase to block..." 
          className="flex-1 w-0 bg-black/40 border border-red-900/50 text-red-100 rounded-lg px-2 py-1.5 outline-none focus:border-red-500/80 transition-colors shadow-inner text-xs placeholder:text-red-900/80"
        />
        <button type="submit" className="bg-red-600 hover:bg-red-500 px-3 py-1.5 rounded-lg text-white font-bold text-xs tracking-widest transition-all shadow-[0_0_10px_rgba(220,38,38,0.4)] whitespace-nowrap">
          Add Rule
        </button>
      </form>
      
      <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-red-900 scrollbar-track-transparent pr-1 min-h-0 space-y-2">
        {rules.map(r => (
          <div key={r.phrase} className="flex flex-col bg-[#1f0f0f]/60 border border-red-900/30 p-2 rounded-lg text-xs">
            <span className="text-red-200 font-semibold truncate">{r.phrase}</span>
            <div className="flex justify-between items-center mt-1 pt-1 border-t border-red-900/30">
              <span className="text-[9px] text-red-500/80 tracking-widest">TYPE: {r.attack_type}</span>
              <button onClick={() => deleteRule(r.phrase)} className="text-[9px] bg-red-900/50 hover:bg-red-800 px-2 py-1 rounded text-red-100 tracking-widest transition">REMOVE</button>
            </div>
          </div>
        ))}
        {rules.length === 0 && <div className="text-xs text-red-900 italic p-2 bg-black/20 rounded border border-red-900/20 text-center">No custom rules.</div>}
      </div>
    </div>
  );
}

function Card({ title, value, icon, overrideColor, glow, border }) {
  const colorClass = overrideColor || "text-cyan-400";
  const glowClass = glow || "shadow-[0_4px_20px_rgba(0,255,204,0.05)]";
  const borderClass = border || "border-cyan-500/30";

  return (
    <div className={`bg-[#0a1120]/80 border ${borderClass} rounded-2xl p-4 backdrop-blur-sm ${glowClass} flex items-center justify-between`}>
      <div>
        <div className="text-[11px] tracking-widest text-[#0891b2] font-semibold uppercase">{title}</div>
        <div className={`text-2xl md:text-3xl font-bold mt-1 ${colorClass}`}>{value ?? '—'}</div>
      </div>
      <div className={`p-2 lg:p-3 rounded-xl bg-black/30 border border-white/5 ${colorClass}`}>
        {icon}
      </div>
    </div>
  );
}

