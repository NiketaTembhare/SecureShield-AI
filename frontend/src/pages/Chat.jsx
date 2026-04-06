import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bot, Loader2, Menu, Send, ShieldAlert, User, ShieldCheck, Eraser, LogOut, LayoutDashboard } from 'lucide-react';
import { api, clearToken, API_BASE } from '../lib/api';

export default function Chat() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Welcome to SecureShield AI. How can I help you today?' },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const messagesEndRef = useRef(null);
  const nav = useNavigate();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleLogout = () => {
    clearToken();
    nav('/login');
  };

  const clearChat = () => {
    setMessages([{ role: 'assistant', content: 'Chat history cleared.' }]);
  };

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setInput('');
    setIsLoading(true);

    try {
      const token = localStorage.getItem('ss_token') || '';
      const response = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ message: userMessage })
      });

      if (response.status === 401) {
        setMessages((prev) => [...prev, { role: 'system_alert', content: '[ERR 401] Unauthorized. Please re-authenticate.' }]);
        return;
      }
      if (response.status === 403) {
        const data = await response.json();
        setMessages((prev) => [...prev, { role: 'system_alert', content: `[BLOCK] ${data.message || 'Security policy violation.'}` }]);
        return;
      }
      if (!response.ok) {
        setMessages((prev) => [...prev, { role: 'system_alert', content: '[ERR 500] Gateway failure.' }]);
        return;
      }

      setMessages((prev) => [...prev, { role: 'assistant', content: '' }]);
      
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        
        const chunkStr = decoder.decode(value, { stream: true });
        const lines = chunkStr.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6);
            if (dataStr === '[DONE]') continue;
            try {
              const data = JSON.parse(dataStr);
              if (data.type === 'control') {
                if (data.data.decision === 'WARN') {
                  setMessages((prev) => {
                    const newArr = [...prev];
                    newArr.splice(newArr.length - 1, 0, { role: 'system_warn', content: `[WARN] ${data.data.warning}` });
                    return newArr;
                  });
                }
              } else if (data.type === 'chunk') {
                setMessages((prev) => {
                  const newArr = [...prev];
                  newArr[newArr.length - 1].content += data.text;
                  return newArr;
                });
              }
            } catch (e) {
              // Ignore parse errors on incomplete chunks
            }
          }
        }
      }
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'system_alert', content: '[ERR] Connection lost. Is backend running?' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="flex h-screen w-full bg-[#070b14] bg-[linear-gradient(to_right,#00ffcc05_1px,transparent_1px),linear-gradient(to_bottom,#00ffcc05_1px,transparent_1px)] bg-[size:4rem_4rem] text-cyan-50 font-mono overflow-hidden">
      <aside className={`${isSidebarOpen ? 'w-64' : 'w-0 hidden md:flex md:w-0'} shrink-0 transition-all duration-300 ease-in-out bg-[#0a1120]/90 backdrop-blur-md border-r border-cyan-500/30 shadow-[4px_0_15px_rgba(0,255,204,0.05)] flex flex-col z-20`}>
        {isSidebarOpen && (
          <div className="flex flex-col h-full w-64 p-4 pb-0">
            <div className="flex items-center gap-2 mb-8 mt-2 px-2">
              <ShieldCheck className="text-cyan-400 w-6 h-6" />
              <div className="font-bold text-lg text-white drop-shadow-[0_0_5px_rgba(0,255,204,0.5)] tracking-wide">SecureShield <span className="text-cyan-400">AI</span></div>
            </div>
            
            <div className="text-xs text-cyan-600/80 px-2 font-bold tracking-widest mb-3">NAVIGATION</div>
            <Link className="flex items-center gap-3 px-3 py-3 rounded-lg hover:bg-cyan-900/30 hover:shadow-[inset_0_0_10px_rgba(0,255,204,0.1)] border border-transparent hover:border-cyan-500/30 text-sm transition-all text-cyan-100" to="/dashboard">
              <LayoutDashboard size={18} className="text-cyan-400" /> Dashboard
            </Link>
            
            <button onClick={clearChat} className="flex items-center gap-3 mt-2 px-3 py-3 rounded-lg hover:bg-cyan-900/30 hover:shadow-[inset_0_0_10px_rgba(0,255,204,0.1)] border border-transparent hover:border-cyan-500/30 text-sm transition-all text-cyan-100 w-full text-left">
              <Eraser size={18} className="text-cyan-400" /> Clear Chat
            </button>

            <button onClick={handleLogout} className="flex items-center gap-3 mt-auto mb-4 px-3 py-3 rounded-lg hover:bg-red-900/30 hover:shadow-[inset_0_0_10px_rgba(255,0,0,0.1)] border border-transparent hover:border-red-500/30 text-sm transition-all text-red-100 w-full text-left">
              <LogOut size={18} className="text-red-400" /> Log out
            </button>
          </div>
        )}
      </aside>

      <main className="flex-1 flex flex-col h-full min-w-0 relative">
        <header className="h-14 flex items-center px-4 border-b border-cyan-500/30 bg-[#0a1120]/80 backdrop-blur-md shadow-[0_4px_15px_rgba(0,255,204,0.05)] z-10">
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="p-2 rounded-lg hover:bg-cyan-900/40 text-cyan-400 transition mr-3">
            <Menu size={20} />
          </button>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></div>
            <span className="text-sm font-semibold tracking-widest text-cyan-50 shadow-cyan-400">Online</span>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-cyan-900 scrollbar-track-transparent">
          <div className="flex flex-col text-sm pt-4 pb-20">
            {messages.map((msg, idx) => (
              <div key={idx} className="py-4">
                <div className="max-w-4xl mx-auto flex gap-4 px-4">
                  <div className={`w-8 h-8 shrink-0 flex items-center justify-center rounded-lg border shadow-lg ${
                    msg.role === 'user' ? 'bg-[#0f172a] border-cyan-500/50 text-cyan-400 shadow-[0_0_15px_rgba(0,255,204,0.2)]'
                      : msg.role === 'system_alert' ? 'bg-[#2a0f0f] border-red-500/50 text-red-400 shadow-[0_0_15px_rgba(255,0,0,0.2)]'
                      : msg.role === 'system_warn' ? 'bg-[#2a1f0f] border-orange-500/50 text-orange-400 shadow-[0_0_15px_rgba(255,165,0,0.2)]'
                      : 'bg-[#0f172a] border-indigo-500/50 text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                  }`}>
                    {msg.role === 'user' ? <User size={16} /> : msg.role.startsWith('system') ? <ShieldAlert size={16} /> : <Bot size={16} />}
                  </div>

                  <div className={`flex-1 p-4 rounded-xl border backdrop-blur-sm ${
                    msg.role === 'assistant' ? 'bg-indigo-900/10 border-indigo-500/30 shadow-[inset_0_0_10px_rgba(99,102,241,0.05)] text-indigo-50 leading-relaxed'
                      : msg.role === 'system_alert' ? 'bg-red-900/20 border-red-500/50 text-red-200 shadow-[0_0_15px_rgba(255,0,0,0.1)]'
                      : msg.role === 'system_warn' ? 'bg-orange-900/20 border-orange-500/50 text-orange-200 shadow-[0_0_15px_rgba(255,165,0,0.1)]'
                      : 'bg-[#0a1120]/60 border-cyan-800/50 text-cyan-50 leading-relaxed'
                  }`}>
                    {msg.content}
                  </div>
                </div>
              </div>
            ))}

            {isLoading && (
              <div className="py-4">
                <div className="max-w-4xl mx-auto flex gap-4 px-4">
                  <div className="w-8 h-8 shrink-0 bg-[#0f172a] border border-indigo-500/50 text-indigo-400 rounded-lg flex items-center justify-center shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                    <Loader2 size={16} className="animate-spin" />
                  </div>
                  <div className="p-4 bg-indigo-900/10 border border-indigo-500/30 rounded-xl backdrop-blur-sm flex items-center shadow-[inset_0_0_10px_rgba(99,102,241,0.05)]">
                    <span className="text-indigo-300 animate-pulse font-mono text-sm">Thinking...</span>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>
        </div>

        <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-[#070b14] via-[#070b14]/90 to-transparent">
          <div className="max-w-4xl mx-auto">
            <form onSubmit={handleSubmit} className="relative flex items-end bg-[#0a1120] border-2 border-cyan-800/50 rounded-xl shadow-[0_0_20px_rgba(0,255,204,0.05)] focus-within:shadow-[0_0_25px_rgba(0,255,204,0.2)] focus-within:border-cyan-500/70 transition-all duration-300">
              <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Message SecureShield AI..."
                className="flex-1 bg-transparent px-4 py-4 outline-none resize-none text-sm placeholder:text-cyan-800 mt-1"
                disabled={isLoading}
                rows={1}
              />
              <button type="submit" disabled={!input.trim() || isLoading} className={`m-2 p-3 rounded-lg transition-all duration-300 ${
                !input.trim() ? 'text-cyan-800 bg-black/20' : 'bg-cyan-600 text-white hover:bg-cyan-500 shadow-[0_0_15px_rgba(0,255,204,0.4)]'
              }`}>
                <Send size={18} />
              </button>
            </form>
            <div className="flex justify-between items-center mt-2 px-2 text-[10px] text-cyan-600/70 tracking-widest uppercase">
              <span>Protected by SecureShield AI.</span>
              <span>Enterprise Gateway active.</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

