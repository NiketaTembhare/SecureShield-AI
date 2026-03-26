import React, { useState, useRef, useEffect } from 'react';
import { Send, ShieldAlert, Bot, User, Loader2, Menu, Plus, Settings, MessageSquare, Briefcase } from 'lucide-react';
import axios from 'axios';

export default function App() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Welcome to SecureShield AI. I am your secure AI interface. How can I assist you today?' }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await axios.post('http://localhost:8000/api/prompt', {
        message: userMessage,
        user_id: "E100",
        department: "HR"
      });

      if (response.data.is_blocked) {
        setMessages(prev => [...prev, { 
          role: 'system_alert', 
          content: response.data.reason || 'Security Alert: Prompt Injection Detected. Request Blocked.' 
        }]);
      } else {
        setMessages(prev => [...prev, { 
          role: 'assistant', 
          content: response.data.response 
        }]);
      }
    } catch (error) {
      console.error('API Error:', error);
      setMessages(prev => [...prev, { 
        role: 'system_alert', 
        content: 'Failed to connect to SecureShield Backend. Is the server running?' 
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Enter key for textarea
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="flex h-screen w-full bg-[#343541] text-gray-100 overflow-hidden font-sans">
      
      {/* Sidebar (Desktop & Toggleable) */}
      <aside 
        className={`${isSidebarOpen ? 'w-64' : 'w-0 hidden md:flex md:w-0'} shrink-0 transition-all duration-300 ease-in-out bg-[#202123] border-r border-gray-700 flex flex-col`}
      >
        {isSidebarOpen && (
          <div className="flex flex-col h-full w-64 p-3">
            {/* New Chat Button */}
            <button className="flex items-center gap-3 w-full p-3 rounded-md border border-gray-600 hover:bg-gray-700/50 transition-colors text-sm font-medium mb-4 text-gray-200">
              <Plus size={16} />
              New chat
            </button>
            
            {/* Nav Menu */}
            <div className="flex-1 overflow-y-auto space-y-2">
              <p className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 mt-4">History</p>
              <button className="flex items-center gap-3 w-full px-3 py-3 rounded-md hover:bg-[#2A2B32] transition-colors text-sm text-gray-300">
                <MessageSquare size={16} />
                <span className="truncate">Prompt Injection Test...</span>
              </button>
            </div>

            {/* Bottom Profile / Settings */}
            <div className="pt-4 border-t border-gray-700 space-y-2 pb-2">
              <button className="flex items-center gap-3 w-full p-3 rounded-md hover:bg-[#2A2B32] transition-colors text-sm text-gray-300">
                <Settings size={16} />
                Settings
              </button>
              <div className="flex items-center gap-3 w-full p-3 rounded-md bg-gray-800/80 border border-gray-700">
                <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-orange-500 to-red-600 flex items-center justify-center font-bold text-white text-xs shadow-md">
                  E
                </div>
                <div className="flex flex-col text-left">
                  <span className="text-sm font-semibold text-gray-200">Emp E100</span>
                  <span className="text-xs text-orange-400 font-medium flex items-center gap-1">
                    <Briefcase size={10} /> HR Dept
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </aside>

      {/* Main Chat Area */}
      <main className="flex-1 flex flex-col h-full min-w-0 bg-[#343541]">
        
        {/* Header */}
        <header className="h-14 shrink-0 flex items-center px-4 border-b border-gray-700/50 bg-[#343541]">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="p-2 -ml-2 rounded-md hover:bg-gray-700/50 text-gray-400 hover:text-gray-100 transition-colors mr-3"
            title="Toggle Sidebar"
          >
            <Menu size={20} />
          </button>
          <div className="flex items-center gap-2">
            <ShieldAlert size={22} className="text-orange-500" />
            <h1 className="text-md font-semibold text-gray-200">SecureShield AI</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/10 text-orange-400 uppercase tracking-wider ml-2 border border-orange-500/20">
              Gateway Active
            </span>
          </div>
        </header>

        {/* Messages Scroll Area */}
        <div className="flex-1 overflow-y-auto">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-500">
              No messages yet. Send a prompt to begin.
            </div>
          ) : (
            <div className="flex flex-col text-sm md:text-base">
              {messages.map((msg, idx) => (
                <div 
                  key={idx} 
                  className={`w-full py-8 border-b border-black/10 ${
                    msg.role === 'assistant' ? 'bg-[#444654]' : 
                    msg.role === 'system_alert' ? 'bg-[#4a1c1c]/40 border-b border-red-900/50' : 
                    'bg-[#343541]'
                  }`}
                >
                  <div className="max-w-3xl mx-auto flex gap-4 md:gap-6 px-4">
                    {/* Avatar */}
                    <div className={`shrink-0 w-8 h-8 flex items-center justify-center shadow-sm ${
                      msg.role === 'user' ? 'bg-emerald-600 rounded-sm' : 
                      msg.role === 'system_alert' ? 'bg-red-600 rounded-sm' :
                      'bg-orange-500 rounded-sm'
                    }`}>
                      {msg.role === 'user' ? <User size={18} className="text-white" /> : 
                       msg.role === 'system_alert' ? <ShieldAlert size={18} className="text-white" /> : 
                       <Bot size={18} className="text-white" />}
                    </div>
                    
                    {/* Content */}
                    <div className="flex-1 min-w-0 space-y-2 mt-1">
                      <div className={`prose prose-invert max-w-none text-gray-200 leading-relaxed font-normal break-words ${
                        msg.role === 'system_alert' ? 'text-red-200 font-medium' : ''
                      }`}>
                        {msg.content}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
              
              {/* Loading State */}
              {isLoading && (
                <div className="w-full py-8 bg-[#444654] border-b border-black/10">
                  <div className="max-w-3xl mx-auto flex gap-4 md:gap-6 px-4">
                    <div className="shrink-0 w-8 h-8 bg-orange-500/50 rounded-sm flex items-center justify-center shadow-sm">
                      <Loader2 size={16} className="text-white animate-spin" />
                    </div>
                    <div className="flex-1 min-w-0 flex items-center">
                      <div className="flex gap-1">
                        <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce [animation-delay:-0.3s]"></span>
                        <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce [animation-delay:-0.15s]"></span>
                        <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce"></span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              {/* Dummy element to scroll to */}
              <div ref={messagesEndRef} className="h-4" />
            </div>
          )}
        </div>

        {/* Input Area (Fixed at bottom) */}
        <div className="shrink-0 bg-gradient-to-t from-[#343541] via-[#343541] to-transparent pt-4 pb-6 px-4 border-t border-transparent relative">
          <div className="max-w-3xl mx-auto">
            <form 
              onSubmit={handleSubmit}
              className="relative flex items-end bg-[#40414F] rounded-xl border border-gray-600/50 shadow-md focus-within:shadow-[0_0_15px_rgba(0,0,0,0.1)] focus-within:border-gray-500 transition-all overflow-hidden"
            >
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Message SecureShield AI... (Press Enter to send)"
                className="flex-1 max-h-[200px] min-h-[52px] bg-transparent pl-4 pr-12 py-3.5 text-gray-100 placeholder-gray-400 focus:outline-none resize-none overflow-y-auto w-full leading-relaxed"
                disabled={isLoading}
                rows={1}
                style={{ height: input ? 'auto' : '52px' }}
              />
              <button 
                type="submit" 
                disabled={!input.trim() || isLoading}
                className={`absolute right-2 bottom-1.5 p-2 rounded-lg transition-colors flex items-center justify-center ${
                  !input.trim() || isLoading 
                    ? 'bg-transparent text-gray-500' // Disabled state
                    : 'bg-orange-500 text-white hover:bg-orange-400' // Enabled state
                }`}
              >
                <Send size={16} />
              </button>
            </form>
            <div className="text-center mt-3 text-xs text-gray-500 flex justify-center items-center gap-1.5">
              SecureShield AI Firewall evaluates inputs before processing.
            </div>
          </div>
        </div>

      </main>
    </div>
  );
}
