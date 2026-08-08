import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, User, Zap, AlertTriangle, Key, Info } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import remarkGfm from 'remark-gfm';
import { useAppStore } from '../../store/assessmentStore';
import { askConsultant, SUGGESTED_QUESTIONS } from '../../ai/consultant';
import './AIAdvisor.css';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
}

export function AIAdvisor() {
  const { assessment, geminiApiKey } = useAppStore();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (messages.length === 0 && assessment) {
      setMessages([
        {
          id: 'system-1',
          role: 'assistant',
          content: `Hello. I am the QuantumGuard AI Consultant. I have analyzed the cryptographic inventory for **${assessment.organization}**.\n\nI can help you understand your quantum exposure, prioritize your migration, or generate specific code remediation examples. How can I assist you today?`,
        }
      ]);
    }
  }, [assessment, messages.length]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (questionText?: string) => {
    const query = questionText || input;
    if (!query.trim() || !assessment || loading) return;

    setInput('');
    setMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', content: query }]);
    setLoading(true);

    try {
      const response = await askConsultant(query, assessment, geminiApiKey);
      setMessages(prev => [...prev, { id: Date.now().toString(), role: 'assistant', content: response.answer }]);
    } catch (err: any) {
      setMessages(prev => [...prev, { id: Date.now().toString(), role: 'assistant', content: `**Error:** ${err.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  if (!assessment) return null;

  const isOffline = !geminiApiKey || geminiApiKey.trim() === '';

  return (
    <div className="ai-advisor animate-fade-in">
      <div className="ai-header">
        <div className="aih-left">
          <Bot size={24} className="aih-icon" />
          <div>
            <h2>AI Security Consultant</h2>
            <p>Grounded in your CBOM. Ask about specific findings or migration strategies.</p>
          </div>
        </div>
        {isOffline && (
          <div className="offline-mode-badge">
            <Info size={14} />
            <span>Offline Mode (Deterministic Fallback Active)</span>
          </div>
        )}
      </div>

      <div className="card chat-container">
        <div className="chat-messages">
          {messages.map(m => (
            <div key={m.id} className={`chat-message ${m.role}`}>
              <div className="msg-avatar">
                {m.role === 'assistant' ? <Bot size={16} /> : <User size={16} />}
              </div>
              <div className="msg-content">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    code({ node, inline, className, children, ...props }: any) {
                      const match = /language-(\w+)/.exec(className || '');
                      return !inline && match ? (
                        <SyntaxHighlighter
                          style={vscDarkPlus as any}
                          language={match[1]}
                          PreTag="div"
                          className="msg-code-block"
                          {...props}
                        >
                          {String(children).replace(/\n$/, '')}
                        </SyntaxHighlighter>
                      ) : (
                        <code className="msg-code-inline" {...props}>
                          {children}
                        </code>
                      );
                    }
                  }}
                >
                  {m.content}
                </ReactMarkdown>
              </div>
            </div>
          ))}
          {loading && (
            <div className="chat-message assistant loading">
              <div className="msg-avatar"><Bot size={16} /></div>
              <div className="msg-content loading-dots">
                <div className="dot"></div>
                <div className="dot"></div>
                <div className="dot"></div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <div className="chat-input-area">
          {/* §30 Suggested Questions Chips */}
          <div className="suggested-prompts">
            {SUGGESTED_QUESTIONS.map((p, i) => (
              <button key={i} className="prompt-chip" onClick={() => handleSend(p)}>
                {p}
              </button>
            ))}
          </div>

          <div className="input-wrapper">
            <input
              type="text"
              className="input chat-input"
              placeholder="Ask about your cryptographic inventory..."
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSend()}
            />
            <button
              className="btn btn-primary send-btn"
              onClick={() => handleSend()}
              disabled={!input.trim() || loading}
            >
              <Send size={16} />
            </button>
          </div>
          <div className="chat-disclaimer">
            {isOffline
              ? 'ⓘ Currently using offline deterministic rule engine. Configure a Gemini API key in Settings for dynamic LLM responses.'
              : 'AI recommendations should be verified by a security engineer before implementation.'}
          </div>
        </div>
      </div>
    </div>
  );
}
