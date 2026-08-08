// ============================================================
// QuantumGuard AI — §30 AI Advisor Page
//
// Implements an interactive chat interface to ask questions
// about the quantum assessment. Uses Gemini if available,
// otherwise falls back to a deterministic offline engine.
// ============================================================

import React, { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Shield, AlertTriangle, Info, Settings, Loader2 } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { askConsultant, SUGGESTED_QUESTIONS } from '../../ai/consultant';
import './AIAdvisor.css';

export function AIAdvisor() {
  const { assessment, addChatMessage, geminiApiKey, setGeminiApiKey } = useAppStore();
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [tempKey, setTempKey] = useState(geminiApiKey);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [assessment?.chatHistory]);

  if (!assessment) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🤖</div>
        <h2>AI Advisor Not Available</h2>
        <p>Please load an assessment to consult with the AI.</p>
      </div>
    );
  }

  const handleSend = async (text: string) => {
    if (!text.trim()) return;

    const userMsg = {
      id: `msg-${Date.now()}`,
      role: 'user' as const,
      content: text,
      timestamp: new Date().toISOString(),
    };
    addChatMessage(userMsg);
    setInput('');
    setIsTyping(true);

    try {
      const response = await askConsultant(text, assessment);
      const aiMsg = {
        id: `msg-${Date.now() + 1}`,
        role: 'assistant' as const,
        content: response.answer,
        citedFindings: response.citedFindings,
        timestamp: new Date().toISOString(),
      };
      addChatMessage(aiMsg);
    } catch (err) {
      const errorMsg = {
        id: `msg-${Date.now() + 1}`,
        role: 'assistant' as const,
        content: `Error: Unable to generate response. Please check your API key or network connection.`,
        timestamp: new Date().toISOString(),
      };
      addChatMessage(errorMsg);
    } finally {
      setIsTyping(false);
    }
  };

  const handleSaveKey = () => {
    setGeminiApiKey(tempKey);
    setShowSettings(false);
  };

  return (
    <div className="ai-advisor-page animate-fade-in">
      <div className="ai-header">
        <div className="ai-header-left">
          <div className="ai-icon-container">
            <Bot size={24} />
          </div>
          <div>
            <h2>AI Remediation Advisor</h2>
            <p>Ask questions about your quantum risk, cryptography, or migration strategy.</p>
          </div>
        </div>
        <button
          className={`btn ${geminiApiKey ? 'btn-ghost' : 'btn-primary'}`}
          onClick={() => setShowSettings(!showSettings)}
        >
          <Settings size={16} />
          {geminiApiKey ? 'API Settings' : 'Configure AI'}
        </button>
      </div>

      {showSettings && (
        <div className="card ai-settings-card animate-fade-in">
          <h4>Google Gemini Integration</h4>
          <p>Enter your Gemini API key to enable generative AI responses. If omitted, QuantumGuard will use a local deterministic fallback engine.</p>
          <div className="ai-settings-input-row">
            <input
              type="password"
              className="input flex-1"
              placeholder="AIzaSy..."
              value={tempKey}
              onChange={(e) => setTempKey(e.target.value)}
            />
            <button className="btn btn-primary" onClick={handleSaveKey}>Save Key</button>
          </div>
        </div>
      )}

      <div className="card chat-container">
        <div className="chat-history">
          {assessment.chatHistory.length === 0 ? (
            <div className="chat-empty-state">
              <Bot size={48} className="chat-empty-icon" />
              <h3>How can I help you today?</h3>
              <p>I have full context of {assessment.name}'s cryptographic inventory and quantum risk posture.</p>
              
              <div className="suggested-questions-grid">
                {SUGGESTED_QUESTIONS.map((q, i) => (
                  <button
                    key={i}
                    className="suggested-question-btn"
                    onClick={() => handleSend(q)}
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="chat-messages">
              {assessment.chatHistory.map((msg) => (
                <div key={msg.id} className={`chat-message-row ${msg.role}`}>
                  <div className="chat-avatar">
                    {msg.role === 'assistant' ? <Bot size={18} /> : <User size={18} />}
                  </div>
                  <div className="chat-bubble">
                    <div className="chat-content" dangerouslySetInnerHTML={{ __html: msg.content.replace(/\n/g, '<br/>') }} />
                    {msg.citedFindings && msg.citedFindings.length > 0 && (
                      <div className="chat-citations">
                        <strong>Cited Findings:</strong>
                        <div className="citation-badges">
                          {msg.citedFindings.map(id => (
                            <span key={id} className="citation-badge">
                              <Shield size={10} /> {id}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {isTyping && (
                <div className="chat-message-row assistant">
                  <div className="chat-avatar">
                    <Bot size={18} />
                  </div>
                  <div className="chat-bubble typing-bubble">
                    <Loader2 size={16} className="spinner" />
                    <span>Analyzing...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        <div className="chat-input-area">
          {!geminiApiKey && (
            <div className="chat-warning">
              <Info size={14} />
              <span>Running in deterministic fallback mode. Configure Gemini API key for advanced generative responses.</span>
            </div>
          )}
          <div className="chat-input-wrapper">
            <input
              type="text"
              className="chat-input"
              placeholder="Ask about vulnerabilities, migration steps, or Q-Day simulation..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSend(input);
              }}
              disabled={isTyping}
            />
            <button
              className="chat-send-btn"
              onClick={() => handleSend(input)}
              disabled={!input.trim() || isTyping}
            >
              <Send size={18} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
