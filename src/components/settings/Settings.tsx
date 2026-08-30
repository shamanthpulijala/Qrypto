import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Key, Save, Moon, Sun, Monitor } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Settings.css';

export function Settings() {
  const [apiKey, setApiKey] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    // API keys are stored server-side only. 
    // We intentionally do NOT fetch them to display in the UI.
    setApiKey('');
  }, []);

  const handleSave = async () => {
    try {
      await fetch('/api/settings/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey })
      });
      setApiKey(''); // Clear from state immediately after sending
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      console.error('Failed to save settings', e);
    }
  };

  return (
    <div className="settings-page animate-fade-in">
      <div className="sp-header">
        <div className="sph-left">
          <SettingsIcon size={24} className="sph-icon" />
          <div>
            <h2>Settings</h2>
            <p>Configure Qrypto AI preferences and integrations.</p>
          </div>
        </div>
      </div>

      <div className="settings-grid">
        <div className="card settings-card">
          <h4><Key size={18} /> API Configuration</h4>
          <p className="settings-desc">
            Enter your AI API key to enable the Qrypto AI Security Consultant. 
            This key is transmitted securely and stored server-side only. It is never persisted in the browser.
          </p>
          <div className="settings-form">
            <label>API Key (OpenRouter or Gemini)</label>
            <input
              type="password"
              className="input"
              placeholder="AIzaSy..."
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
            />
            <button className="btn btn-primary mt-4" onClick={handleSave}>
              <Save size={16} /> Save Configuration
            </button>
            {saved && <span className="save-success text-success ml-4">Saved successfully!</span>}
          </div>
        </div>
        
        <div className="card settings-card">
           <h4><Monitor size={18} /> Appearance</h4>
           <p className="settings-desc">Toggle application theme. (Dark mode is default for security console aesthetic).</p>
           <div className="theme-toggle">
             <button className="btn btn-ghost active"><Moon size={16} /> Dark</button>
             <button className="btn btn-ghost disabled" disabled><Sun size={16} /> Light (WIP)</button>
           </div>
        </div>
      </div>
    </div>
  );
}
