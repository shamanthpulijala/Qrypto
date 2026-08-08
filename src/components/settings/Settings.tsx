import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Key, Save, Moon, Sun, Monitor } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Settings.css';

export function Settings() {
  const [apiKey, setApiKey] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const key = localStorage.getItem('gemini_api_key');
    if (key) setApiKey(key);
  }, []);

  const handleSave = () => {
    localStorage.setItem('gemini_api_key', apiKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="settings-page animate-fade-in">
      <div className="sp-header">
        <div className="sph-left">
          <SettingsIcon size={24} className="sph-icon" />
          <div>
            <h2>Settings</h2>
            <p>Configure QuantumGuard AI preferences and integrations.</p>
          </div>
        </div>
      </div>

      <div className="settings-grid">
        <div className="card settings-card">
          <h4><Key size={18} /> API Configuration</h4>
          <p className="settings-desc">
            Enter your Google Gemini API key to enable the AI Security Consultant and Remediation Engine. 
            This key is stored locally in your browser and never sent to our servers.
          </p>
          <div className="settings-form">
            <label>Gemini API Key</label>
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
