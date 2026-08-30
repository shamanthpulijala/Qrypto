import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Key, Save, Cloud, Server, AlertTriangle, CheckCircle2, Trash2 } from 'lucide-react';
import './Settings.css';

const AWS_KEY_STORAGE_KEY = 'qg_aws_access_key_id';
const AWS_SECRET_STORAGE_KEY = 'qg_aws_secret_access_key';
const AWS_REGION_STORAGE_KEY = 'qg_aws_region';

export function Settings() {
  const [apiKey, setApiKey] = useState('');
  const [saved, setSaved] = useState(false);

  // AWS credentials (in-memory only)
  const [awsKeyId, setAwsKeyId] = useState('');
  const [awsSecret, setAwsSecret] = useState('');
  const [awsRegion, setAwsRegion] = useState('us-east-1');
  const [awsSaved, setAwsSaved] = useState(false);
  const [awsConfigured, setAwsConfigured] = useState(false);

  useEffect(() => {
    setApiKey('');
    // Load AWS config (stored in sessionStorage — cleared when tab closes)
    const storedKeyId = sessionStorage.getItem(AWS_KEY_STORAGE_KEY) || '';
    const storedRegion = sessionStorage.getItem(AWS_REGION_STORAGE_KEY) || 'us-east-1';
    setAwsRegion(storedRegion);
    setAwsConfigured(!!storedKeyId);
  }, []);

  const handleSave = async () => {
    try {
      await fetch('/api/settings/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey })
      });
      setApiKey('');
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      console.error('Failed to save settings', e);
    }
  };

  const handleAwsSave = () => {
    if (!awsKeyId.trim() || !awsSecret.trim()) return;
    // Store in sessionStorage (cleared on tab/browser close — never persisted to disk)
    sessionStorage.setItem(AWS_KEY_STORAGE_KEY, awsKeyId.trim());
    sessionStorage.setItem(AWS_SECRET_STORAGE_KEY, awsSecret.trim());
    sessionStorage.setItem(AWS_REGION_STORAGE_KEY, awsRegion.trim());
    // Clear from React state immediately
    setAwsKeyId('');
    setAwsSecret('');
    setAwsConfigured(true);
    setAwsSaved(true);
    setTimeout(() => setAwsSaved(false), 2500);
  };

  const handleAwsClear = () => {
    sessionStorage.removeItem(AWS_KEY_STORAGE_KEY);
    sessionStorage.removeItem(AWS_SECRET_STORAGE_KEY);
    sessionStorage.removeItem(AWS_REGION_STORAGE_KEY);
    setAwsKeyId('');
    setAwsSecret('');
    setAwsConfigured(false);
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
        {/* AI API Key */}
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

        {/* AWS KMS Live Scan Credentials */}
        <div className="card settings-card aws-card">
          <h4><Cloud size={18} /> AWS KMS Live Scan</h4>
          <p className="settings-desc">
            Provide temporary AWS credentials to enable live polling of your AWS KMS environment.
            Credentials are stored only in <strong>session memory</strong> (cleared when you close this tab) 
            and are never sent to any server other than AWS directly.
          </p>

          {awsConfigured && !awsKeyId && (
            <div className="aws-status-badge aws-status-active">
              <CheckCircle2 size={15} />
              <span>AWS credentials active for this session. The next scan will include live KMS findings.</span>
              <button className="btn btn-sm btn-ghost" onClick={handleAwsClear} title="Clear credentials">
                <Trash2 size={13} /> Clear
              </button>
            </div>
          )}

          <div className="aws-warning">
            <AlertTriangle size={14} />
            <span>Use read-only credentials. Required IAM policy: <code>kms:ListKeys</code>, <code>kms:DescribeKey</code>.</span>
          </div>

          <div className="settings-form">
            <label>AWS Access Key ID</label>
            <input
              type="password"
              className="input"
              placeholder="AKIAIOSFODNN7EXAMPLE"
              value={awsKeyId}
              onChange={e => setAwsKeyId(e.target.value)}
              autoComplete="off"
            />

            <label style={{ marginTop: '12px' }}>AWS Secret Access Key</label>
            <input
              type="password"
              className="input"
              placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              value={awsSecret}
              onChange={e => setAwsSecret(e.target.value)}
              autoComplete="off"
            />

            <label style={{ marginTop: '12px' }}>AWS Region</label>
            <select
              className="input"
              value={awsRegion}
              onChange={e => setAwsRegion(e.target.value)}
            >
              {[
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-central-1',
                'ap-south-1', 'ap-southeast-1', 'ap-northeast-1',
              ].map(r => <option key={r} value={r}>{r}</option>)}
            </select>

            <button
              className="btn btn-primary mt-4"
              onClick={handleAwsSave}
              disabled={!awsKeyId.trim() || !awsSecret.trim()}
            >
              <Server size={16} /> Activate for This Session
            </button>
            {awsSaved && <span className="save-success text-success ml-4">Credentials saved! Upload files to trigger live KMS scan.</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
