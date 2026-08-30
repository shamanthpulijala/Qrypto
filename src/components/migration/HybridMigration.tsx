import React from 'react';
import { Layers, Network, Lock, Zap, Shield, ChevronRight, Activity } from 'lucide-react';
import './HybridMigration.css';

export function HybridMigration() {
  return (
    <div className="hybrid-migration-page animate-fade-in">
      <div className="hybrid-header">
        <Layers size={24} className="text-accent-violet" />
        <h2>The Dual-Encapsulation Circuit</h2>
        <p>Interactive visualization of Hybrid Key Exchange combining classical (X25519) and post-quantum (ML-KEM) security.</p>
      </div>

      <div className="circuit-board card">
        <div className="circuit-grid">
          
          {/* LEFT: Client */}
          <div className="circuit-side client-side">
            <div className="endpoint">
              <ServerIcon />
              <h4>Client (Initiator)</h4>
            </div>
          </div>

          {/* CENTER: The Hybrid KEM Flow */}
          <div className="circuit-core">
            
            {/* Layer 1: Classical */}
            <div className="kem-layer classical-layer">
              <div className="layer-title"><Lock size={14} /> Classical KEM (X25519)</div>
              <div className="flow-track">
                <div className="pulse-packet classical-packet right"></div>
                <div className="pulse-packet classical-packet left"></div>
                <span className="track-label">ECDH Share</span>
              </div>
              <div className="secret-node">
                <div className="node-inner classical-secret">K1</div>
              </div>
            </div>

            {/* Layer 2: Post-Quantum */}
            <div className="kem-layer pqc-layer">
              <div className="layer-title"><Shield size={14} /> Post-Quantum KEM (ML-KEM-768)</div>
              <div className="flow-track">
                <div className="pulse-packet pqc-packet right"></div>
                <div className="pulse-packet pqc-packet left"></div>
                <span className="track-label">Ciphertext (1088B)</span>
              </div>
              <div className="secret-node">
                <div className="node-inner pqc-secret">K2</div>
              </div>
            </div>

            {/* The Combiner */}
            <div className="combiner-stage">
              <div className="combiner-lines">
                <div className="c-line c-top"></div>
                <div className="c-line c-bottom"></div>
              </div>
              
              <div className="kdf-node">
                <div className="kdf-core">
                  <Activity size={20} className="kdf-icon" />
                  <span>HKDF Combine</span>
                </div>
              </div>

              <div className="final-secret">
                <ChevronRight size={20} className="text-accent-cyan" />
                <div className="quantum-safe-key">
                  <Zap size={16} />
                  <span>Quantum-Safe Shared Secret</span>
                </div>
              </div>
            </div>

          </div>

          {/* RIGHT: Server */}
          <div className="circuit-side server-side">
            <div className="endpoint">
              <ServerIcon />
              <h4>Server (Responder)</h4>
            </div>
          </div>

        </div>
      </div>

      {/* Code Mapping Abstraction */}
      <div className="hybrid-code-mapping card">
        <div className="card-header">
          <h3><Network size={16} /> Implementation Mapping (TLS 1.3 Draft)</h3>
        </div>
        <div className="mapping-grid">
          <div className="map-block">
            <h4>SupportedGroups Extension</h4>
            <code>X25519_Kyber768Draft00 (0x6399)</code>
            <p>Signals support for hybrid key exchange.</p>
          </div>
          <div className="map-block">
            <h4>KeyShareEntry</h4>
            <code>struct &#123;<br/>
              &nbsp;&nbsp;opaque x25519_key_exchange[32];<br/>
              &nbsp;&nbsp;opaque kyber_key_exchange[1184];<br/>
            &#125;</code>
            <p>Concatenated public keys sent in ClientHello.</p>
          </div>
          <div className="map-block">
            <h4>Key Derivation</h4>
            <code>Secret = HKDF-Extract(<br/>
              &nbsp;&nbsp;salt,<br/>
              &nbsp;&nbsp;concat(K_x25519, K_kyber)<br/>
            )</code>
            <p>Ensures security if either algorithm remains unbroken.</p>
          </div>
        </div>
      </div>

    </div>
  );
}

function ServerIcon() {
  return (
    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="opacity-50">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
      <line x1="6" y1="6" x2="6.01" y2="6"></line>
      <line x1="6" y1="18" x2="6.01" y2="18"></line>
    </svg>
  );
}
