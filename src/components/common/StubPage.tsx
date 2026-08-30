// ============================================================
// Qrypto — StubPage
//
// An honest placeholder for pages that are not yet implemented.
// Clearly states what the page is and why it is not yet available.
// Never shows fake data or fabricated functionality.
// ============================================================

import React from 'react';
import { Construction } from 'lucide-react';

interface Props {
  title: string;
  description: string;
}

export function StubPage({ title, description }: Props) {
  return (
    <div className="page-container">
      <div className="empty-state">
        <div className="empty-state-icon" style={{ opacity: 0.7 }}>
          <Construction size={40} color="var(--text-tertiary)" />
        </div>
        <h2 style={{ color: 'var(--text-primary)', marginTop: '16px' }}>{title}</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '480px', textAlign: 'center', lineHeight: 1.6 }}>
          {description}
        </p>
        <div style={{
          marginTop: '20px',
          padding: '10px 16px',
          background: 'rgba(245, 184, 77, 0.08)',
          border: '1px solid rgba(245, 184, 77, 0.2)',
          borderRadius: '6px',
          fontSize: '0.8rem',
          color: '#F5B84D',
        }}>
          STATUS: NOT IMPLEMENTED
        </div>
      </div>
    </div>
  );
}
