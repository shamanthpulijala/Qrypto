// ============================================================
// QuantumGuard AI — Command Palette §41
// Ctrl+K global search — premium developer-tool feel
// ============================================================

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Search, LayoutDashboard, AlertTriangle, Zap, Network,
  Map, Bot, FileText, BarChart3, Settings, Shield
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './CommandPalette.css';

const NAV_COMMANDS = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard, group: 'Navigation' },
  { id: 'findings', label: 'Findings', icon: AlertTriangle, group: 'Navigation' },
  { id: 'qday', label: 'Q-Day Simulator', icon: Zap, group: 'Navigation' },
  { id: 'attackmap', label: 'Crypto Twin', icon: Network, group: 'Navigation' },
  { id: 'migration', label: 'Migration Planner', icon: Map, group: 'Navigation' },
  { id: 'ai', label: 'AI Advisor', icon: Bot, group: 'Navigation' },
  { id: 'agility', label: 'Crypto Agility', icon: BarChart3, group: 'Navigation' },
  { id: 'reports', label: 'Reports', icon: FileText, group: 'Navigation' },
  { id: 'settings', label: 'Settings', icon: Settings, group: 'Navigation' },
  { id: 'landing', label: 'Home', icon: Shield, group: 'Navigation' },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const { setCurrentPage, assessment } = useAppStore();

  // Build search items from nav + findings
  const allItems = React.useMemo(() => {
    const items = [...NAV_COMMANDS];
    if (assessment) {
      // Add algorithm search items
      const algos = new Set(assessment.findings.map(f => f.algorithm));
      algos.forEach(algo => {
        items.push({ id: `algo-${algo}`, label: algo, icon: Shield, group: 'Algorithms' });
      });
      // Add service search items
      const services = new Set(assessment.findings.map(f => f.service));
      services.forEach(svc => {
        items.push({ id: `svc-${svc}`, label: svc, icon: Network, group: 'Services' });
      });
    }
    return items;
  }, [assessment]);

  const filtered = query.trim()
    ? allItems.filter(i => i.label.toLowerCase().includes(query.toLowerCase()))
    : allItems.slice(0, 12);

  interface CommandItem {
    id: string;
    label: string;
    icon: React.ComponentType<{ size?: number }>;
    group: string;
  }

  // Group filtered items
  const groupedItems = React.useMemo(() => {
    const acc: Record<string, CommandItem[]> = {};
    (filtered as CommandItem[]).forEach(item => {
      if (!acc[item.group]) acc[item.group] = [];
      acc[item.group].push(item);
    });
    return acc;
  }, [filtered]);

  // Keyboard shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
        setQuery('');
        setActiveIndex(0);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const executeItem = useCallback((item: CommandItem) => {
    if (item.group === 'Navigation') {
      setCurrentPage(item.id);
    } else if (item.group === 'Algorithms') {
      setCurrentPage('findings');
    } else if (item.group === 'Services') {
      setCurrentPage('attackmap');
    }
    setOpen(false);
    setQuery('');
  }, [setCurrentPage]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex(i => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex(i => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && filtered[activeIndex]) {
      executeItem(filtered[activeIndex] as CommandItem);
    }
  };

  if (!open) return null;

  let flatIndex = 0;
  const groupKeys = Object.keys(groupedItems);

  return (
    <div className="cmd-overlay" onClick={() => setOpen(false)}>
      <div className="cmd-palette" onClick={e => e.stopPropagation()}>
        <div className="cmd-input-wrap">
          <Search size={16} />
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Search pages, algorithms, services..."
            value={query}
            onChange={e => { setQuery(e.target.value); setActiveIndex(0); }}
            onKeyDown={handleKeyDown}
          />
        </div>

        <div className="cmd-results">
          {filtered.length === 0 ? (
            <div className="cmd-empty">No results found</div>
          ) : (
            groupKeys.map(groupName => (
              <div key={groupName}>
                <div className="cmd-group-label">{groupName}</div>
                {groupedItems[groupName].map(item => {
                  const Icon = item.icon;
                  const idx = flatIndex++;
                  return (
                    <button
                      key={item.id}
                      className={`cmd-item ${idx === activeIndex ? 'active' : ''}`}
                      onClick={() => executeItem(item)}
                      onMouseEnter={() => setActiveIndex(idx)}
                    >
                      <Icon size={16} />
                      {item.label}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="cmd-footer">
          <span><span className="cmd-key">↑</span> <span className="cmd-key">↓</span> Navigate</span>
          <span><span className="cmd-key">↵</span> Select</span>
          <span><span className="cmd-key">Esc</span> Close</span>
        </div>
      </div>
    </div>
  );
}
