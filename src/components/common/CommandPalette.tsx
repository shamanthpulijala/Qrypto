// ============================================================
// Qrypto — Global Command Center (⌘/Ctrl+K) — §6, §7, §8
// Search-first, keyboard-first. Every item runs a REAL action
// wired to existing store state — no fabricated commands.
// Motion per §28.2; honours prefers-reduced-motion (§28.7).
// ============================================================

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Search, LayoutDashboard, AlertTriangle, Zap, Network, Map, Bot,
  FileText, BarChart3, Settings, Shield, Boxes, RefreshCw, FileDown,
  Home, ScanLine, KeyRound, GitBranch,
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './CommandPalette.css';

type Group = 'Navigation' | 'Investigation' | 'Actions';

interface CommandItem {
  id: string;
  label: string;
  hint?: string;                 // right-aligned context (shortcut / metadata)
  icon: React.ComponentType<{ size?: number }>;
  group: Group;
  keywords?: string;             // extra fuzzy-match surface
  run: () => void;
}

/** Subsequence fuzzy match — returns a score (higher = better) or -1 for no match.
 *  Rewards contiguous runs and word-boundary starts, so "rsaf" ranks
 *  "Show RSA findings" above an incidental scatter match. */
function fuzzyScore(query: string, target: string): number {
  if (!query) return 0;
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  let qi = 0;
  let score = 0;
  let streak = 0;
  let prev = -1;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      streak = ti === prev + 1 ? streak + 1 : 0;
      score += 1 + streak * 2;
      if (ti === 0 || /[\s./:_-]/.test(t[ti - 1])) score += 3; // word-boundary bonus
      prev = ti;
      qi++;
    }
  }
  return qi === q.length ? score : -1;
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [closing, setClosing] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const {
    assessment, qdayActive,
    setCurrentPage, clearAssessment, runQDaySimulation, resetQDaySimulation,
  } = useAppStore();

  const go = useCallback((page: string) => () => setCurrentPage(page), [setCurrentPage]);

  // ── Build the command set from REAL state only ────────────
  const items = useMemo<CommandItem[]>(() => {
    const nav: CommandItem[] = [
      { id: 'nav-dashboard', label: 'Overview', icon: LayoutDashboard, group: 'Navigation', run: go('dashboard') },
      { id: 'nav-findings', label: 'Findings', icon: AlertTriangle, group: 'Navigation', run: go('findings') },
      { id: 'nav-inventory', label: 'Cryptographic Inventory', icon: Boxes, group: 'Navigation', keywords: 'crypto assets algorithms', run: go('inventory') },
      { id: 'nav-qday', label: 'Quantum Assessment', icon: Zap, group: 'Navigation', keywords: 'q-day mosca risk', run: go('qday') },
      { id: 'nav-attackmap', label: 'Crypto Relationship Graph', icon: Network, group: 'Navigation', keywords: 'attack map twin', run: go('attackmap') },
      { id: 'nav-hndl', label: 'Harvest-Now-Decrypt-Later', icon: KeyRound, group: 'Navigation', keywords: 'hndl long-lived', run: go('hndl') },
      { id: 'nav-migration', label: 'Migration Planner', icon: Map, group: 'Navigation', keywords: 'remediation roadmap pqc', run: go('migration') },
      { id: 'nav-agility', label: 'Crypto Agility', icon: BarChart3, group: 'Navigation', run: go('agility') },
      { id: 'nav-ai', label: 'AI Security Consultant', icon: Bot, group: 'Navigation', keywords: 'advisor', run: go('ai') },
      { id: 'nav-reports', label: 'Reports', icon: FileText, group: 'Navigation', run: go('reports') },
      { id: 'nav-settings', label: 'Settings', icon: Settings, group: 'Navigation', keywords: 'api key provider appearance', run: go('settings') },
    ];

    const actions: CommandItem[] = [];
    if (assessment) {
      actions.push(
        { id: 'act-rescan', label: 'Re-scan / New scan', hint: 'clears current assessment', icon: RefreshCw, group: 'Actions', keywords: 'scan repository', run: () => clearAssessment() },
        { id: 'act-qday', label: qdayActive ? 'Exit Q-Day simulation' : 'Run Q-Day simulation', icon: Zap, group: 'Actions', run: () => (qdayActive ? resetQDaySimulation() : runQDaySimulation()) },
        // Report/CBOM/export live in the Reports workspace — open the real
        // destination rather than fake an invocation. (See flag in handoff notes.)
        { id: 'act-report', label: 'Generate Technical Report', hint: 'Reports', icon: FileText, group: 'Actions', run: go('reports') },
        { id: 'act-cbom', label: 'Export CBOM (CycloneDX)', hint: 'Reports', icon: FileDown, group: 'Actions', keywords: 'sbom bill of materials', run: go('reports') },
        { id: 'act-export-findings', label: 'Export Current Findings', hint: 'Reports', icon: FileDown, group: 'Actions', run: go('reports') },
      );
    } else {
      actions.push(
        { id: 'act-home', label: 'Start a scan', hint: 'Home', icon: Home, group: 'Actions', run: go('landing') },
      );
    }

    // Investigation — derived entirely from real scan findings (§7, §8)
    const investigation: CommandItem[] = [];
    if (assessment?.findings?.length) {
      const algos = Array.from(new Set(assessment.findings.map(f => f.algorithm).filter(Boolean)));
      algos.forEach(algo => {
        const count = assessment.findings.filter(f => f.algorithm === algo).length;
        investigation.push({
          id: `inv-algo-${algo}`, label: `Show ${algo} findings`, hint: `${count} finding${count === 1 ? '' : 's'}`,
          icon: ScanLine, group: 'Investigation', keywords: `${algo} algorithm crypto`, run: go('findings'),
        });
      });
      const services = Array.from(new Set(assessment.findings.map(f => f.service).filter(Boolean)));
      services.forEach(svc => {
        investigation.push({
          id: `inv-svc-${svc}`, label: `Inspect service: ${svc}`, hint: 'graph',
          icon: GitBranch, group: 'Investigation', keywords: `${svc} service component`, run: go('attackmap'),
        });
      });
    }

    return [...nav, ...actions, ...investigation];
  }, [assessment, qdayActive, go, clearAssessment, runQDaySimulation, resetQDaySimulation]);

  // ── Filter + rank ─────────────────────────────────────────
  const filtered = useMemo(() => {
    const q = query.trim();
    if (!q) {
      // Default view: nav + actions, investigation hidden until searched
      return items.filter(i => i.group !== 'Investigation').slice(0, 12);
    }
    return items
      .map(i => ({ i, s: Math.max(fuzzyScore(q, i.label), fuzzyScore(q, i.keywords || '') - 2) }))
      .filter(x => x.s >= 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 24)
      .map(x => x.i);
  }, [items, query]);

  // Preserve declared group order regardless of ranking
  const grouped = useMemo(() => {
    const order: Group[] = ['Navigation', 'Investigation', 'Actions'];
    const acc: Record<string, CommandItem[]> = {};
    filtered.forEach(i => { (acc[i.group] ||= []).push(i); });
    return order.filter(g => acc[g]?.length).map(g => [g, acc[g]] as const);
  }, [filtered]);

  // Flat order that matches render order, for arrow-key navigation
  const flat = useMemo(() => grouped.flatMap(([, list]) => list), [grouped]);

  // ── Open / close with motion-aware unmount ────────────────
  const close = useCallback(() => {
    setClosing(true);
    window.setTimeout(() => { setOpen(false); setClosing(false); }, 120); // matches --duration-fast
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
        setClosing(false);
        setQuery('');
        setActiveIndex(0);
      } else if (e.key === 'Escape' && open) {
        e.preventDefault();
        close();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, close]);

  useEffect(() => { if (open) inputRef.current?.focus(); }, [open]);
  useEffect(() => { setActiveIndex(0); }, [query]);

  // Keep the active row scrolled into view
  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.querySelector<HTMLElement>(`[data-idx="${activeIndex}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex, open]);

  const execute = useCallback((item: CommandItem) => {
    item.run();
    close();
    setQuery('');
  }, [close]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIndex(i => Math.min(i + 1, flat.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIndex(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter' && flat[activeIndex]) { e.preventDefault(); execute(flat[activeIndex]); }
  };

  if (!open) return null;

  let idx = -1;
  return (
    <div
      className={`cmd-overlay ${closing ? 'closing' : ''}`}
      onClick={close}
      role="presentation"
    >
      <div
        className={`cmd-palette ${closing ? 'closing' : ''}`}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Command center"
      >
        <div className="cmd-input-wrap">
          <Search size={16} aria-hidden />
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Search commands, findings, algorithms, services…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            role="combobox"
            aria-expanded="true"
            aria-controls="cmd-listbox"
            aria-activedescendant={flat[activeIndex] ? `cmd-opt-${flat[activeIndex].id}` : undefined}
            autoComplete="off"
            spellCheck={false}
          />
          {!assessment && <span className="cmd-scope-tag" title="No scan loaded">NO SCAN</span>}
        </div>

        <div className="cmd-results" id="cmd-listbox" role="listbox" ref={listRef}>
          {flat.length === 0 ? (
            <div className="cmd-empty">No matching commands</div>
          ) : (
            grouped.map(([group, list]) => (
              <div key={group} className="cmd-group">
                <div className="cmd-group-label">{group}</div>
                {list.map(item => {
                  idx++;
                  const active = idx === activeIndex;
                  const Icon = item.icon;
                  const rowIdx = idx;
                  return (
                    <button
                      key={item.id}
                      id={`cmd-opt-${item.id}`}
                      data-idx={rowIdx}
                      role="option"
                      aria-selected={active}
                      className={`cmd-item ${active ? 'active' : ''}`}
                      style={{ animationDelay: `${Math.min(rowIdx, 6) * 15}ms` }}
                      onClick={() => execute(item)}
                      onMouseMove={() => setActiveIndex(rowIdx)}
                    >
                      <Icon size={16} />
                      <span className="cmd-item-label">{item.label}</span>
                      {item.hint && <span className="cmd-item-hint">{item.hint}</span>}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="cmd-footer">
          <span><span className="cmd-key">↑</span><span className="cmd-key">↓</span> Navigate</span>
          <span><span className="cmd-key">↵</span> Select</span>
          <span><span className="cmd-key">Esc</span> Close</span>
        </div>
      </div>
    </div>
  );
}
