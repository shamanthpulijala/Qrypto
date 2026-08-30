import React, { useMemo, useCallback, useState } from 'react';
import { Network, Search, AlertTriangle, ShieldCheck, X, Zap, ArrowRight, Shield, Database, Lock, Server } from 'lucide-react';
import type { Node, Edge, NodeChange } from '@xyflow/react';
import {
  ReactFlow, Background, Controls,
  Handle, Position, BackgroundVariant, applyNodeChanges
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useAppStore } from '../../store/assessmentStore';
import type { ServiceNode } from '../../types';
import { getUsageAwareRecommendation } from '../../engine/migrationPlanner';
import './AttackMap.css';

// ─── Custom Node Component ─────────────────────────────────────

function ServiceNodeComponent({ data }: { data: any }) {
  const { qdayActive } = useAppStore();

  const isVuln = data.isVulnerable;
  const isQDayAffected = qdayActive && data.isQDayAffected;
  const isSelected = data.isSelected;

  let headerClass = 'node-header-ok';
  if (isQDayAffected) headerClass = 'node-header-qday';
  else if (isVuln) headerClass = 'node-header-vuln';

  return (
    <div className={`attack-node ${isQDayAffected ? 'node-pulse' : ''} ${isSelected ? 'node-selected' : ''}`}>
      <Handle type="target" position={Position.Top} className="node-handle" />
      <div className={`node-header ${headerClass}`}>
        <span className="node-name">{data.label}</span>
      </div>
      <div className="node-body">
        <div className="nb-row">
          <span className="nb-label">Risk</span>
          <span className="nb-val" style={{ color: data.riskScore >= 70 ? '#F5484B' : data.riskScore >= 40 ? '#F5B84D' : '#4CAF6D' }}>
            {data.riskScore}/100
          </span>
        </div>
        <div className="nb-row">
          <span className="nb-label">Data</span>
          <span className="nb-val">{data.dataSensitivity}</span>
        </div>
        {data.cryptoFindings.length > 0 && (
          <div className="nb-findings">
            {data.cryptoFindings.length} findings
          </div>
        )}
        {data.internetFacing && (
          <div className="nb-internet">🌐 Internet Facing</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="node-handle" />
    </div>
  );
}

const nodeTypes = { service: ServiceNodeComponent };

// ─── Main Component ───────────────────────────────────────────

export function AttackMap() {
  const { assessment, qdayActive, runQDaySimulation, resetQDaySimulation } = useAppStore();
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'high' | 'vulnerable' | 'qday'>('all');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const selectedService = useMemo(() => {
    if (!assessment || !selectedNodeId) return null;
    return assessment.services.find(s => s.id === selectedNodeId) || null;
  }, [assessment, selectedNodeId]);

  const selectedServiceFindings = useMemo(() => {
    if (!assessment || !selectedService) return [];
    return assessment.findings.filter(f => f.service === selectedService.name);
  }, [assessment, selectedService]);

  const graphData = useMemo(() => {
    if (!assessment) return { initialNodes: [], initialEdges: [] };

    const { services, findings, qDaySimulation } = assessment;

    let filteredServices = services;

    if (riskFilter === 'high') {
      filteredServices = services.filter(s => s.riskScore >= 60);
    } else if (riskFilter === 'vulnerable') {
      filteredServices = services.filter(s => findings.some(f => f.service === s.name && f.quantumStatus === 'vulnerable'));
    } else if (riskFilter === 'qday') {
      filteredServices = services.filter(s => qDaySimulation?.affectedServices.some(af => af.id === s.id));
    }

    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      filteredServices = filteredServices.filter(s =>
        s.name.toLowerCase().includes(term) ||
        s.type.toLowerCase().includes(term) ||
        s.cryptoFindings.some(c => c.toLowerCase().includes(term))
      );
    }

    const initialNodes: Node[] = filteredServices.map(svc => {
      const svcFindings = findings.filter(f => f.service === svc.name);
      const isVulnerable = svcFindings.some(f => f.quantumStatus === 'vulnerable');
      const isQDayAffected = qdayActive && qDaySimulation?.affectedServices.some(s => s.id === svc.id);

      return {
        id: svc.id,
        type: 'service',
        position: svc.position || { x: Math.random() * 500, y: Math.random() * 500 },
        data: {
          label: svc.name,
          type: svc.type,
          internetFacing: svc.internetFacing,
          dataSensitivity: svc.dataSensitivity,
          cryptoFindings: svc.cryptoFindings,
          riskScore: svc.riskScore,
          isVulnerable,
          isQDayAffected,
          isSelected: svc.id === selectedNodeId,
        },
      };
    });

    const filteredIds = new Set(filteredServices.map(s => s.id));

    const initialEdges: Edge[] = [];
    filteredServices.forEach(svc => {
      svc.dependencies.forEach(dep => {
        if (!filteredIds.has(dep)) return;

        const isQDayAffected = qdayActive &&
                               qDaySimulation?.affectedServices.some(s => s.id === svc.id) &&
                               qDaySimulation?.affectedServices.some(s => s.id === dep);

        initialEdges.push({
          id: `e-${dep}-${svc.id}`,
          source: dep,
          target: svc.id,
          animated: isQDayAffected,
          style: {
            stroke: isQDayAffected ? '#F5484B' : '#334155',
            strokeWidth: isQDayAffected ? 2.5 : 1,
            opacity: isQDayAffected ? 1 : 0.5,
          },
        });
      });
    });

    return { initialNodes, initialEdges };
  }, [assessment, qdayActive, searchTerm, riskFilter, selectedNodeId]);

  React.useEffect(() => {
    setNodes(graphData.initialNodes);
    setEdges(graphData.initialEdges);
  }, [graphData]);

  const onNodesChange = useCallback(
    (changes: NodeChange<Node>[]) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
  };

  if (!assessment) return null;

  return (
    <div className="attack-map-page animate-fade-in">
      <div className="am-header">
        <div className="amh-left">
          <Network size={24} className="amh-icon" />
          <div>
            <h2>Attack Path &amp; Dependency Graph</h2>
            <p>Visualize how quantum vulnerabilities propagate through service dependencies.</p>
          </div>
        </div>

        <div className="amh-controls">
          {/* Search */}
          <div className="search-box">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              placeholder="Search service or crypto..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="input search-input"
            />
          </div>

          {/* Risk filter */}
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value as any)}
            className="input filter-select"
          >
            <option value="all">All Risks</option>
            <option value="high">High Risk (60+)</option>
            <option value="vulnerable">Quantum Vulnerable</option>
            <option value="qday">Q-Day Impacted</option>
          </select>

          {/* Q-Day Simulation Toggle */}
          <button
            className={`btn ${qdayActive ? 'btn-danger' : 'btn-secondary'} qday-toggle-btn`}
            onClick={() => qdayActive ? resetQDaySimulation() : runQDaySimulation()}
          >
            <Zap size={14} />
            {qdayActive ? 'Reset Q-Day' : 'Q-Day Simulation'}
          </button>
        </div>
      </div>

      <div className="map-layout">
        <div className="card map-container">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.4}
            maxZoom={2.5}
            proOptions={{ hideAttribution: true }}
            className="qg-flow"
          >
            <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#334155" />
            <Controls className="qg-controls" showInteractive={false} />
          </ReactFlow>

          {qdayActive && (
            <div className="map-overlay-warning">
              <AlertTriangle size={16} />
              <span>Q-Day Simulation active. Red pulsing paths indicate quantum attack propagation.</span>
            </div>
          )}
        </div>

        {/* §29 Node Selection Inspector Sidebar */}
        {selectedService && (
          <div className="node-inspector card animate-slide-in">
            <div className="ni-header">
              <h3>Service Details</h3>
              <button className="ni-close" onClick={() => setSelectedNodeId(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="ni-body">
              {/* Service */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <Server size={16} /> Service
                </div>
                <div className="ni-row">
                  <span className="ni-label">Name</span>
                  <span className="ni-val-strong">{selectedService.name}</span>
                </div>
                <div className="ni-row">
                  <span className="ni-label">Type</span>
                  <span className="ni-val">{selectedService.type}</span>
                </div>
                <div className="ni-row">
                  <span className="ni-label">Exposure</span>
                  <span className="ni-val" style={{ color: selectedService.internetFacing ? '#4DD0E1' : '#94a3b8' }}>
                    {selectedService.internetFacing ? '🌐 Internet Facing' : '🔒 Internal Only'}
                  </span>
                </div>
              </div>

              {/* Risk */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <AlertTriangle size={16} /> Risk
                </div>
                <div className="ni-row">
                  <span className="ni-label">Risk Score</span>
                  <span className="ni-val-strong" style={{ color: selectedService.riskScore >= 70 ? '#F5484B' : selectedService.riskScore >= 40 ? '#F5B84D' : '#4CAF6D' }}>
                    {selectedService.riskScore} / 100
                  </span>
                </div>
                <div className="ni-row">
                  <span className="ni-label">Vulnerability</span>
                  <span className="ni-val">
                    {selectedServiceFindings.some(f => f.quantumStatus === 'vulnerable') ? (
                      <span className="badge badge-high">Quantum Vulnerable</span>
                    ) : (
                      <span className="badge badge-low">Quantum Safe</span>
                    )}
                  </span>
                </div>
              </div>

              {/* Crypto */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <Lock size={16} /> Crypto
                </div>
                <div className="ni-chips">
                  {selectedService.cryptoFindings.length > 0 ? (
                    selectedService.cryptoFindings.map((cf, i) => (
                      <span key={i} className="ni-chip">{cf}</span>
                    ))
                  ) : (
                    <span className="ni-val">No explicit crypto primitives flagged.</span>
                  )}
                </div>
                {selectedServiceFindings.length > 0 && (
                  <div className="ni-findings-list mt-2">
                    <span className="ni-label">Detected Findings ({selectedServiceFindings.length}):</span>
                    {selectedServiceFindings.map(f => (
                      <div key={f.id} className="ni-finding-item">
                        <span className="mono">{f.id}</span> — {f.algorithm} ({f.severity})
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Data */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <Database size={16} /> Data
                </div>
                <div className="ni-row">
                  <span className="ni-label">Sensitivity</span>
                  <span className="ni-val-strong">{selectedService.dataSensitivity}</span>
                </div>
                <div className="ni-row">
                  <span className="ni-label">Max Lifetime</span>
                  <span className="ni-val">
                    {Math.max(...selectedServiceFindings.map(f => f.dataLifetimeYears), 5)} years
                  </span>
                </div>
              </div>

              {/* Dependencies */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <Network size={16} /> Dependencies
                </div>
                <div className="ni-row">
                  <span className="ni-label">Depends On</span>
                  <span className="ni-val">
                    {selectedService.dependencies.length > 0 ? (
                      selectedService.dependencies.map(depId => {
                        const depSvc = assessment.services.find(s => s.id === depId);
                        return depSvc ? depSvc.name : depId;
                      }).join(', ')
                    ) : 'None'}
                  </span>
                </div>
              </div>

              {/* Recommendations */}
              <div className="ni-section">
                <div className="ni-section-title">
                  <ShieldCheck size={16} /> Recommendations
                </div>
                {selectedServiceFindings.length > 0 ? (
                  selectedServiceFindings.slice(0, 2).map((f, i) => {
                    const rec = getUsageAwareRecommendation(f.algorithm, f.usage);
                    return (
                      <div key={i} className="ni-rec-card">
                        <div className="ni-rec-replacement">
                          <span className="badge badge-cyan">{rec.replacement}</span>
                        </div>
                        <p className="ni-rec-strategy">{rec.strategy}</p>
                      </div>
                    );
                  })
                ) : (
                  <p className="ni-val">Maintain modern crypto hygiene and monitor for new algorithm deprecations.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
