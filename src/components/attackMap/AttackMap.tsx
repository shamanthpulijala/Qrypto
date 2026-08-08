import React, { useMemo, useCallback } from 'react';
import { Network, Search, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';
import type { Node, Edge, NodeChange } from '@xyflow/react';
import {
  ReactFlow, Background, Controls,
  Handle, Position, BackgroundVariant, applyNodeChanges
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useAppStore } from '../../store/assessmentStore';
import type { ServiceNode } from '../../types';
import './AttackMap.css';

// ─── Custom Node Component ─────────────────────────────────────

function ServiceNodeComponent({ data }: { data: any }) {
  const { qdayActive } = useAppStore();

  const isVuln = data.isVulnerable;
  const isQDayAffected = qdayActive && data.isQDayAffected;

  let headerClass = 'node-header-ok';
  if (isQDayAffected) headerClass = 'node-header-qday';
  else if (isVuln) headerClass = 'node-header-vuln';

  return (
    <div className={`attack-node ${isQDayAffected ? 'node-pulse' : ''}`}>
      <Handle type="target" position={Position.Top} className="node-handle" />
      <div className={`node-header ${headerClass}`}>
        <span className="node-name">{data.label}</span>
      </div>
      <div className="node-body">
        <div className="nb-row">
          <span className="nb-label">Risk</span>
          <span className="nb-val" style={{ color: data.riskScore >= 70 ? '#ef4444' : data.riskScore >= 40 ? '#eab308' : '#22c55e' }}>
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
  const { assessment, qdayActive } = useAppStore();
  const [nodes, setNodes] = React.useState<Node[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);

  const graphData = useMemo(() => {
    if (!assessment) return { initialNodes: [], initialEdges: [] };

    const { services, findings, qDaySimulation } = assessment;

    const initialNodes: Node[] = services.map(svc => {
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
        },
      };
    });

    const initialEdges: Edge[] = [];
    services.forEach(svc => {
      svc.dependencies.forEach(dep => {
        const isQDayAffected = qdayActive &&
                               qDaySimulation?.affectedServices.some(s => s.id === svc.id) &&
                               qDaySimulation?.affectedServices.some(s => s.id === dep);

        initialEdges.push({
          id: `e-${dep}-${svc.id}`,
          source: dep,
          target: svc.id,
          animated: isQDayAffected,
          style: {
            stroke: isQDayAffected ? '#ef4444' : '#334155',
            strokeWidth: isQDayAffected ? 2 : 1,
            opacity: isQDayAffected ? 1 : 0.5,
          },
        });
      });
    });

    return { initialNodes, initialEdges };
  }, [assessment, qdayActive]);

  React.useEffect(() => {
    setNodes(graphData.initialNodes);
    setEdges(graphData.initialEdges);
  }, [graphData]);

  const onNodesChange = useCallback(
    (changes: NodeChange<Node>[]) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );

  if (!assessment) return null;

  return (
    <div className="attack-map-page animate-fade-in">
      <div className="am-header">
        <div className="amh-left">
          <Network size={24} className="amh-icon" />
          <div>
            <h2>Attack Path & Dependency Graph</h2>
            <p>Visualize how quantum vulnerabilities propagate through service dependencies.</p>
          </div>
        </div>
        <div className="amh-right">
          <div className="legend">
            <div className="lg-item"><div className="lg-color ok" /> Secure</div>
            <div className="lg-item"><div className="lg-color warn" /> Vulnerable Algo</div>
            <div className="lg-item"><div className="lg-color danger" /> Q-Day Affected Path</div>
          </div>
        </div>
      </div>

      <div className="card map-container">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.5}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          className="qg-flow"
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#334155" />
          <Controls className="qg-controls" showInteractive={false} />
        </ReactFlow>
        
        {qdayActive && (
          <div className="map-overlay-warning">
            <AlertTriangle size={16} />
            <span>Q-Day Simulation active. Red paths indicate simulated quantum attack propagation.</span>
          </div>
        )}
      </div>
    </div>
  );
}
