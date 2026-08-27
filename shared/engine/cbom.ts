// ============================================================
// Qrypto — CycloneDX 1.6 CBOM Generator
//
// Generates a spec-conformant CycloneDX 1.6 Cryptographic Bill
// of Materials from scan findings. Uses the algorithm registry
// for canonical names, primitives, and OID mappings.
//
// Reference: https://cyclonedx.org/specification/overview/
// CycloneDX 1.6 uses "cryptographic-asset" type for crypto
// components, not the invalid "cryptography" or "secret-material"
// that the Phase 0 stub used.
// ============================================================

import type { Finding, QuantumStatus } from '../types';
import { lookupAlgorithm, type AlgorithmEntry } from './registry';

// ─── CycloneDX 1.6 Types (subset) ─────────────────────────────

interface CycloneDXBOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.6';
  version: number;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    component?: { type: string; name: string };
  };
  components: CycloneDXComponent[];
  vulnerabilities?: any[];
}

interface CycloneDXComponent {
  type: string;               // "cryptographic-asset" in 1.6
  'bom-ref': string;
  name: string;               // canonical algorithm name
  version?: string;           // key size or version string
  description?: string;
  cryptoProperties?: {
    assetType: string;        // "algorithm", "protocol", "certificate", "key"
    algorithmProperties?: {
      primitive?: string;     // CycloneDX primitive
      parameterSetIdentifier?: string;
      curve?: string;
      oids?: string[];
    };
    certificateProperties?: any;
    protocolProperties?: any;
  };
  evidence?: {
    occurrences: {
      location: string;
      line?: number;
      offset?: number;
      symbol?: string;
      additionalContext?: string;
    }[];
  };
  properties?: { name: string; value: string }[];
}

// ─── CycloneDX Asset Type Mapping ─────────────────────────────

function mapAssetType(category: string): string {
  switch (category) {
    case 'secret': return 'key-material';
    case 'certificate': return 'certificate';
    case 'tls': return 'protocol';
    default: return 'algorithm';
  }
}

// ─── Quantum Status to CycloneDX Property ─────────────────────

function quantumStatusToProperties(qs: QuantumStatus): { name: string; value: string }[] {
  const props: { name: string; value: string }[] = [
    { name: 'qrypto:quantumStatus', value: qs },
  ];
  if (qs === 'vulnerable') {
    props.push({ name: 'qrypto:quantumRisk', value: 'quantum-vulnerable' });
  } else if (qs === 'quantum-resistant') {
    props.push({ name: 'qrypto:quantumRisk', value: 'quantum-safe' });
  } else if (qs === 'classical-weak') {
    props.push({ name: 'qrypto:quantumRisk', value: 'classically-deprecated' });
  }
  return props;
}

// ─── Main Generator ───────────────────────────────────────────

export interface CBOMOptions {
  projectName?: string;
  toolVersion?: string;
}

/**
 * Generate a CycloneDX 1.6 CBOM from scan findings.
 *
 * Each unique algorithm+keySize+category combination becomes one
 * component. Evidence (file locations) is attached per component.
 * The output is spec-conformant and can be validated against the
 * CycloneDX 1.6 JSON schema.
 */
export function generateCBOM(
  findings: Finding[],
  options: CBOMOptions = {}
): CycloneDXBOM {
  // Group findings by canonical algorithm + key size
  const grouped = new Map<string, {
    entry: AlgorithmEntry;
    keySize?: number;
    findings: Finding[];
  }>();

  for (const f of findings) {
    const entry = lookupAlgorithm(f.algorithm);
    const key = `${entry.canonicalName}:${f.keySize ?? 'none'}:${f.category}`;
    if (!grouped.has(key)) {
      grouped.set(key, { entry, keySize: f.keySize, findings: [] });
    }
    grouped.get(key)!.findings.push(f);
  }

  // Build components
  const components: CycloneDXComponent[] = [];
  for (const [, group] of grouped) {
    const { entry, keySize, findings: groupFindings } = group;
    const primary = groupFindings[0]; // representative finding

    const component: CycloneDXComponent = {
      type: 'cryptographic-asset',
      'bom-ref': `crypto-${entry.canonicalName.replace(/\s+/g, '-').toLowerCase()}${keySize ? `-${keySize}` : ''}`,
      name: entry.canonicalName,
      description: [
        `Algorithm: ${entry.canonicalName}`,
        entry.nistStandard ? `NIST Standard: ${entry.nistStandard}` : '',
        `Quantum Status: ${primary.quantumStatus}`,
        `Classical Status: ${primary.classicalStatus}`,
        entry.pqcReplacement ? `PQC Replacement: ${entry.pqcReplacement}` : '',
        `Occurrences: ${groupFindings.length} finding(s) across ${[...new Set(groupFindings.map(f => f.service))].join(', ')}`,
      ].filter(Boolean).join('. '),
      cryptoProperties: {
        assetType: mapAssetType(primary.category),
        algorithmProperties: {
          primitive: entry.cycloneDxPrimitive,
          parameterSetIdentifier: keySize?.toString(),
          oids: entry.oid ? [entry.oid] : undefined,
        },
      },
      evidence: {
        occurrences: groupFindings.map(f => ({
          location: `${f.file}#L${f.line}`,
          line: f.line,
          offset: 0,
          symbol: f.algorithm,
          additionalContext: f.detectedPattern,
        })),
      },
      properties: [
        ...quantumStatusToProperties(primary.quantumStatus),
        { name: 'qrypto:severity', value: primary.severity },
        { name: 'qrypto:riskScore', value: String(primary.riskScore) },
        { name: 'qrypto:category', value: primary.category },
        { name: 'qrypto:usage', value: primary.usage },
        { name: 'qrypto:occurrences', value: String(groupFindings.length) },
        ...(entry.pqcReplacement ? [{ name: 'qrypto:pqcReplacement', value: entry.pqcReplacement }] : []),
        ...(entry.pqcStandard ? [{ name: 'qrypto:pqcStandard', value: entry.pqcStandard }] : []),
        ...(primary.migrationStrategy ? [{ name: 'qrypto:migrationStrategy', value: primary.migrationStrategy }] : []),
      ],
    };

    components.push(component);
  }

  // Sort by severity (critical first) then by occurrence count
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  components.sort((a, b) => {
    const aSev = a.properties?.find(p => p.name === 'qrypto:severity')?.value ?? 'medium';
    const bSev = b.properties?.find(p => p.name === 'qrypto:severity')?.value ?? 'medium';
    const aOrder = severityOrder[aSev as keyof typeof severityOrder] ?? 2;
    const bOrder = severityOrder[bSev as keyof typeof severityOrder] ?? 2;
    if (aOrder !== bOrder) return aOrder - bOrder;
    const aCount = parseInt(a.properties?.find(p => p.name === 'qrypto:occurrences')?.value ?? '0');
    const bCount = parseInt(b.properties?.find(p => p.name === 'qrypto:occurrences')?.value ?? '0');
    return bCount - aCount;
  });

  const bom: CycloneDXBOM = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{
        vendor: 'Qrypto',
        name: 'Qrypto CBOM Generator',
        version: options.toolVersion ?? '2.0.0',
      }],
      ...(options.projectName ? {
        component: {
          type: 'application',
          name: options.projectName,
        },
      } : {}),
    },
    components,
  };

  return bom;
}

/**
 * Serialize a CBOM to a JSON string for download/storage.
 */
export function serializeCBOM(bom: CycloneDXBOM): string {
  return JSON.stringify(bom, null, 2);
}
