import { KMSClient, ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import type { Finding } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';


export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

/**
 * Connects to live AWS KMS and translates remote keys into Cryptographic Findings.
 */
export async function detectLiveKms(credentials: AwsCredentials, project: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const now = new Date().toISOString();
  
  try {
    const client = new KMSClient({
      region: credentials.region || 'us-east-1',
      credentials: {
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
      }
    });

    const listCommand = new ListKeysCommand({ Limit: 50 }); // Fetch first 50 keys for demo purposes
    const listResponse = await client.send(listCommand);

    if (!listResponse.Keys) return findings;

    for (const key of listResponse.Keys) {
      if (!key.KeyId) continue;

      const describeCommand = new DescribeKeyCommand({ KeyId: key.KeyId });
      const describeResponse = await client.send(describeCommand);
      const metadata = describeResponse.KeyMetadata;
      
      if (!metadata) continue;

      // Extract details
      const spec = metadata.KeySpec || 'UNKNOWN'; // e.g., SYMMETRIC_DEFAULT, RSA_2048, ECC_NIST_P256
      const usage = metadata.KeyUsage || 'ENCRYPT_DECRYPT'; // e.g., ENCRYPT_DECRYPT, SIGN_VERIFY
      
      let mappedAlgorithm = spec;
      let keySize: number | undefined = undefined;
      let qStatus: Finding['quantumStatus'] = 'adequate';
      let cStatus: Finding['classicalStatus'] = 'adequate';
      let bSeverity: Finding['algorithmSeverity'] = 'medium';
      
      // Parse AWS KeySpecs (Partial mapping for common types)
      if (spec === 'SYMMETRIC_DEFAULT') {
        mappedAlgorithm = 'AES-256-GCM'; // AWS default
        keySize = 256;
        qStatus = 'adequate';
        cStatus = 'strong';
        bSeverity = 'low';
      } else if (spec.startsWith('RSA_')) {
        mappedAlgorithm = 'RSA';
        keySize = parseInt(spec.split('_')[1], 10);
        qStatus = 'vulnerable';
        if (keySize < 2048) {
          cStatus = 'weak';
          bSeverity = 'critical';
        } else {
          cStatus = 'adequate';
          bSeverity = 'high';
        }
      } else if (spec.startsWith('ECC_')) {
        mappedAlgorithm = spec; // e.g. ECC_NIST_P256
        qStatus = 'vulnerable';
        cStatus = 'strong';
        bSeverity = 'high';
      } else if (spec.startsWith('HMAC_')) {
        mappedAlgorithm = spec; // e.g. HMAC_256
        qStatus = 'adequate';
        cStatus = 'strong';
        bSeverity = 'low';
      } else {
        qStatus = 'unknown';
        cStatus = 'unknown';
      }

      const category = spec.startsWith('RSA') || spec.startsWith('ECC') 
        ? (usage === 'SIGN_VERIFY' ? 'signature' : 'public-key') 
        : 'symmetric';

      const riskBreakdown = computeRiskScore({
        quantumStatus: qStatus,
        baseSeverity: bSeverity,
        internetFacing: false,
        dataSensitivity: 'high',
        dataLifetimeYears: 10,
        isHardcoded: false,
        service: 'AWS KMS',
      });

      const algorithmSeverity = deriveAlgorithmSeverity({
        algorithm: mappedAlgorithm,
        quantumStatus: qStatus,
        baseSeverity: bSeverity,
        category: category as any,
      });

      const effective = deriveEffectiveSeverity({
        algorithmSeverity: algorithmSeverity.severity,
        quantumStatus: qStatus,
        contextualRisk: riskBreakdown.totalScore,
      });

      findings.push({
        id: `kms-${key.KeyId}`,
        file: `aws://kms/${credentials.region}/${key.KeyId}`,
        line: 1,
        repository: 'Live Cloud Environment',
        project,
        service: 'AWS KMS',
        language: 'unknown',
        algorithm: mappedAlgorithm,
        keySize,
        category: 'cloud-kms',
        usage: `Live KMS Key: ${usage}`,
        detectedPattern: spec,
        confidence: 1.0, // Absolute certainty since it's an API response
        quantumStatus: qStatus,
        classicalStatus: cStatus,
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `Live AWS KMS API reported key spec ${spec}.`,
        internetFacing: false, // KMS is usually internal, though could be exposed via apps
        dataSensitivity: 'high',
        dataLifetimeYears: 10,
        isCryptoAgile: false,
        isHardcoded: false,
        contextSource: 'EXPLICIT',
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: effective.severity === 'critical' ? 1 : effective.severity === 'high' ? 2 : 3,
        recommendedAlgorithm: qStatus === 'vulnerable' ? 'Migrate to post-quantum keys (once AWS supports PQC natively)' : 'Maintain current strong keys',
        tags: ['cloud-kms', 'aws', 'live-scan'],
        detectedAt: now,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['live-api'],
          matchedText: JSON.stringify({ KeyId: key.KeyId, Spec: spec, State: metadata.KeyState }),
          confidenceDerivation: 'Authenticated AWS KMS API response.'
        }
      });
    }

  } catch (error) {
    console.error("Live KMS Scan Failed:", error);
    // Don't crash the orchestrator, just log and return whatever we found so far.
  }

  return findings;
}
