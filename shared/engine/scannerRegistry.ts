export type ScannerStatus = 'READY' | 'PARTIAL' | 'UNSUPPORTED' | 'EXPERIMENTAL';

export interface ScannerCapability {
  id: string;
  name: string;
  description: string;
  detects: string;
  doesNotDetect: string;
  method: string;
  supportedInputs: string[];
  status: ScannerStatus;
  limitations: string;
}

export const SCANNER_REGISTRY: ScannerCapability[] = [
  {
    id: 'source-code',
    name: 'SOURCE CODE',
    description: 'Scans source code files for cryptographic algorithms, secrets, and API usage.',
    detects: 'RSA, ECC, AES, hashes, signatures, secrets, libraries and crypto API usage.',
    doesNotDetect: 'Runtime cryptographic operations, memory-resident keys.',
    method: 'Regex + AST + dependency analysis where supported.',
    supportedInputs: ['Local folder', 'ZIP', 'Repository'],
    status: 'READY',
    limitations: 'Static analysis only; cannot verify runtime crypto state.'
  },
  {
    id: 'ast',
    name: 'AST',
    description: 'Semantic analysis of source code to validate API usage and reduce false positives.',
    detects: 'Cryptographic API arguments, dynamic key sizes, function contexts.',
    doesNotDetect: 'Files in languages without supported tree-sitter grammars.',
    method: 'Tree-sitter AST parsing.',
    supportedInputs: ['.js', '.ts', '.py', '.java', '.go', '.cs'],
    status: 'READY',
    limitations: 'Limited to supported tree-sitter grammars. Performance intensive.'
  },
  {
    id: 'certificates',
    name: 'CERTIFICATE / X.509',
    description: 'Parses digital certificates to extract key sizes, algorithms, and vulnerabilities.',
    detects: 'X.509 PEM, DER (where supported), issuer, subject, validity, signature algorithm, weak indicators.',
    doesNotDetect: 'Certificates stored in proprietary encrypted keystores without passwords.',
    method: 'Static parsing of PEM/DER files.',
    supportedInputs: ['.pem', '.crt', '.cer', '.der', '.key'],
    status: 'READY',
    limitations: 'Does not verify trust chains or live CA endpoints.'
  },
  {
    id: 'tls',
    name: 'TLS / PROTOCOL',
    description: 'Identifies TLS configurations and protocols.',
    detects: 'TLS, SSL, SSH, IPsec configuration evidence where supported.',
    doesNotDetect: 'Live network traffic interception.',
    method: 'Regex + configuration file parsing.',
    supportedInputs: ['Source Code', 'Config Files'],
    status: 'READY',
    limitations: 'Static configuration evidence only. No live handshake testing.'
  },
  {
    id: 'pqc',
    name: 'PQC',
    description: 'Detects Post-Quantum Cryptography implementations.',
    detects: 'ML-KEM, ML-DSA, SLH-DSA, and other supported PQC references.',
    doesNotDetect: 'Proprietary non-standard quantum algorithms.',
    method: 'Regex + Dependency analysis.',
    supportedInputs: ['Source Code', 'Dependencies'],
    status: 'READY',
    limitations: 'Limited to NIST standardized ML-KEM/ML-DSA parameters.'
  },
  {
    id: 'hsm',
    name: 'HSM / PKCS#11',
    description: 'Detects hardware security module configurations.',
    detects: 'PKCS#11, Cryptoki, SoftHSM, YubiHSM, TPM2/tpm2-tss, p11-kit configuration references.',
    doesNotDetect: 'Live HSM connections or HSM internal keys.',
    method: 'Regex + API usage detection.',
    supportedInputs: ['Source Code', 'Config Files'],
    status: 'READY',
    limitations: 'Cannot detect physical HSM boundaries or export controls.'
  },
  {
    id: 'cloud-kms',
    name: 'CLOUD KMS',
    description: 'Detects Cloud Key Management Service integrations.',
    detects: 'AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault API usage and configuration.',
    doesNotDetect: 'IAM permissions or live KMS state.',
    method: 'Evidence-based detection (SDK usage, endpoints).',
    supportedInputs: ['Source Code', 'Config Files'],
    status: 'READY',
    limitations: 'Relies on SDK usage evidence. Cannot verify IAM policies.'
  },
  {
    id: 'docker',
    name: 'DOCKER / CONTAINER',
    description: 'Scans container definitions for crypto configurations.',
    detects: 'Base images, package installations, crypto libraries in Dockerfiles and compose files.',
    doesNotDetect: 'Live container introspection or static container archive inspection.',
    method: 'Regex on Dockerfile/compose files.',
    supportedInputs: ['Dockerfile', 'docker-compose.yml'],
    status: 'READY',
    limitations: 'Static Dockerfile inspection only. Does not analyze built layers.'
  },
  {
    id: 'binary',
    name: 'BINARY',
    description: 'Static analysis of binary artifacts for cryptographic references.',
    detects: 'Static ELF/PE strings, symbol references, and crypto library imports.',
    doesNotDetect: 'Execution paths or packed/obfuscated code.',
    method: 'Static analysis only. NEVER executes binaries.',
    supportedInputs: ['.dll', '.so', '.exe', '.bin'],
    status: 'READY',
    limitations: 'Cannot decompile. Operates on extracted symbol strings only.'
  },
  {
    id: 'combined',
    name: 'COMBINED ENTERPRISE SCAN',
    description: 'Runs all compatible scanner families against one target and merges findings.',
    detects: 'Everything supported by individual scanners.',
    doesNotDetect: 'N/A',
    method: 'Unified normalization and deduplication.',
    supportedInputs: ['Local folder', 'ZIP', 'Repository'],
    status: 'READY',
    limitations: 'Requires OS-compatible directory structure.'
  }
];

export function getScannerRegistry(): ScannerCapability[] {
  return SCANNER_REGISTRY;
}
