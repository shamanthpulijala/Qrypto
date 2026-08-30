// ============================================================
// Qrypto AI Advisor — PQC Knowledge Base
// ============================================================

export const PQC_ALGORITHMS = [
  {
    name: 'ML-KEM',
    fullName: 'Module-Lattice Key Encapsulation Mechanism',
    nistId: 'FIPS 203',
    previousName: 'CRYSTALS-Kyber',
    category: 'Key Encapsulation',
    variants: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
    replaces: ['RSA (key establishment)', 'ECDH', 'DH'],
    description: 'A lattice-based key encapsulation mechanism standardized by NIST. Used to securely exchange symmetric keys without relying on the hardness of integer factorization or discrete logarithm problems.',
    status: 'NIST Standardized (2024)',
    useCase: 'Key establishment, key encapsulation',
    migrationNote: 'Consider hybrid X25519+ML-KEM-768 during the transition period for backward compatibility. Pure ML-KEM-1024 provides the highest security level.',
  },
  {
    name: 'ML-DSA',
    fullName: 'Module-Lattice Digital Signature Algorithm',
    nistId: 'FIPS 204',
    previousName: 'CRYSTALS-Dilithium',
    category: 'Digital Signatures',
    variants: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
    replaces: ['RSA (signatures)', 'ECDSA', 'DSA', 'SHA1withRSA', 'SHA256withRSA'],
    description: 'A lattice-based digital signature scheme standardized by NIST. Provides quantum-resistant signatures significantly larger than classical signature schemes but feasible for most applications.',
    status: 'NIST Standardized (2024)',
    useCase: 'Digital signatures, code signing, certificate signing',
    migrationNote: 'ML-DSA-65 provides a balanced security/performance tradeoff. Signature sizes are larger than RSA/ECDSA — evaluate protocol constraints before migration.',
  },
  {
    name: 'SLH-DSA',
    fullName: 'Stateless Hash-Based Digital Signature Algorithm',
    nistId: 'FIPS 205',
    previousName: 'SPHINCS+',
    category: 'Digital Signatures',
    variants: ['SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-256s', 'SLH-DSA-SHAKE-128s'],
    replaces: ['RSA (signatures)', 'ECDSA', 'DSA'],
    description: 'A hash-based stateless signature scheme. Its security relies only on the security of the underlying hash function — providing different security assumptions from lattice-based algorithms.',
    status: 'NIST Standardized (2024)',
    useCase: 'Long-term signatures, code signing, situations requiring security diversity from lattice assumptions',
    migrationNote: 'Larger signatures than ML-DSA. Useful as a security-diversity alternative or when hash-based proofs are preferred.',
  },
];

export const ALGORITHM_RISK_TABLE = [
  { algorithm: 'RSA-1024', quantumRisk: 'Very High', classicalRisk: 'High', recommendation: 'Immediately replace', timeline: 'Now' },
  { algorithm: 'RSA-2048', quantumRisk: 'High', classicalRisk: 'Low', recommendation: 'Plan migration to ML-KEM/ML-DSA', timeline: '1–3 years' },
  { algorithm: 'RSA-4096', quantumRisk: 'High (slower quantum attack estimate)', classicalRisk: 'Very Low', recommendation: 'Plan migration to ML-KEM/ML-DSA', timeline: '3–5 years' },
  { algorithm: 'ECC/ECDSA (256-bit)', quantumRisk: 'High', classicalRisk: 'Low', recommendation: 'Migrate to ML-DSA for signatures', timeline: '1–3 years' },
  { algorithm: 'ECDH (P-256)', quantumRisk: 'High', classicalRisk: 'Low', recommendation: 'Migrate to ML-KEM; consider hybrid', timeline: '1–3 years' },
  { algorithm: 'DH', quantumRisk: 'High', classicalRisk: 'Varies (key size dependent)', recommendation: 'Migrate to ML-KEM', timeline: '1–2 years' },
  { algorithm: 'MD5', quantumRisk: 'N/A (already broken classically)', classicalRisk: 'Critical', recommendation: 'Replace immediately', timeline: 'Now' },
  { algorithm: 'SHA-1', quantumRisk: 'Low (Grover: ~2^80 — still expensive)', classicalRisk: 'High (collision attacks)', recommendation: 'Replace with SHA-256/SHA-3', timeline: 'Now' },
  { algorithm: 'SHA-256', quantumRisk: 'Low (Grover: ~2^128 effective)', classicalRisk: 'Low', recommendation: 'Acceptable; consider SHA-384 for long-lived systems', timeline: 'No urgent action' },
  { algorithm: 'SHA-3', quantumRisk: 'Very Low', classicalRisk: 'Very Low', recommendation: 'Preferred for new systems', timeline: 'No action needed' },
  { algorithm: 'AES-128', quantumRisk: 'Low (Grover: ~2^64 — marginal)', classicalRisk: 'Low', recommendation: 'Consider AES-256 for long-lived data', timeline: 'Low urgency' },
  { algorithm: 'AES-256', quantumRisk: 'Very Low (Grover: ~2^128 effective)', classicalRisk: 'Very Low', recommendation: 'Preferred symmetric cipher', timeline: 'No urgent action' },
  { algorithm: 'DES', quantumRisk: 'N/A (already broken classically)', classicalRisk: 'Critical (56-bit key)', recommendation: 'Replace immediately with AES-256', timeline: 'Now' },
  { algorithm: '3DES', quantumRisk: 'N/A (classically weak)', classicalRisk: 'High (Sweet32 attack)', recommendation: 'Replace with AES-256-GCM', timeline: 'Now' },
  { algorithm: 'TLS 1.0/1.1', quantumRisk: 'N/A', classicalRisk: 'Critical (BEAST, POODLE)', recommendation: 'Upgrade to TLS 1.3', timeline: 'Now' },
  { algorithm: 'TLS 1.2', quantumRisk: 'Low', classicalRisk: 'Low (with modern cipher suites)', recommendation: 'Prefer TLS 1.3; add PQC cipher suite support', timeline: 'Plan TLS 1.3 migration' },
  { algorithm: 'TLS 1.3', quantumRisk: 'Low (no PQC KEM yet widely deployed)', classicalRisk: 'Very Low', recommendation: 'Add X25519Kyber768 hybrid cipher suite', timeline: 'Evaluate PQC cipher suite support' },
  { algorithm: 'ChaCha20-Poly1305', quantumRisk: 'Very Low', classicalRisk: 'Very Low', recommendation: 'Acceptable; no urgent action', timeline: 'No urgent action' },
  { algorithm: 'ML-KEM', quantumRisk: 'Very Low (currently)', classicalRisk: 'Low (lattice assumptions)', recommendation: 'Recommended for new key establishment', timeline: 'Adopt' },
  { algorithm: 'ML-DSA', quantumRisk: 'Very Low (currently)', classicalRisk: 'Low (lattice assumptions)', recommendation: 'Recommended for new signatures', timeline: 'Adopt' },
];

export const COMPLIANCE_FRAMEWORKS = [
  {
    id: 'nist-csf',
    name: 'NIST Cybersecurity Framework (CSF 2.0)',
    description: 'Framework for improving critical infrastructure cybersecurity.',
    controls: [
      { id: 'ID.AM-5', name: 'Cryptographic Asset Inventory', description: 'Cryptographic assets (algorithms, keys, certificates) are inventoried.' },
      { id: 'PR.DS-2', name: 'Data in Transit Protection', description: 'Data in transit is protected using cryptographic mechanisms.' },
      { id: 'PR.DS-1', name: 'Data at Rest Protection', description: 'Data at rest is protected using cryptographic mechanisms.' },
    ],
  },
  {
    id: 'nist-pqc',
    name: 'NIST PQC Migration (NIST IR 8413)',
    description: 'NIST guidance on migration to post-quantum cryptography.',
    controls: [
      { id: 'PQC-INV', name: 'Cryptographic Inventory', description: 'Inventory all cryptographic assets that may be quantum-vulnerable.' },
      { id: 'PQC-PRIO', name: 'Prioritized Migration', description: 'Prioritize migration of highest-risk, internet-facing systems.' },
      { id: 'PQC-HYBRID', name: 'Hybrid Transition', description: 'Consider hybrid classical+PQC approach during migration.' },
      { id: 'PQC-AGILITY', name: 'Crypto Agility', description: 'Design systems to support algorithm updates without major refactoring.' },
    ],
  },
  {
    id: 'pci-dss',
    name: 'PCI DSS v4.0',
    description: 'Payment Card Industry Data Security Standard.',
    controls: [
      { id: '4.2.1', name: 'Strong Cryptography in Transit', description: 'Strong cryptography is used to protect PAN in transit over open networks.' },
      { id: '3.5.1', name: 'Strong Cryptography at Rest', description: 'PAN is secured with strong cryptography.' },
      { id: '12.3.3', name: 'Cryptographic Key Management', description: 'Cryptographic keys are managed using documented key-management procedures.' },
    ],
  },
];
