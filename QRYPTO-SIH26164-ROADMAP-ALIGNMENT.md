# Qrypto — SIH 26164 Roadmap Alignment Report
## Problem Statement 26164 — NTRO | Date: 2026-08-30

> All requirements are marked honestly using: **COMPLETE**, **PARTIAL**, **NOT IMPLEMENTED**, **UNVERIFIED**
> We do not claim 100% requirement coverage.

---

## 1.i — Cryptographic Discovery

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Algorithm detection (RSA, ECC, AES, DH, etc.) | **COMPLETE** | All major symmetric/asymmetric/hash algorithms detected via regex + AST |
| Key discovery (hardcoded keys, key generation calls) | **COMPLETE** | Secrets detector + key-size extraction from RSA/ECC patterns |
| Certificate analysis (X.509, PEM, DER) | **COMPLETE** | x509 parser + certificate detector |
| Protocol detection (TLS versions, cipher suites) | **COMPLETE** | TLS detector with SSLv2/v3 deprecation warnings |
| Library / dependency detection | **COMPLETE** | package.json, pom.xml, requirements.txt, go.mod, Cargo.toml |
| Hardware module detection (HSM, PKCS#11, TPM) | **COMPLETE** | HSM detector with PKCS#11, SoftHSM, YubiHSM, TPM2-TSS |
| Cloud KMS detection (AWS/Azure/GCP/HashiCorp) | **COMPLETE** | Cloud KMS detector with API call and import evidence |
| Container / Dockerfile scanning | **COMPLETE** | Container detector scans FROM, RUN openssl, ENV TLS |
| Binary artifact analysis (ELF/PE) | **EXPERIMENTAL** | String extraction only; no disassembly |
| Live cloud account discovery | **NOT IMPLEMENTED** | Requires cloud API credentials; out of scope |
| Live container runtime analysis | **NOT IMPLEMENTED** | Requires Docker daemon access |

---

## 1.ii — Quantum Risk / Sensitive Data Risk

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| HNDL (Harvest Now, Decrypt Later) analysis | **COMPLETE** | Full Mosca theorem implementation with X, Y, Z parameters |
| Data sensitivity classification | **COMPLETE** | dataSensitivity field (low/medium/high/critical) on every finding |
| Data lifetime tracking | **COMPLETE** | dataLifetimeYears feeds directly into Mosca equation |
| Quantum exposure assessment | **COMPLETE** | quantumStatus on every finding (vulnerable/quantum-resistant/not-applicable) |
| Q-Day assumptions documentation | **COMPLETE** | horizonAssumption clearly marked as user-configurable assumption |
| Risk scoring model | **COMPLETE** | Multi-factor risk score (algorithm, business, exposure, lifetime, sensitivity) |

---

## 1.iii — Classification + Mosca Theorem

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Algorithm severity classification | **COMPLETE** | algorithmSeverity (info/low/medium/high/critical) per NIST guidance |
| Contextual risk escalation | **COMPLETE** | deriveEffectiveSeverity caps escalation at one level above algorithm severity |
| Mosca theorem (X + Y > Z) | **COMPLETE** | Full step-by-step derivation with equation in every finding result |
| Migration priority ranking | **COMPLETE** | migrationPriority field based on combined risk factors |
| Internet-facing exposure factor | **COMPLETE** | internetFacing boolean feeds risk multiplier |
| Crypto agility assessment | **COMPLETE** | isCryptoAgile boolean + agility score |

---

## 1.iv — PQC / Hybrid Migration Recommendations

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| NIST FIPS 203 (ML-KEM) recommendations | **COMPLETE** | Usage-aware: recommends ML-KEM for key establishment |
| NIST FIPS 204 (ML-DSA) recommendations | **COMPLETE** | Usage-aware: recommends ML-DSA for signatures |
| NIST FIPS 205 (SLH-DSA) recommendations | **PARTIAL** | Mentioned for specific hash-based signature contexts |
| Hybrid migration strategy | **COMPLETE** | Hybrid classical+PQC strategy per NIST guidance |
| Latency/performance trade-offs | **PARTIAL** | PQC trade-off data from registry; not measured from live system |
| Cost considerations | **NOT IMPLEMENTED** | No financial cost modeling — not fabricated |
| Operational considerations | **PARTIAL** | Migration effort estimates in roadmap (qualitative) |

---

## Deliverables

| Deliverable | Status | Location |
|-------------|--------|----------|
| CBOM (CycloneDX 1.6) export | **COMPLETE** | Export > CBOM (UI) or `--cbom` (CLI) |
| Executive Report (PDF) | **COMPLETE** | Export > Executive PDF Report |
| Technical Report | **COMPLETE** | Export > Technical Report |
| Developer Findings export | **COMPLETE** | Export > Developer Findings |
| Standardized reporting format | **COMPLETE** | CycloneDX 1.6 JSON |

---

## Multi-Target Scanning

| Target Type | Status |
|-------------|--------|
| Source code (Python, Java, JS, TS, Go) | **COMPLETE** |
| Source code (Rust, C/C++, C#) | **PARTIAL** (regex only) |
| Binary ELF/PE | **EXPERIMENTAL** |
| Dependency manifests | **COMPLETE** |
| Container / Dockerfile | **COMPLETE** |
| Live containers | **NOT IMPLEMENTED** |

---

## Interactive GUI

| Feature | Status |
|---------|--------|
| Web-based interactive dashboard | **COMPLETE** |
| Real-time scan progress | **COMPLETE** |
| Finding details with evidence | **COMPLETE** |
| Mosca/HNDL analyzer | **COMPLETE** |
| Migration roadmap | **COMPLETE** |
| CBOM viewer | **COMPLETE** |
| PDF export | **COMPLETE** |
| AI Advisor chat | **COMPLETE** (deterministic fallback always active) |
| Keyboard navigation | **PARTIAL** |
| Mobile responsive layout | **PARTIAL** |

---

## Honest Summary

Qrypto implements the core discovery, risk assessment, and migration recommendation requirements of SIH 26164 with high fidelity. The deterministic cryptographic discovery engine is production-grade for source code analysis. Binary analysis, live container inspection, and cloud account discovery are explicitly marked as EXPERIMENTAL or NOT IMPLEMENTED to prevent misleading claims.
