# Qrypto

### Cryptographic Discovery & Post-Quantum Readiness

Qrypto is a cryptographic discovery and assessment tool built for exploring the transition from classical cryptography to Post-Quantum Cryptography (PQC).

It scans repositories and other artifacts for cryptographic usage, collects evidence, evaluates risk, and provides migration recommendations.

The main idea is simple:

> Find what cryptography is being used, understand the risk, and figure out what needs to change.

---

## What Qrypto Does

Qrypto currently covers:

- Cryptographic algorithm discovery
- Secrets and key detection
- X.509 certificate analysis
- TLS and protocol configuration detection
- Dependency analysis
- HSM / PKCS#11 detection
- Cloud KMS detection
- Docker/container analysis
- Experimental binary analysis
- Quantum risk assessment
- HNDL analysis
- Crypto-agility assessment
- PQC migration recommendations
- Migration roadmap generation
- AI-assisted explanation of findings
- CLI-based scanning

---

## How It Works

```text
Repository / Artifact
        |
        v
   Cryptographic
     Discovery
        |
        v
      Evidence
        |
        v
    Risk Engine
        |
        +------> Quantum / HNDL Assessment
        |
        +------> Crypto-Agility
        |
        +------> PQC Recommendations
        |
        v
   Migration Roadmap
        |
        v
  Security Report
