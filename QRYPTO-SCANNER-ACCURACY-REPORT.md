# Qrypto Scanner Accuracy Report
## Version: 1.0.0 | Date: 2026-08-30 | Status: Controlled Fixture Results Only

> **IMPORTANT ACCURACY DISCLAIMER**
> Accuracy metrics in this report are computed from controlled test fixtures only.
> Claims are limited to what can be statistically justified from the available sample size.
> Where sample size is insufficient for statistical significance, this is stated as **NOT ENOUGH DATA**.
> We do NOT claim 100% accuracy. All metrics are best-effort.

---

## Methodology

Each scanner was tested against the controlled benchmark corpus (`benchmark/corpus/`) containing deliberately crafted test files in Python, Java, JavaScript, TypeScript, and Go. Results were manually verified against known-positive ground truth.

**Metrics Definitions**
- **TP (True Positive)**: Finding is correct and the algorithm is genuinely present.
- **FP (False Positive)**: Finding reported but the algorithm usage is not actually present.
- **FN (False Negative)**: Algorithm is present but was not detected.
- **Precision = TP / (TP + FP)**
- **Recall = TP / (TP + FN)**
- **F1 = 2 × (Precision × Recall) / (Precision + Recall)**

---

## Scanner Results by Corpus

### Corpus 1: Controlled 8-Category Crypto Fixture (`benchmark/corpus/`)

| Scanner | Expected | Detected (raw) | After Dedup | TP | FP | FN | Precision | Recall | F1 | Notes |
|---------|----------|---------------|-------------|----|----|----|-----------|---------|----|-------|
| RSA Detector | 4 | 6 | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 | Dedup correctly collapsed API + comment variants |
| ECC / ECDSA Detector | 6 | 9 | 6 | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 | P-256, SECP256R1, ecdsa.GenerateKey all detected |
| Hash Detector (MD5/SHA1) | 5 | 7 | 5 | 5 | 0 | 0 | 1.00 | 1.00 | 1.00 | MD5 detected across all 4 languages |
| Secrets Detector | 1 | 1 | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 | Hardcoded private key PEM block detected |
| PQC Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No PQC in fixture — correct absence |
| TLS / Protocol Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No TLS config in fixture |
| Dependency Scanner | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No manifests in corpus — NOT ENOUGH DATA |
| Cloud KMS Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No cloud KMS calls in corpus — NOT ENOUGH DATA |
| Container / Docker Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No Dockerfiles in corpus |
| HSM / PKCS#11 Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No HSM in corpus — NOT ENOUGH DATA |
| Binary Detector | 0 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | No binary files in corpus |

**Overall (Corpus 1 — testable scanners only):**
- Total TP: 16 | Total FP: 0 | Total FN: 0
- **Aggregate Precision: 1.00 | Recall: 1.00 | F1: 1.00**
- ⚠️ **WARNING**: Sample size is small (5 files, ~250 lines). These metrics MUST NOT be cited as production-grade accuracy. They reflect detection correctness on a controlled, simple fixture only.

---

### Corpus 2: Enterprise Sample ZIP (`qrypto-enterprise-sample.zip`)

| Scanner | Files Scanned | Raw Findings | After Dedup | Notes |
|---------|--------------|-------------|-------------|-------|
| All detectors combined | Multiple | 40+ | 40 | Confirmed via CLI scan |
| Secrets | Present | Detected | Confirmed | Hardcoded AWS-key-pattern detected |
| RSA/ECC | Present | Detected | Confirmed | RSA-2048 and P-256 usage |

**Accuracy Assessment**: Qualitative only. NOT ENOUGH DATA for statistical metrics.

---

### Corpus 3: Dependency Scanner (package.json / pom.xml / requirements.txt)

| Manifest Type | Supported | Correctly Distinguishes DEPENDENCY vs USAGE |
|---------------|-----------|---------------------------------------------|
| package.json | READY | PARTIAL (library name only; no runtime trace) |
| pom.xml | READY | PARTIAL |
| requirements.txt | READY | PARTIAL |
| go.mod | READY | PARTIAL |
| Cargo.toml | READY | PARTIAL |

**Known Limitation**: The dependency scanner detects known crypto library names in dependency manifests. It does **not** perform runtime analysis to confirm actual API usage. All findings are labeled `DEPENDENCY_PRESENT` (not `RUNTIME_USAGE`).

---

## Scanner Capability Matrix

| Scanner | Status | Single File | Folder | ZIP | Repo URL | Browser | Backend | CLI |
|---------|--------|------------|--------|-----|----------|---------|---------|-----|
| RSA | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| ECC / ECDSA | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Hash (MD5/SHA-1/SHA-256) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Symmetric (AES) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| PQC (ML-KEM/ML-DSA) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| TLS / Protocol | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Secrets / Hardcoded Keys | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Certificates (x.509/PEM/DER) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Dependencies (manifests) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Cloud KMS (AWS/Azure/GCP) | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| HSM / PKCS#11 | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Container / Dockerfile | READY | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Binary (ELF/PE) | EXPERIMENTAL | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| AST-Based Detection | PARTIAL | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| Repository URL Cloning | UNSUPPORTED | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Live Container Runtime | UNSUPPORTED | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Cloud Account Discovery | UNSUPPORTED | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

---

## Input / File Matrix

| Input Type | Supported | Scanner Behavior |
|-----------|-----------|-----------------|
| Single source file (.py, .ts, etc.) | READY | Full analysis via pipeline |
| Local folder | READY | Recursive walk, up to 10,000 files |
| ZIP archive | READY | Client-side extraction via JSZip |
| Git repository URL | UNSUPPORTED | Not implemented; returns error |
| PEM certificate | READY | Parsed by x509 detector + certificates detector |
| DER certificate | READY | Binary-safe detection of certificate patterns |
| Dockerfile | READY | Detected by container detector |
| Docker Compose | READY | Detected by container detector |
| ELF binary | EXPERIMENTAL | String extraction; no full symbol analysis |
| PE / DLL / EXE | EXPERIMENTAL | String extraction; no full disassembly |
| package.json | READY | Full dependency manifest analysis |
| pom.xml | READY | Maven dependency analysis |
| requirements.txt | READY | Python package analysis |
| go.mod | READY | Go module analysis |
| Cargo.toml | READY | Rust crate analysis |

---

## Scanner Limitations

1. **AST detection**: WebAssembly tree-sitter parser works for Python and TypeScript. Java AST analysis falls back to regex on WASM initialization failures.
2. **Binary analysis**: String extraction only — no disassembly, no symbol resolution. Results are EXPERIMENTAL and may have elevated false positives.
3. **Cloud KMS**: Detects cloud KMS API calls in source code. Does NOT connect to cloud APIs or discover live key inventory.
4. **Repository URL**: Remote cloning is NOT implemented. Users must clone locally first.
5. **Confidence**: Default threshold of 0.70. All metrics above are at ≥0.70 confidence.
6. **Language coverage**: Python, Java, JavaScript, TypeScript, Go are primary. Rust, C/C++, C# are partial (regex only, no AST).

---

## False Positive Examples (Known / Acceptable)

| Scenario | FP Type | Reason | Mitigation |
|----------|---------|--------|------------|
| Comment blocks with algorithm names | Low-confidence FP | e.g. `# TODO: replace MD5` | Confidence penalty applied for comments |
| Test fixture files | Low-confidence FP | Algorithm in test code is test data | Confidence penalty for `test/` paths |
| Dependency manifest without usage | DEPENDENCY_PRESENT | Library listed but not called | Label distinguishes from RUNTIME_USAGE |

---

*Report generated from automated test results. Manual inspection performed on benchmark corpus.
Real-world corpus validation (WebGoat, OpenSSL, etc.) requires external environment access — marked UNVERIFIED.*
