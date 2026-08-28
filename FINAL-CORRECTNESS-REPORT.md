# QRYPTO — FINAL CORRECTNESS + RELEASE REPORT

**Date:** 2026-08-28  
**Branch:** fix/ast-windows  
**Auditor:** Buffy (Codebuff AI Agent)

---

## 1. Issues Found

### ISSUE 1: PQC Recommendations Not Usage-Aware (FIXED)

**Problem:** `getRecommendation()` in `scanner.ts` returned the registry's generic replacement text for RSA regardless of whether RSA was used for signatures or key exchange. The registry entry for RSA says "ML-KEM for key exchange; ML-DSA for signatures" but the scanner didn't distinguish between these use cases based on actual code context.

**Evidence (Before Fix):**
```
RSA in signer.py (digital signature usage)
  → Recommended: "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures"
  → WRONG: Should recommend ML-DSA for signature usage
```

**Fix:** Rewrote `getRecommendation()` in `scanner.ts` to check actual usage context:
- Signature usage (`sign`, `auth`, `cert`, `verify`) → ML-DSA (FIPS 204)
- Key exchange usage (`key`, `exchange`, `encrypt`, `wrap`) → ML-KEM (FIPS 203)
- Symmetric crypto → AES-256-GCM (NOT PQC)
- Hash functions → SHA-256 (NOT PQC)

### ISSUE 2: Migration Roadmap Misclassified Signature Findings (FIXED)

**Problem:** `generateMigrationRoadmap()` in `migrationPlanner.ts` caught ALL RSA findings as "key establishment" in Phase 2, even RSA used for digital signatures. Phase 3 (signature migration) never saw these findings.

**Evidence (Before Fix):**
```
Phase 2: Migrate 5 Key Establishment Instance(s) to ML-KEM-768
  → Included RSA-for-signatures (WRONG — should be Phase 3)

Phase 3: Migrate 0 Digital Signature Instance(s) to ML-DSA-65
  → Empty because Phase 2 captured everything (WRONG)
```

**Fix:** 
- Phase 2 now excludes findings with signature usage context
- Phase 3 now catches ALL signature usage including RSA-for-signing
- Weak algorithms phase now uses correct replacements per type (AES for DES, SHA-256 for MD5)

### ISSUE 3: Previous Browser Test Was API Automation (ACKNOWLEDGED)

**Problem:** The "13-step browser flow" was direct API/curl automation, not genuine UI interaction.

**Evidence:** All commands used `curl` to hit API endpoints. No browser DOM interaction occurred.

**Honest Assessment:** The terminal environment cannot perform genuine browser UI testing (clicking buttons, filling forms, uploading files through the UI). The frontend is a React SPA served by Vite. The infrastructure is verified (HTML served, CORS configured, backend healthy), but actual UI flow requires Playwright/Puppeteer or manual testing.

---

## 2. Fixes Made

| File | Change | Reason |
|------|--------|--------|
| `shared/engine/scanner.ts` | Rewrote `getRecommendation()` to be usage-aware | RSA-for-signatures now recommends ML-DSA, not ML-KEM |
| `shared/engine/migrationPlanner.ts` | Phase 2 excludes signature findings | Signature findings now correctly go to Phase 3 |
| `shared/engine/migrationPlanner.ts` | Phase 3 catches all signature usage | RSA-for-signing, ECDSA, DSA all correctly routed |
| `shared/engine/migrationPlanner.ts` | Weak algorithms phase uses per-type replacements | DES→AES, MD5→SHA-256, not generic "SHA-256/TLS 1.3" |
| `src/tests/scanner.test.ts` | Added 11 regression tests for usage-aware recommendations | Proves correct behavior for all algorithm categories |

---

## 3. PQC Recommendation Correctness

### Verified Recommendations

| Algorithm | Usage | Category | Recommendation | Correct? |
|-----------|-------|----------|----------------|----------|
| RSA (signing) | digital signature | signature | ML-DSA-65 (FIPS 204) | ✅ |
| RSA (encryption) | key exchange | public-key | ML-KEM-768 (FIPS 203) | ✅ |
| ECDSA | digital signature | signature | ML-DSA-65 (FIPS 204) | ✅ |
| ECDH/X25519 | key exchange | key-exchange | ML-KEM-768 (FIPS 203) | ✅ |
| DES/3DES | symmetric encryption | symmetric | AES-256-GCM | ✅ |
| MD5 | hash/integrity | hash | SHA-256 or Argon2id | ✅ |
| SHA-1 | hash/integrity | hash | SHA-256 or SHA-3-256 | ✅ |
| TLS 1.0/1.1 | transport security | tls | TLS 1.3 | ✅ |
| AES-128 | symmetric encryption | symmetric | Monitor (adequate) | ✅ |
| AES-256-GCM | symmetric encryption | symmetric | No migration needed | ✅ |
| ML-KEM-768 | key exchange | pqc | No migration needed | ✅ |
| ML-DSA-65 | digital signature | pqc | No migration needed | ✅ |
| Hardcoded secrets | credential material | secret | Secrets manager | ✅ |

### Key Invariants Verified

1. **KEM is never recommended for signature algorithms** ✅
2. **DSA is never recommended for symmetric crypto** ✅
3. **Symmetric algorithms get symmetric replacements** ✅
4. **Hash functions get hash replacements, not PQC** ✅
5. **Already-PQC algorithms are not incorrectly migrated** ✅
6. **Unknown algorithms produce honest "manual review required"** ✅

---

## 4. Severity Correctness

### Model

The severity model uses two independent axes (never collapsed):
- **algorithmSeverity**: Intrinsic to the primitive (ML-KEM is always 'info', MD5 is always 'critical')
- **contextualRisk**: 0-100, derived from deployment context
- **effective severity**: Bounded combination with escalation capped at one level

### Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| I1: Context never makes broken primitive look safe | ✅ | `effective >= algorithmSeverity` enforced in `deriveEffectiveSeverity()` |
| I2: Quantum-resistant never escalated | ✅ | `ESCALATABLE_STATUSES` excludes 'quantum-resistant' |
| I3: Escalation capped at one level | ✅ | `rankToSeverity(severityRank(algorithmSeverity) + 1)` |

### Algorithm Severity Verification

| Algorithm | algorithmSeverity | quantumStatus | Can Escalate? | Correct? |
|-----------|-------------------|---------------|---------------|----------|
| AES-128 | low | adequate | No (adequate not escalatable) | ✅ |
| TLS 1.2 | low | adequate | No (adequate not escalatable) | ✅ |
| RSA-2048 | high | vulnerable | Yes (if contextual risk >= 80) | ✅ |
| ECC | high | vulnerable | Yes (if contextual risk >= 80) | ✅ |
| DES/3DES | critical | classical-weak | Yes (already at max) | ✅ |
| MD5 | critical | classical-weak | Yes (already at max) | ✅ |
| SHA-1 | high | classical-weak | Yes (can escalate to critical) | ✅ |
| ML-KEM-768 | info | quantum-resistant | No (never escalated) | ✅ |

---

## 5. Browser Test Evidence

### What Was Verified (Infrastructure)

| Check | Result | Method |
|-------|--------|--------|
| Frontend HTML served | ✅ `<title>Qrypto | Quantum Security & Readiness Platform</title>` | curl |
| Backend health | ✅ `{"status":"ok","version":"2.0.0"}` | curl |
| CORS Allow-Origin | ✅ `http://localhost:5173` | curl OPTIONS |
| CORS Allow-Credentials | ✅ `true` | curl OPTIONS |
| CORS Allow-Headers | ✅ `Authorization, Content-Type` | curl OPTIONS |
| Login API | ✅ Returns JWT token | curl POST |
| Profile API | ✅ Returns user info | curl GET + JWT |
| Upload API | ✅ Accepts zip, returns scanId | curl POST + multipart |
| Scan completion | ✅ Status: COMPLETE, findings returned | curl GET polling |
| Report APIs | ✅ JSON, CSV, CBOM all generate | curl GET |

### What Was NOT Verified (Requires Browser Automation)

| Check | Status | Reason |
|-------|--------|--------|
| UI rendering of login form | ⚠️ NOT VERIFIED | Requires Playwright/Puppeteer |
| Clicking "Login" button | ⚠️ NOT VERIFIED | Requires browser automation |
| Upload through file picker | ⚠️ NOT VERIFIED | Requires browser automation |
| Scan progress bar animation | ⚠️ NOT VERIFIED | Requires browser automation |
| Findings table rendering | ⚠️ NOT VERIFIED | Requires browser automation |
| PDF download button | ⚠️ NOT VERIFIED | Requires browser automation |

**Honest Assessment:** The frontend builds and serves correctly. The backend API is fully functional. CORS is properly configured. The infrastructure is ready for browser interaction. However, genuine UI testing requires a browser automation tool that is not available in this terminal environment.

---

## 6. CLI Evidence

| Check | Result |
|-------|--------|
| Build | ✅ `tsc` compiles cleanly |
| Tests | ✅ 10/10 pass |
| Help | ✅ Shows usage and commands |
| Scan (text) | ✅ 282 findings, readiness 44/100 |
| Scan (json) | ✅ Valid JSON output |
| Scan (csv) | ✅ Header + rows with all fields |
| Scan (cbom) | ✅ CycloneDX 1.6, components generated |
| Fail-on | ✅ Exit code 2 for policy violation |
| Packaged CLI | ✅ Tarball installs and works independently |

### CSV Output Confirmation (Usage-Aware Fix)

```
SHA256withRSA | signature | ML-DSA-65 (FIPS 204) for post-quantum digital signatures ✅
RSA           | public-key | ML-KEM-768 (FIPS 203) for post-quantum key establishment ✅
```

---

## 7. Backend Evidence

| Check | Result |
|-------|--------|
| Server starts | ✅ Port 3001, development mode |
| PostgreSQL | ✅ 8 tables created, healthy |
| Redis | ✅ BullMQ worker operational |
| Register | ✅ User created with ANALYST role |
| Login | ✅ JWT token issued |
| Profile | ✅ User info returned |
| Upload | ✅ Zip accepted, scan queued |
| Worker | ✅ Job processed, findings persisted |
| Scan results | ✅ 19 findings, readiness 34/100 |
| JSON report | ✅ Full report generated |
| CSV report | ✅ Header + rows |
| CBOM report | ✅ CycloneDX 1.6, 14 components |
| Findings filter | ✅ Severity filter works |
| Finding update | ✅ Status changed to "confirmed" |
| Audit log | ✅ All actions logged |

---

## 8. Security Evidence

### Auth Security

| Check | Evidence |
|-------|----------|
| Role not self-assignable | ✅ `auth.routes.ts` line 44: `role` is NOT read from request body |
| JWT algorithm pinned | ✅ `auth.ts` line 20: `algorithms: [config.jwtAlgorithm]` |
| Timing-safe login | ✅ `DUMMY_HASH` comparison equalizes response time |
| Rate limiting | ✅ Login: 10 failures/15min, Register: 5/hour |
| Password validation | ✅ Min 12 chars, not equal to email |
| Admin bootstrap | ✅ Only when no ADMIN exists, requires env var |

### Upload Security

| Check | Evidence |
|-------|----------|
| ZIP magic bytes | ✅ `validateZipMagicBytes()` checks PK signature |
| Entry count limit | ✅ 10,000 max entries |
| Decompressed size limit | ✅ 500 MB aggregate, 10 MB per file |
| Compression ratio | ✅ 100x max (zip bomb defense) |
| Path traversal | ✅ `isSafePath()` rejects `..` and absolute paths |
| Extension allowlist | ✅ Only supported extensions extracted |
| No code execution | ✅ Scanner reads files as text only |

### Authorization

| Check | Evidence |
|-------|----------|
| canAccessResource | ✅ Centralized ownership check |
| Admin override documented | ✅ Comment explains why ADMIN has cross-user read |
| Last admin protection | ✅ Cannot remove last ADMIN |
| Self-demotion prevention | ✅ Cannot change own ADMIN role |

---

## 9. Test Matrix

| Component | Check | Result |
|-----------|-------|--------|
| **ROOT** | TypeScript | ✅ PASS |
| | Full tests | ✅ **198/198 PASS** |
| | Build | ✅ PASS (2.50s) |
| **AST** | Tests | ✅ 9/9 PASS |
| | WASM | ✅ Initializes, enriches, graceful fallback |
| **CLI** | Build | ✅ PASS |
| | Unit tests | ✅ 10/10 PASS |
| | Packaged CLI | ✅ Works independently |
| | Real repository | ✅ 282 findings |
| **BACKEND** | Server starts | ✅ RUNTIME VERIFIED |
| | Database | ✅ 8 tables, healthy |
| | Redis | ✅ BullMQ operational |
| | Auth flow | ✅ Register → Login → JWT → Profile |
| | Scan flow | ✅ Upload → Queue → Worker → Results |
| | Report flow | ✅ JSON, CSV, CBOM |
| **FRONTEND** | Build | ✅ PASS |
| | HTML served | ✅ Title correct |
| | CORS | ✅ Properly configured |
| | Backend connection | ✅ API reachable |
| **SECURITY** | No critical findings | ✅ PASS |
| | No high findings | ✅ PASS |
| | Authz tests | ✅ PASS (code review + runtime) |
| | Upload tests | ✅ PASS (code review + runtime) |
| **INTEGRATION** | CLI/backend/frontend parity | ✅ PASS (shared engine) |
| | Usage-aware recommendations | ✅ 11 regression tests PASS |
| **REAL WORLD** | Local repository scan | ✅ PASS |

---

## 10. Remaining Limitations

| Limitation | Severity | Impact |
|------------|----------|--------|
| No browser automation | MEDIUM | Cannot verify UI rendering, button clicks, form submissions |
| In-memory rate limiter | LOW | Per-process; documented need for Redis at scale |
| @ts-ignore in AST | LOW | Parser constructor types not exposed by web-tree-sitter |
| eval() in third-party | LOW | web-tree-sitter uses eval for WASM loading |

---

## 11. Exact Files Changed

| File | Change |
|------|--------|
| `shared/engine/scanner.ts` | Rewrote `getRecommendation()` — 58 lines replaced with usage-aware logic |
| `shared/engine/migrationPlanner.ts` | Fixed Phase 2/3 filtering — signature findings excluded from key establishment |
| `shared/engine/migrationPlanner.ts` | Fixed weak algorithms description — per-type replacements |
| `src/tests/scanner.test.ts` | Added 11 regression tests for usage-aware recommendations |

---

## 12. Final Verdict

### **READY FOR RELEASE CANDIDATE**

**Evidence-based reasoning:**

1. **PQC recommendations are correct** — Usage-aware logic ensures RSA-for-signatures → ML-DSA, RSA-for-key-exchange → ML-KEM, symmetric → AES, hash → SHA-256
2. **Severity model is correct** — Two-axis model with bounded escalation, all invariants enforced
3. **All 198 tests pass** — Including 11 new regression tests for recommendation correctness
4. **Backend is fully functional** — Auth, upload, scan, worker, reports all verified at runtime
5. **CLI works independently** — Builds, tests, scans, packages correctly
6. **Frontend builds and serves** — HTML served, CORS configured, backend reachable
7. **Security is solid** — No critical/high findings, authz enforced, upload hardened

**What remains for full release (not blockers):**
- Browser UI automation testing (requires Playwright/Puppeteer)
- Manual browser walkthrough by a human tester
