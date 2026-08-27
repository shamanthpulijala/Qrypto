# Qrypto — Implementation Log

A running record of every change made while turning Qrypto from an audited prototype into a working product.

---

## Phase 1 — Truth (2026-08-27)

**Date/Time:** 2026-08-27
**Phase:** 1 — Truth (P0-1, P0-2, P0-4, P0-9)

### Objectives
1. Remove all fabricated UI numbers (P0-1)
2. Separate algorithm severity from contextual risk (P0-2)
3. Replace hardcoded confidence with computed/evidence-based confidence (P0-4)
4. Derive migration roadmap from real findings (P0-9)

### Files Changed

| File | Change |
|---|---|
| `shared/engine/severity.ts` | **NEW** — Severity/risk split model with invariants I1, I2, I3 |
| `shared/engine/scanner.ts` | Added computed confidence, imported severity module, added evidence metadata |
| `shared/engine/riskEngine.ts` | Removed NovaBank demo-specific business criticality entries |
| `shared/engine/migrationPlanner.ts` | Removed all fabricated owners and fake statuses |
| `shared/engine/detectors/config.ts` | Added `algorithmSeverity`, `severityRationale` to findings |
| `shared/engine/detectors/dependencies.ts` | Added `algorithmSeverity`, `severityRationale` to findings |
| `src/components/dashboard/RiskPulse.tsx` | Replaced fabricated stream with findings-derived events |
| `src/components/dashboard/Dashboard.tsx` | Replaced hardcoded ring scores with computed data |
| `src/components/dashboard/NextBestAction.tsx` | Replaced fake impact/effort with real risk/priority |
| `src/components/layout/Topbar.tsx` | Changed "LIVE ASSESSMENT" to "SCAN COMPLETE" |
| `src/components/findings/FindingDetailModal.tsx` | Removed fabricated "$100k/month" PCI penalty |
| `src/components/repository/RepositoryDetailModal.tsx` | Removed fabricated LOC/size fallback |
| `src/components/migration/MigrationPlanner.tsx` | Replaced hardcoded HYBRID MODE bar with real task stats |
| `src/components/landing/Landing.tsx` | Corrected pattern count, HNDL data, migration bars, risk factors, source code claim |
| `src/data/novaBankRepo.ts` | Added `algorithmSeverity`, `severityRationale` |
| `src/data/sampleRepo.ts` | Added `algorithmSeverity`, `severityRationale` |
| `src/tests/riskEngine.test.ts` | Added `algorithmSeverity` to test helper |
| `src/tests/frontend.test.ts` | Made `owner` check optional |
| `PHASE_1_STATUS.md` | **NEW** — Phase status document |

### Major Implementation Decisions

1. **Severity/risk split uses CVSS-inspired model** — algorithm severity is intrinsic (path-independent), contextual risk drives prioritization only. Escalation capped at one level, quantum-resistant primitives never escalated. This mirrors the CVSS base/environmental separation that security reviewers already expect.

2. **Confidence computation is evidence-based** — starts from pattern specificity, adds boost for key size extraction, deducts for comments/test paths. AST corroboration is structured but inactive (AST layer is dead). The 0.70 threshold is now meaningful.

3. **Migration tasks are never fabricated** — all tasks start as `todo` with no owner. A freshly scanned repo generates tasks derived from its actual findings. Status changes require actual persisted state.

4. **No "improvement by invention"** — when removing a fabricated number, we either wire real data or remove the display. We do not replace one fake number with another.

### Tests Run

| Test | Result |
|---|---|
| `tsc -b` (TypeScript typecheck) | ✅ PASS — 0 errors |
| `vitest run` (all tests) | ✅ 116/116 PASS |
| `vite build` (frontend bundle) | ⚠️ Pre-existing failure — `web-tree-sitter` import |

### Test Results Detail
- `src/tests/scanner.test.ts`: 28/28 pass
- `src/tests/riskEngine.test.ts`: 26/26 pass
- `src/tests/api.test.ts`: 27/27 pass
- `src/tests/frontend.test.ts`: 35/35 pass

### Known Limitations
- AST layer is dead in both runtimes (browser and server)
- Business criticality remains filename-based (substring heuristic)
- `findingCounter` is module-global (IDs climb across browser scans)
- Frontend build fails due to pre-existing `web-tree-sitter` issue

### Next Recommended Phase
**Phase 2 — Requirement Completion**: CycloneDX 1.6 CBOM (P0-5), Mosca engine (P0-3), model fields (P0-10), PDF reports (P0-6).

---

## Phase 2 — Requirement Completion (2026-08-27)

**Date/Time:** 2026-08-27
**Phase:** 2 — Requirement Completion (P0-5, P0-3, P0-10)

### Objectives
1. Add `mode`, `library`, `libraryVersion`, `protocol`, `variant` to Finding type (P0-10)
2. Create algorithm registry with canonical names, NIST status, CycloneDX mappings (P0-5a)
3. Create conformant CycloneDX 1.6 CBOM generator (P0-5b)
4. Wire CBOM to Reports page + browser-mode export (P0-5c)
5. Create Mosca engine with configurable threat horizon (P0-3a)
6. Wire Mosca into Q-Day simulator with explainability panel (P0-3b)

### Files Changed

| File | Change |
|---|---|
| `shared/types/index.ts` | Added `CryptoMode` type, `mode`, `library`, `libraryVersion`, `protocol`, `variant` to `Finding` |
| `shared/engine/registry.ts` | **NEW** — Algorithm registry with 40+ entries, CycloneDX primitives, NIST OIDs, PQC replacements |
| `shared/engine/cbom.ts` | **NEW** — CycloneDX 1.6 CBOM generator (conformant, spec-valid) |
| `shared/engine/mosca.ts` | **NEW** — Mosca engine (X = Y + Z model, configurable horizon, explainable derivation) |
| `src/engine/cbom.ts` | **NEW** — Engine shim for CBOM module |
| `src/engine/mosca.ts` | **NEW** — Engine shim for Mosca module |
| `src/engine/registry.ts` | **NEW** — Engine shim for algorithm registry |
| `src/components/reports/Reports.tsx` | Added CBOM export button + CycloneDX compliance section |
| `src/components/qday/QDaySimulator.tsx` | Replaced linear fudge factor with Mosca model + explainability panel |
| `server/src/routes/reports.routes.ts` | Replaced CBOM stub with conformant generator |
| `src/tests/phase2.test.ts` | **NEW** — 23 tests for registry, CBOM, and Mosca |

### Major Implementation Decisions

1. **Algorithm registry is the single source of truth for CycloneDX mappings** — 40+ algorithms mapped to canonical names, CycloneDX primitives, NIST OIDs, quantum status, and PQC replacements. Unknown algorithms get sensible defaults. The registry unblocks both CBOM and future PQC recommendation improvements.

2. **CycloneDX 1.6 uses `cryptographic-asset` type** — the Phase 0 stub used invalid `cryptography` and `secret-material`. The new generator uses the correct 1.6 enum values and groups findings by algorithm+keySize+category for clean BOM components.

3. **Mosca engine is fully explainable** — every finding gets a step-by-step derivation showing X (data lifetime), Y (migration time), Z (threat horizon), and the equation. The horizon is ALWAYS documented as an assumption, never presented as fact.

4. **Migration time estimation is conservative** — based on algorithm complexity categories (secrets: days, TLS: weeks, RSA key exchange: months). Not invented — reflects real-world migration effort patterns.

5. **Q-Day simulator now uses Mosca** — the linear fudge factor `drop = vulnerableFindings.length * 4.0 * yearFactor` is replaced with the real X = Y + Z model. Exposure is now the percentage of vulnerable findings where data lifetime + migration time exceeds the threat horizon.

### Tests Run

| Test | Result |
|---|---|
| `tsc -b` (TypeScript typecheck) | ✅ PASS — 0 errors |
| `vitest run` (all tests) | ✅ 139/139 PASS |

### Test Results Detail
- `src/tests/scanner.test.ts`: 28/28 pass
- `src/tests/riskEngine.test.ts`: 26/26 pass
- `src/tests/api.test.ts`: 27/27 pass
- `src/tests/frontend.test.ts`: 35/35 pass
- `src/tests/phase2.test.ts`: 23/23 pass (NEW)

### Known Limitations
- Mosca migration time is estimated from algorithm category, not from actual codebase analysis
- The CBOM does not yet include certificate chain data (no X.509 parsing)
- Business criticality remains filename-based

### Next Recommended Phase
**Phase 3 — Depth**: AST revival (P0-7), finding fingerprints (P0-8), frontend auth (P0-11), context override UI (P0-12).

---

## Phase 2 continued — PDF Reports (2026-08-27)

**Date/Time:** 2026-08-27
**Phase:** 2 — PDF Reports (P0-6)

### Objectives
1. Add browser-based PDF report generation (executive + technical)
2. Wire PDF export to Reports page
3. Add tests for PDF data pipeline

### Files Changed

| File | Change |
|---|---|
| `shared/engine/pdfReport.ts` | **NEW** — PDF report generator using jsPDF + jspdf-autotable |
| `src/engine/pdfReport.ts` | **NEW** — Engine shim for PDF module |
| `src/components/reports/Reports.tsx` | Added PDF export buttons (executive + technical), data builder |
| `src/tests/pdfReport.test.ts` | **NEW** — 8 tests for PDF data pipeline |

### Major Implementation Decisions

1. **jsPDF + jspdf-autotable** — chosen for browser-native PDF generation without server dependency. Works in both in-browser and backend modes. autotable provides clean table rendering with per-cell color styling.

2. **Two report types** — Executive (high-level: readiness score, scan stats, compliance, critical findings, migration roadmap) and Technical (adds full findings table with confidence derivation and evidence details).

3. **Data pipeline testable without canvas** — PDF data preparation is separated from jsPDF rendering, allowing unit tests to verify structure and logic without a browser canvas.

4. **Per-page footer** — every page includes the Qrypto version, generation date, page numbers, and the disclaimer that quantum risk assessments are estimates.

### Tests Run

| Test | Result |
|---|---|
| `tsc -b` (TypeScript typecheck) | ✅ PASS — 0 errors |
| `vitest run` (all tests) | ✅ 147/147 PASS |

### Test Results Detail
- `src/tests/scanner.test.ts`: 28/28 pass
- `src/tests/riskEngine.test.ts`: 26/26 pass
- `src/tests/api.test.ts`: 27/27 pass
- `src/tests/frontend.test.ts`: 35/35 pass
- `src/tests/phase2.test.ts`: 23/23 pass
- `src/tests/pdfReport.test.ts`: 8/8 pass (NEW)

---

## Phase 2 Completion — Gap Fixes (2026-08-27)

**Date/Time:** 2026-08-27
**Phase:** 2 — Completion fixes (registry integration, field population, schema validation, parity, developer PDF)

### Objectives
1. Integrate algorithm registry into scan pipeline (was unused by scanner)
2. Populate mode, library, protocol, variant from detection evidence
3. Add CBOM schema validation tests
4. Add browser/backend parity tests
5. Add Mosca assessment to PDF reports
6. Add developer remediation PDF type
7. Add integration test (scan → Mosca → CBOM)
8. Improve Mosca migration time to use finding context

### Files Changed

| File | Change |
|---|---|
| `shared/engine/scanner.ts` | Integrated registry for recommendations, added field detection helpers, flagged unknown algorithms |
| `shared/engine/mosca.ts` | Improved migration time estimation to use hardcoded/library/cert context, documented estimation basis |
| `shared/engine/pdfReport.ts` | Added Mosca section, developer remediation report type |
| `src/components/reports/Reports.tsx` | Added developer PDF export button |
| `src/tests/phase2.test.ts` | Added 15 new tests: schema validation, parity, integration, Mosca context |
| `PHASE_2_STATUS.md` | **NEW** — Phase 2 completion status document |

### Major Implementation Decisions

1. **Registry is now the primary source for PQC recommendations** — the scanner's hardcoded if/else chains are replaced by registry lookup with context-aware enhancement. Unknown algorithms get honest "Insufficient context" responses.

2. **New Finding fields are populated from evidence** — mode, library, protocol, variant are detected from the matched pattern text and file path. Only populated when evidence exists; undefined otherwise (never fabricated).

3. **Mosca migration time now considers finding context** — hardcoded status (+30%), library presence (-20%), certificate usage (+20%). The estimation basis is documented in every derivation step.

4. **CBOM schema validation is automated** — 8 tests verify the CycloneDX 1.6 structure, required fields, empty/single/PQC/unknown cases.

5. **Parity is enforced by deterministic tests** — same input produces identical scanner output, CBOM, and Mosca results.

### Tests Run

| Test | Result |
|---|---|
| `tsc -b` (TypeScript typecheck) | ✅ PASS — 0 errors |
| `vitest run` (all tests) | ✅ 162/162 PASS |
| `vite build` (production build) | ⚠️ Pre-existing failure — `web-tree-sitter` import (not Phase 2) |

### Test Results Detail
- `src/tests/scanner.test.ts`: 28/28 pass
- `src/tests/riskEngine.test.ts`: 26/26 pass
- `src/tests/api.test.ts`: 27/27 pass
- `src/tests/frontend.test.ts`: 35/35 pass
- `src/tests/phase2.test.ts`: 38/38 pass (15 new)
- `src/tests/pdfReport.test.ts`: 8/8 pass

### Known Limitations
- Production build fails due to pre-existing `web-tree-sitter` issue (not Phase 2)
- `libraryVersion` not populated yet (requires manifest parsing)
- Business criticality remains filename-based

### Next Recommended Phase
**Phase 3 — Depth**: AST revival (P0-7), finding fingerprints (P0-8), frontend auth (P0-11), context override UI (P0-12).
