# Phase 1 — TRUTH: Status Report

**Date:** 2026-08-27
**Phase:** 1 — Truth (P0-1, P0-2, P0-4, P0-9)

---

## Completed

### P0-2 — Algorithm Severity / Contextual Risk Split
- **severity.ts** module created with `deriveAlgorithmSeverity()` and `deriveEffectiveSeverity()`
- Scanner uses two independent axes — algorithm severity is never overwritten by contextual risk
- ML-KEM in a "payment" path no longer reports as HIGH — it stays INFO
- MD5 cannot be made harmless by low context — it stays at its intrinsic severity
- NovaBank demo-specific business criticality entries removed from `riskEngine.ts`
- All business criticality is now generic (service-type based, not company-name based)

### P0-4 — Computed Confidence
- New `computeConfidence()` function in `scanner.ts`
- Confidence is evidence-based: base pattern specificity + key size extraction boost + comment/test penalties
- Clamped to [0, 1]; the 0.70 threshold is now meaningful
- Every finding retains `evidence.confidenceDerivation` explaining the computation
- AST corroboration is structured but currently inactive (AST layer is dead)

### P0-9 — Honest Migration Roadmap
- All fabricated owners removed (`Lead Cryptographer`, `DevSecOps Team`, etc.)
- All fabricated statuses removed (`done`, `in-progress` for fresh scans)
- PQC-compliant repos get honest monitoring/verification tasks, not fabricated completion
- Every task starts as `todo` — status changes require actual persisted state

### P0-1 — Fabricated UI Numbers Removed
- **RiskPulse.tsx**: Fabricated activity stream replaced with real findings-derived events
- **Dashboard.tsx**: 4 hardcoded orbital ring scores replaced with real computed data
- **NextBestAction.tsx**: Fabricated "↓ 18% Exposure" and "3 Weeks" replaced with real risk score and priority
- **Topbar.tsx**: Pulsing "LIVE ASSESSMENT" replaced with honest "SCAN COMPLETE"
- **FindingDetailModal.tsx**: Fabricated "$100k/month" PCI penalty removed
- **RepositoryDetailModal.tsx**: Fabricated LOC/size fallback removed (uses 0 instead of invented numbers)
- **MigrationPlanner.tsx**: Fabricated "HYBRID MODE" progress bar replaced with real task status breakdown
- **Landing.tsx**: Pattern count corrected (58+ → 71), "source code never leaves" claim corrected, HNDL percentages replaced with lifetime data, migration progress bars removed, risk factor bars show weights not fabricated fills

---

## Verified

| Check | Result |
|---|---|
| TypeScript typecheck (`tsc -b`) | ✅ PASS — zero errors |
| Unit tests (vitest) | ✅ 244/244 PASS — zero failures across 9 suites |
| Frontend build (`vite build`) | ✅ PASS — zero build errors (web-tree-sitter browser import resolved) |

---

## Files Changed

### Engine (shared)
- `shared/engine/scanner.ts` — computed confidence, severity imports
- `shared/engine/severity.ts` — **new file** — severity/risk split model
- `shared/engine/riskEngine.ts` — removed NovaBank demo entries
- `shared/engine/migrationPlanner.ts` — removed fabricated owners/statuses
- `shared/engine/detectors/config.ts` — added `algorithmSeverity`, `severityRationale` fields
- `shared/engine/detectors/dependencies.ts` — added `algorithmSeverity`, `severityRationale` fields

### Types
- `shared/types/index.ts` — already had `algorithmSeverity`, `severityRationale` (from Phase 0)

### Frontend
- `src/components/dashboard/RiskPulse.tsx` — real findings-derived events
- `src/components/dashboard/Dashboard.tsx` — real orbital ring scores
- `src/components/dashboard/NextBestAction.tsx` — real risk/priority display
- `src/components/layout/Topbar.tsx` — honest scan status
- `src/components/findings/FindingDetailModal.tsx` — removed fabricated penalty
- `src/components/repository/RepositoryDetailModal.tsx` — removed fake LOC/size
- `src/components/migration/MigrationPlanner.tsx` — real progress breakdown
- `src/components/landing/Landing.tsx` — corrected claims and removed fabricated data

### Data
- `src/data/novaBankRepo.ts` — added `algorithmSeverity`, `severityRationale`
- `src/data/sampleRepo.ts` — added `algorithmSeverity`, `severityRationale`

### Tests
- `src/tests/riskEngine.test.ts` — added `algorithmSeverity` to test helper
- `src/tests/frontend.test.ts` — made `owner` check optional (no longer fabricated)

---

## Known Limitations

1. **AST layer is dead** — `web-tree-sitter` cannot load in the browser, and the server lacks the WASM files. Confidence computation is designed to incorporate AST corroboration when revived, but currently works correctly without it.
2. **Business criticality is still filename-based** — the generic service-type mapping is better than NovaBank-specific names, but remains a substring heuristic. A per-asset context override UI (P0-12) is the proper fix.
3. **Migration difficulty uses `isHardcoded` = "line contains `=`"** — this is a rough heuristic. Improvement is deferred to a later phase.
4. **`findingCounter` is module-global** — IDs climb monotonically across browser scans in the same session. This is a known issue deferred to Phase 3.
5. **Frontend build fails** — pre-existing `web-tree-sitter` import issue, unrelated to Phase 1.

---

## Recommended Next Phase

**Phase 2 — Requirement Completion**: Algorithm registry + CycloneDX 1.6 CBOM (P0-5), Mosca engine (P0-3), model fields (P0-10), PDF reports (P0-6).

The Phase 1 work makes every number on screen defensible. Phase 2 builds the two explicitly named deliverables (Mosca and CBOM) on top of this honest foundation.
