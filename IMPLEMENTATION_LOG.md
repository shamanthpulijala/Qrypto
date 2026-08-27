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
