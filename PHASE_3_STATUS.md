# Phase 3 — Depth: Status Report

**Date:** 2026-08-27
**Phase:** 3 — Depth (P0-7, P0-8, P0-11, P0-12)

---

## STATUS: COMPLETE

---

### P0-7 — AST Revival
- `shared/engine/detectors/ast.ts` rewritten with dynamic imports and graceful degradation
- Works in Node.js (server-side) with WASM grammars
- Browser: graceful fallback (WASM loading not yet configured)
- Extracts call arguments, determines comment/string context, identifies node type
- Adjusts confidence based on AST evidence (+0.15 call expressions, −0.30 comments)
- `getAstStats()` utility for coverage reporting

### P0-8 — Finding Fingerprints
- `generateFingerprint()` in scanner.ts: deterministic, stable across rescans
- Excludes line numbers (inserting a line above doesn't resurrect suppressed findings)
- SHA-256 (Node) or simple hash (browser) of `repo:path:algorithm:usage:pattern`
- Findings include `fingerprint`, `firstSeen`, `lastSeen`

### P0-11 — Frontend Auth
- `App.tsx` has auth gate: unauthenticated users see Landing + LoginModal
- `useAuthStore` manages user state across App, Topbar, Sidebar
- LoginModal supports both backend JWT auth and client-only demo mode
- Role-gating on admin-only user management routes

### P0-12 — Context Override UI
- `ContextOverridePanel.tsx` for per-finding/per-service overrides
- Overrides: internetFacing, dataSensitivity, dataLifetimeYears, businessCriticality
- `recalculateFindingsWithContext()` recalculates risk scores
- Overrides persist across rescans

---

## Tests

| Suite | Tests | Result |
|---|---|---|
| scanner.test.ts | 28 | ✅ PASS |
| riskEngine.test.ts | 26 | ✅ PASS |
| api.test.ts | 27 | ✅ PASS |
| frontend.test.ts | 35 | ✅ PASS |
| phase2.test.ts | 38 | ✅ PASS |
| pdfReport.test.ts | 8 | ✅ PASS |
| ast.test.ts | 8 | ✅ PASS |
| **Total** | **170** | **✅ ALL PASS** |

---

## Known Limitations

1. AST WASM files not available on Windows — enrichment silently degrades
2. Business criticality remains filename-based (improved by context overrides)
3. `findingCounter` is module-global (IDs climb across browser scans)
