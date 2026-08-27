# Qrypto — Audit, Gap Analysis & Production Roadmap

**Problem Statement:** SIH 2026 · ID 26164 · Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) · NTRO
**Audited commit:** `4ea0af9` — *feat: upgrade Qrypto for production-grade ECDAT*
**Audit date:** 2026-08-27
**Auditor stance:** would this survive review by an enterprise CISO or a government cryptographic authority?

---

## 0. Read this first — three blocking issues

Before any feature work, three things need attention. Two are safety issues, one is that the project currently cannot build.

### 0.1 A live API key is exposed — rotate it now

`src/api/.env` contains a real OpenRouter credential, twice:

```
VITE_OPENROUTER_API_KEY=<redacted — live OpenRouter key, rotate immediately>
OPENROUTER_API_KEY=<redacted — same key, duplicated>
```

What I verified:

| Check | Result |
|---|---|
| In git history? | **No** — `git log -S"sk-or-v1" --all` is empty, `src/api/.env` is untracked |
| Ignored by git? | **No** — root `.gitignore` is 0 bytes, so `git check-ignore` matches nothing. The next `git add .` commits it |
| In the built bundle? | **Yes** — found in `dist/assets/index-CxYlEYbn.js` |

The `VITE_` prefix is the core problem: Vite *inlines* those variables into the client bundle by design. A `VITE_`-prefixed secret is a published secret. If the deployed site was ever built from that bundle, anyone can open devtools and spend the account.

Rotate the key regardless of the git status, restore `.gitignore` before any `git add`, and move LLM calls behind the backend so no key reaches the browser.

### 0.2 Privilege escalation — anyone can become ADMIN and read every tenant's data

This is a genuine exploit chain, not a theoretical concern. Three facts combine:

**1.** The public registration endpoint takes `role` from the request body — `server/src/routes/auth.routes.ts:13,30`:

```ts
const { email, password, name, role } = req.body;
// ...
role: role || 'ANALYST',
```

**2.** `requireRole` is defined at `server/src/middleware/auth.ts:36` and **never used anywhere**. I grepped the whole server: the only hit is its own definition.

**3.** Every ownership check treats ADMIN as a global bypass — `findings.routes.ts:25,64,88`, `reports.routes.ts:19`, `scan.routes.ts:114`:

```ts
if (scan.userId !== req.user!.userId && req.user!.role !== 'ADMIN') { /* deny */ }
```

So: `POST /api/auth/register` with `{"role":"ADMIN"}` returns a valid ADMIN token, which reads every user's scans, findings and reports. Findings embed matched source lines (`detectedPattern`), so this leaks customers' source code.

**Fix:** strip `role` from the register payload (always `ANALYST`); promotion becomes an ADMIN-only operation guarded by `requireRole(['ADMIN'])`. Replace the `role === 'ADMIN'` bypass with an explicit scoping rule.

Two related items in the same area:

- `server/src/config.ts:9` ships a hardcoded fallback JWT secret, and in production it only *warns* (`:13-14`) rather than refusing to boot. The repo is public, so the fallback secret is public — tokens become forgeable if `JWT_SECRET` is unset. Make production boot **fail** on a missing secret.
- Rate limiting is applied only to `POST /api/scans` (`scan.routes.ts:19`). `/login` and `/register` are unthrottled — credential stuffing, and unlimited admin-account creation.

### 0.3 The frontend cannot build — 18 files are zero-byte

Exactly 18 tracked files are empty in the working tree:

```
package.json  package-lock.json  vite.config.ts  tsconfig.json
tsconfig.app.json  tsconfig.node.json  index.html  .gitignore
.oxlintrc.json  README.md  .env.example
create-test-repo.js  create-test-repo.cjs
create-enterprise-sample-repo.cjs  create-pqc-ready-repo.cjs
sample-vulnerable-repo.zip  qrypto-enterprise-sample.zip  qrypto-pqc-ready-sample.zip
```

`npm install`, `dev`, `build`, and `test` all fail. **The engine and all application source are intact** — `shared/engine/scanner.ts` is 13,415 bytes, `shared/types/index.ts` is 10,675 bytes.

**Recovery is safe, and I verified this specifically because `git diff HEAD` looks alarming (82 files, 12,486 insertions).** It isn't:

```
raw:            82 files changed, 12486 insertions(+), 20785 deletions(-)
ignore-cr-eol:  18 files changed,     0 insertions(+),  8299 deletions(-)
```

64 of those files differ **only** by CRLF line endings. Once line endings are ignored, every remaining difference is a pure deletion — there is no uncommitted work to lose, and all 18 files are recoverable from HEAD.

```bash
git checkout -- .                  # restores all 18; loses nothing
git config core.autocrlf true      # stops the CRLF churn
```

> One housekeeping note: this repo's remote is `shamanthpulijala/quantum-machine-control.git`, not the `shamanthpulijala/Qrypto` you referenced in the brief. Worth confirming which is authoritative before anyone pushes.

---

## PART A — Current state

### A.1 Architecture

```
┌──────────────────────────── Frontend (Vite + React 19) ─────────────────────────────┐
│  Landing (ZIP drop / sample load)  →  Zustand assessmentStore                        │
│  Dashboard · Findings · Inventory · HNDL · Migration · Agility                       │
│  AttackMap · Q-Day · AI Advisor · Reports · Settings                                 │
│                        imports src/engine/* (one-line re-export shims)               │
└────────────┬────────────────────────────────────────────────────┬───────────────────┘
             │ Mode A: in-browser scan                            │ Mode B: backend scan
             ▼                                                    ▼
┌──── shared/engine (SINGLE SOURCE OF TRUTH) ────┐   ┌──── server/ (Express) ─────────┐
│ pipeline · scanner · riskEngine                 │◄──┤ /api/auth /scans /findings     │
│ hndlAnalyzer · migrationPlanner · cryptoAgility │   │ /reports                       │
│ detectors/ ×10 (~71 regex patterns)             │   │ multer + adm-zip → BullMQ      │
│ detectors/ast.ts  ← dead at runtime             │   │ worker → Prisma → PostgreSQL   │
└─────────────────────────────────────────────────┘   └────────────────────────────────┘
```

**The strongest architectural decision in the codebase:** `shared/engine/` is a genuine single source of truth. The frontend imports it via one-line shims in `src/engine/*`, and the backend worker imports it directly (`server/src/workers/scan.worker.ts:5-8`). Frontend and backend run *identical* detection logic. Please don't "clean up" those shims — they are deliberate and correct.

The dual execution mode is also a real asset: an in-browser scan path (nothing leaves the machine) alongside a backend path. That in-browser mode is the seed of the on-prem story NTRO will care about.

### A.2 Tech stack

| Layer | Choice |
|---|---|
| Frontend | React 19.2, Vite 8.2, TypeScript ~6.0, Zustand 5, per-component CSS |
| Visualisation | recharts 3.10, @xyflow/react 12, three.js + fiber + drei, framer-motion 13, gsap |
| Navigation | **No router.** `currentPage` string in the store, `switch` in `src/App.tsx:71-92` |
| Backend | Express 4.21, Prisma 5.22 → PostgreSQL, BullMQ 5 → Redis, JWT, bcrypt, multer 2, adm-zip, helmet 8 |
| Tests | Vitest 4.1 — 116 tests across 4 files |
| Deployment | **Nothing in-repo.** No Dockerfile, no compose, no `.github/`, no vercel.json — all verified absent |

The absent router is a real product limitation, not a style issue: no deep links, no browser back/forward, and no shareable report URL — which enterprise reporting workflows assume.

### A.3 Detection engine — what it actually does

Ten detectors, **~71 regex patterns**, counted per file:

| Detector | Patterns | Method |
|---|---|---|
| ecc, rsa, hashes, secrets, signatures, certificates, tls, pqc | 15, 12, 9, 9, 8, 7, 6, 5 | Regex |
| dependencies | 6 packages | **Real parsing** — `JSON.parse` of package.json, line-split of requirements.txt |
| config | 2 directives | Regex, and only for files literally named `nginx.conf` / `default.conf` |

**The AST layer is dead in both runtimes.** `detectors/ast.ts:1` genuinely imports `web-tree-sitter`, but:

```ts
if (typeof process !== 'undefined' && process.env) {
  wasmPath = require('path').resolve(process.cwd(), 'node_modules/tree-sitter-wasms/out', wasmFile);
} else {
  return;                          // ast.ts:65 — browser always bails
}
```

and `server/package.json` lists neither `web-tree-sitter` nor `tree-sitter-wasms`, so the server path fails too. Both failures are swallowed by `console.warn` (`ast.ts:13-14`, `:119-121`) and the scan still reports success. Even if the wasm loaded, there is no semantic resolution — no argument extraction, no import/alias resolution, no constant propagation. `CRYPTO_API_PATTERNS` at `:31-41` is declared and never referenced.

So **detection is regex-only today.** That is a defensible starting point, but the pitch must not claim AST analysis.

Two concrete key-size defects follow from regex-only extraction:

- `rsa.ts:32` — the idiomatic Python call `rsa.generate_private_key(...)` has no capture group, so the most common real-world RSA keygen yields **no key size at all**.
- `certificates.ts:11-18` — `keySize: 2048` is hardcoded *and* a capture group exists, but `scanner.ts:151` short-circuits on the hardcoded value. So `openssl genrsa -out ca.key 1024` is reported as **2048-bit**. A wrong key size is worse than a missing one.

Language coverage is by file extension (`scanner.ts:16-24`): Python, Java, JavaScript, TypeScript, Go, plus YAML/JSON/XML. No C, C++, C#, Rust. Three inconsistent allowlists exist (`scanner.ts:16-24`, `pipeline.ts:70-74`, `upload.service.ts:58`) — the upload layer accepts `.rs`, `.c`, `.cpp`, `.cs` which the pipeline then silently discards.

### A.4 Confidence scoring — every value is a hardcoded literal

Confidence is copied verbatim from the pattern definition — `scanner.ts:180`:

```ts
confidence: pattern.confidence,
```

No entropy, no corroboration, no penalty for test/vendor/comment paths. Values range 0.80–0.99 (e.g. `secrets.ts` private key `0.99`, hardcoded password `0.80`).

**Consequence: the confidence filter is a permanent no-op.** The threshold is 0.70 (`pipeline.ts:170-172, 271`) and the lowest constant in the repo is 0.80. The UI still logs *"Applying confidence threshold (≥0.70)…"* on every scan. The only code that could push a value below 0.70 is the AST penalty, which never runs.

### A.5 Risk engine — right shape, wrong inputs

The weighted sum itself is sound (`riskEngine.ts:134-141`, weights `0.30/0.20/0.15/0.15/0.10/0.10`). The inputs are the problem: **four of six are filename substring guesses.**

| Input | Source | Verdict |
|---|---|---|
| Algorithm risk | Step function on `quantumStatus` (`riskEngine.ts:26-32`) | Reasonable |
| Business criticality | Lookup on **service name string** (`riskEngine.ts:49-72`) | Hardcoded, demo-contaminated |
| Internet exposure | Path contains `api`/`controller`/`gateway`/`web` (`scanner.ts:81-86`) | Substring guess |
| Data lifetime | Path/service keyword → years (`scanner.ts:96-102`) | Substring guess |
| Data sensitivity | Path/service substring (`scanner.ts:88-94`) | Substring guess |
| Migration difficulty | Category + `isHardcoded` | `isHardcoded` = "line contains `=`" (`scanner.ts:163`) |

The criticality table ships the demo's own fixtures inside the production engine:

```ts
'NovaBank Payment Service': 100, 'NovaBank API Gateway': 85,   // riskEngine.ts:49-72
```

And `'Test Suite': 10` is checked **last** in `scanner.ts:66-79`, so `tests/payment_test.py` scores as `'Payment Service'` = 100.

#### The single most damaging bug in the product

Severity is recomputed from the risk score, discarding the pattern's own severity (`scanner.ts:183-186`). Since context contributes 55% of the weight independent of algorithm quality, correct modern cryptography in a "payment" path is reported as high severity. Worked example for ML-KEM:

```
5×0.30 + 100×0.20 + 100×0.15 + 85×0.15 + 100×0.10 + 40×0.10 = 63  →  "high"
```

**Qrypto currently flags NIST-approved post-quantum cryptography as a high-severity finding.** AES-256 and SHA-256 in payment paths land ~68, also "high". A cryptographer on the judging panel will find this in about ninety seconds, and it inverts the product's entire message. This is the highest-value single fix in this document.

### A.6 Mosca — absent

Grep-verified across `src/`, `shared/`, `server/src`: **no occurrence of "mosca" in any source file.** There is no shelf-life variable, no migration-time variable, no collapse-time variable, and no `X = Y + Z` comparison. This is an explicit requirement of the problem statement.

What exists instead is `hndlAnalyzer.ts` — 72 lines producing a **fixed 10-row table** (`:7-18`) whose risk comes from string-comparing hardcoded lifetime labels (`:20-30`). It never reads `finding.dataLifetimeYears` — the one lifetime value the scanner actually derived per finding is ignored.

The only Q-Day number is `qdayYear: 2030` hardcoded in `src/store/assessmentStore.ts:116`, and the simulator that consumes it is a linear fudge factor (`:190`, `drop = vulnerableFindings.length * 4.0 * yearFactor`), not a threat model.

### A.7 PQC recommendations

Two static if/else chains: `scanner.ts:230-273` and `migrationPlanner.ts:21-97`. The only contextual axis is `usage` — key exchange → ML-KEM, signing → ML-DSA. Nothing consults exposure, data lifetime, performance envelope, or hybrid-vs-pure choice. `pqcKnowledge.ts` holds 3 algorithms with a `variants` array no code selects from; SLH-DSA and FALCON are *detected* but never *recommended*.

**The migration roadmap is partly fabricated.** `migrationPlanner.ts:115-193` emits hardcoded tasks with invented owners — `'Lead Cryptographer'`, `'DevSecOps Team'`, `'Security Architecture Board'` — and pre-set statuses `'done'` / `'in-progress'` (`:242`). A freshly scanned repository ships a roadmap that already claims completed work. If a judge scans their own repo and sees tasks marked done, credibility is gone.

### A.8 CBOM — a stub, and the UI doesn't reach it

Repo-wide search for `cyclonedx` / `bomFormat` / `specVersion` returns exactly one location: `server/src/routes/reports.routes.ts:95-148`, whose own comment reads *"Phase 2 stub."* It is also spec-invalid: `type: 'cryptography'` (CycloneDX 1.6 uses `cryptographic-asset`), `assetType: 'secret-material'` (not a valid enum member), and `primitive` is set to Qrypto's internal categories (`public-key`, `tls`, `pqc`) rather than CycloneDX primitives.

**Nothing calls it.** `src/api/client.ts:202` declares `downloadCBOM`; no component invokes it. The two buttons the UI labels "CBOM" export a flat CSV (`Inventory.tsx:67-77`, filename `quantumguard-cbom.csv`) and an ad-hoc JSON dump (`Reports.tsx:425-450`). In browser-only mode there is no CycloneDX output at all.

**No PDF export exists** — no jsPDF/pdfmake/html2canvas dependency, and no `window.print()` anywhere in `src/`.

### A.9 Security posture

**Genuinely well done — keep this:**

- Zip handling (`upload.service.ts`): 10,000-entry cap (`:35`), path-traversal rejection (`:46`), compression-ratio check (`:52`), extension allowlist (`:58`).
- Cleanup on **both** success and error paths (`scan.worker.ts:163-165, 178-179`) — commonly forgotten.
- **No `child_process`, no `exec`, no `spawn`, no `git clone`** anywhere in the server. No command injection, no SSRF via repo URLs.
- Per-user ownership checks on every data route.
- Real persisted triage with a `FindingStatusChange` audit table (`findings.routes.ts:78-108`).
- Production error handler hides messages (`index.ts:51`); helmet enabled; CORS is single-origin, not wildcard.

**Needs work:**

| Issue | Location | Impact |
|---|---|---|
| Role injection at register + unused `requireRole` | `auth.routes.ts:13,30` | **Critical** — full cross-account read |
| Fallback JWT secret, warns only in prod | `config.ts:9,13` | **Critical** — forgeable tokens |
| No rate limit on `/login`, `/register` | `scan.routes.ts:19` only | High — credential stuffing |
| Zip-bomb check uses attacker-controlled headers | `upload.service.ts:51` | High — forge `header.size` to bypass |
| No aggregate uncompressed-size cap | `upload.service.ts` | High — ~5 GB disk per scan, 10 scans/hr |
| `fileFilter` trusts client mimetype | `upload.service.ts:23` | Medium — no magic-byte check |
| Rate limiter in-memory, never pruned, `req.ip` without `trust proxy` | `rateLimit.ts:5,9` | Medium — leaks memory; behind a proxy all users share one bucket |
| No tenant/org model | `schema.prisma` | Medium — per-user only, no multi-tenancy |
| No refresh tokens, revocation, MFA, SSO, password policy, lockout | — | Medium — enterprise table stakes |
| `dangerouslySetInnerHTML` on raw LLM output | `advisor/AIAdvisor.tsx:144` | XSS — dead code, delete the file |

Default credentials `postgres:postgres` at `config.ts:7` should also go.

### A.10 Frontend honesty audit — fix before demoing

The team explicitly asked not to present invented metrics. These are live in the UI right now.

| What | Where | Reality |
|---|---|---|
| "Real-time activity stream" | `RiskPulse.tsx:3,17-20` | **Fully fabricated.** Subscribes to the store (`:12`), then never reads it. Four hardcoded events with fake timestamps |
| Readiness gauge | `Dashboard.tsx:42-46` | **4 of 5 rings hardcoded** (Discovery 85, Agility 71, Migration 60, Certs 90). A real agility score exists and is ignored |
| "↓ 18% Exposure", "3 Weeks" | `NextBestAction.tsx:47,52` | Invented impact and effort |
| Lines of code, repo size | `RepositoryDetailModal.tsx:31-32` | `lineCount: Math.max(f.line+10, 45)`, `sizeBytes: 1024 + f.line*30` — fabricated, then summed into headline stats |
| Q-Day exposure % | `QDaySimulator.tsx:49` | `0.15 + decadeProgress * 1.35` |
| "HYBRID MODE" progress bar | `MigrationPlanner.tsx:101` | Literal `25%` / `10%` |
| HNDL bubbles, 5-year zone | `HNDLAnalyzer.tsx:22-25,93` | Magnitudes `100/300/600/1200`; bypasses the real HNDL engine |
| "$100k/month" PCI penalty | `FindingDetailModal.tsx:61` | Invented figure |
| "58+ patterns", "8 Languages" | `Landing.tsx:210,215` | Pattern count ≈ accurate (71); "8 languages" only if YAML/JSON/XML count |
| Static risk/migration/HNDL % | `Landing.tsx:45-50,55-59,64-66` | Marketing fixtures rendered as data |
| Pulsing "LIVE ASSESSMENT" | `Topbar.tsx:60-61` | False liveness on a static snapshot |
| "Source code never leaves your browser" | `Landing.tsx:455,473` | File paths, line numbers and org name **do** go to OpenRouter |

Two structural consequences worth separating out:

- `assessmentStore.ts:32` hardcodes `dependencies: []`, so the dependency attack graph **renders zero edges for every real scan**. The dependency-graph requirement is effectively unmet, and the Q-Day cascade can never propagate.
- `Inventory.tsx:265` surfaces per-regex author literals as a "Confidence" percentage, presenting hand-written constants as measured detector accuracy.

### A.11 Auth, tests, scale

**Frontend auth is dead code.** `LoginModal.tsx` is never rendered — grep for `useAuthStore` and `LoginModal` across `src/` hits only their own definitions. The app is fully open. `authStore.ts:34-56` holds demo users (`admin@quantumguard.ai` / `quantum2024`) printed in the UI at `LoginModal.tsx:110-113`. The token is correctly in-memory (`client.ts:11`), but the profile persists to localStorage (`authStore.ts:103`) — so after a refresh the user looks logged in while every API call is unauthenticated. No role-gating anywhere.

Also: `Settings.tsx:16` writes `gemini_api_key` while the store reads `qg_gemini_key` (`assessmentStore.ts:117`) — **saving an API key in Settings does nothing**, and the label says Gemini while the app calls OpenRouter.

**Tests:** 116 across four files (scanner 28, riskEngine 26, api 27, frontend 35). `frontend.test.ts` imports `render, screen, fireEvent, waitFor` and calls `render(` **zero times** — it re-tests engine functions. So no component is ever rendered in a test, and there is no coverage of auth, token handling, zip limits, or rate limiting.

**Scale:** `runScanPipeline` is `async` in name only — the sole awaits are the dead AST calls, and `scanFile` is fully synchronous. In the browser this blocks the main thread for the whole scan (no Web Worker); on the server it blocks the BullMQ worker, so effective concurrency is 1. `scanner.ts:134` does `content.slice(0, match.index)` per match to count newlines — O(n·m) quadratic on large files with many hits. `scan.worker.ts:49` uses `readFileSync`. `security.ts:55`'s `validateUploadedFile` is dead code and `MAX_TOTAL_UPLOAD_BYTES` is never referenced.

Two correctness bugs in the same area: `findingCounter` (`scanner.ts:59`) is module-global and reset only in `scanFiles`, which the pipeline never calls — so IDs climb monotonically across jobs in the long-lived worker. And `scan.worker.ts:86` overrides the engine with `dataSensitivity: 'High'`, so the same repo scanned in the browser and on the backend yields **different risk scores**.

---

## PART B — Gap analysis vs PS 26164

Scoring: ●●● meets intent · ●●○ partial · ●○○ token · ○○○ absent

| # | Requirement | Now | Evidence | Gap | Pri |
|---|---|---|---|---|---|
| **A. Cryptographic discovery** ||||||
| A1 | Algorithms (RSA/ECC/AES/SHA/…) | ●●● | ~71 patterns, 10 detectors | Cipher **modes** (GCM/CBC/ECB) not detected at all | P0 |
| A2 | Keys | ●●○ | `secrets.ts`, 9 patterns | No entropy scoring despite `entropy` in the type | P1 |
| A3 | Certificates | ●●○ | `certificates.ts` regex | No real X.509 parsing — no issuer/subject/validity/chain | P1 |
| A4 | Protocols | ●●○ | `tls.ts`, 6 patterns | No `protocol` field; no cipher-suite enumeration; SSH/IPsec absent | P1 |
| A5 | Libraries | ●●○ | `dependencies.ts`, 6 packages | No `library`/`version` fields — name stuffed into `algorithm` (`:34`) | P0 |
| A6 | Hardware modules (HSM) | ○○○ | — | Absent | P2 |
| A7 | Cloud services (KMS) | ○○○ | — | Absent | P2 |
| A8 | Binaries | ○○○ | — | No ELF/PE parsing | P1 |
| A9 | Containers | ○○○ | — | No image scanning | P1 |
| A10 | Multi-layer detection | ●○○ | `ast.ts` dead in both runtimes | Regex-only in practice | P0 |
| **B. Quantum risk assessment** ||||||
| B1 | Identify vulnerable systems | ●●● | `riskEngine.ts` | Sound shape | — |
| B2 | Context-aware risk | ●●○ | 6-factor weighted sum | 4 of 6 inputs are filename guesses; no user override UI | P0 |
| B3 | Sensitive-data risk | ●●○ | `dataSensitivity` inferred | Substring-based only | P1 |
| **C. Classification** ||||||
| C1 | Type, algorithm, usage, risk, exposure | ●●● | `Finding` type | — | — |
| C2 | Lifetime | ●●○ | `dataLifetimeYears` | Inferred, and **HNDL ignores it** | P0 |
| C3 | Business criticality | ●○○ | Service-name lookup | Not a field; table contains demo names | P0 |
| C4 | Version & mode | ○○○ | — | No `version`, no `mode` field | P0 |
| **D. Mosca** ||||||
| D1 | X = Y + Z model | ○○○ | **Grep-verified absent** | Entire requirement missing | **P0** |
| D2 | Configurable threat horizon | ●○○ | `qdayYear: 2030` in store | Hardcoded; engine never reads it | P0 |
| D3 | Explainable output | ○○○ | — | No derivation shown | P0 |
| **E. Recommendations** ||||||
| E1 | PQC algorithms | ●●○ | Static if/else | ML-KEM/ML-DSA only; SLH-DSA detected, never recommended | P0 |
| E2 | Hybrid approaches | ●○○ | Mentioned in strings | No hybrid decision logic | P0 |
| E3 | Multi-factor (latency/cost/compat) | ○○○ | Only `usage` | No performance or compatibility model | P1 |
| **F. Deliverable** ||||||
| F1 | **CycloneDX CBOM** | ●○○ | One "Phase 2 stub", spec-invalid, unreachable | Core deliverable unmet | **P0** |
| F2 | Standardised reports | ●○○ | JSON only | **No PDF**; CSV only in Inventory | P0 |
| F3 | Interactive GUI | ●●● | 20+ screens | Strong — but displays fabricated numbers | P0 |
| F4 | Scan repos / binaries / containers | ●○○ | ZIP only | 1 of 4 input classes | P1 |
| **G. Platform** ||||||
| G1 | Evidence per finding | ●●○ | `detectedPattern` + line | `evidence` object only populated by the dead AST layer | P0 |
| G2 | Confidence scoring | ●○○ | Hardcoded literals | Filter is a no-op | P0 |
| G3 | False-positive management | ●●○ | Real triage + audit table | **No fingerprint** → suppressions lost on rescan | P0 |
| G4 | Auth / RBAC | ●○○ | JWT + bcrypt; `requireRole` unused | Privilege escalation; frontend auth dead | **P0** |
| G5 | Audit logs | ●●○ | `AuditLog` model, persisted | Not surfaced in UI | P1 |
| G6 | Multi-tenancy | ●○○ | Per-user only | No org/tenant model | P2 |
| G7 | API-first | ●●● | 11 REST endpoints | Good | — |
| G8 | CLI | ○○○ | — | Absent | P1 |
| G9 | CI/CD integration | ○○○ | — | Absent | P1 |
| G10 | Continuous monitoring | ○○○ | — | Absent | P2 |
| G11 | On-prem / agent | ●●○ | In-browser mode is the seed | Not packaged or positioned | P1 |
| G12 | Deployment artifacts | ○○○ | No Dockerfile/CI — verified | Cannot be deployed reproducibly | P1 |
| G13 | Dependency graph | ●○○ | `AttackMap` exists | `dependencies: []` → **zero edges always** | P1 |
| G14 | Benchmark framework | ○○○ | — | No precision/recall harness | P1 |

**Roughly 45% of the problem statement is genuinely met.** Discovery breadth for source-code algorithms, the API surface, and the GUI are real strengths. The two structural holes are **Mosca (absent)** and **CycloneDX CBOM (stub)** — both named explicitly in the deliverable, and both very achievable in the time available.

---

## PART C — Target architecture

```
                        ┌──────────── CONTROL PLANE (SaaS or on-prem) ────────────┐
                        │  Auth (JWT+refresh, MFA, SSO) · RBAC · Audit · Tenants   │
                        │  REST API v1 · Job orchestration · Report store          │
                        └───────────────────────┬─────────────────────────────────┘
                                                │ results + CBOM only (no source)
   ┌────────────────────────────────────────────┴─────────────────────────────────┐
   │                        SCANNER AGENT (deployable unit)                        │
   │  ┌────────────┬────────────┬────────────┬────────────┬────────────┐          │
   │  │  Source    │  Binary    │ Container  │ Certificate│  Config    │          │
   │  │  Scanner   │  Scanner   │  Scanner   │  Scanner   │  Scanner   │          │
   │  └─────┬──────┴─────┬──────┴─────┬──────┴─────┬──────┴─────┬──────┘          │
   │        └────────────┴────────────┴────────────┴────────────┘                 │
   │                              ▼                                               │
   │   L1 Regex → L2 AST (tree-sitter) → L3 Dependency → L4 Config → L5 Binary    │
   │                              ▼                                               │
   │              EVIDENCE FUSION → CONFIDENCE (computed, not literal)            │
   └──────────────────────────────┬───────────────────────────────────────────────┘
                                  ▼
                    CRYPTO NORMALIZATION (canonical algorithm registry)
                                  ▼
                    CBOM ENGINE  ──► CycloneDX 1.6 (conformant)
                                  ▼
        QUANTUM RISK ENGINE (algorithm · lifetime · criticality · exposure)
                                  ▼
        MOSCA ENGINE:  X = Y + Z    (configurable horizon, fully explainable)
                                  ▼
        PQC RECOMMENDATION ENGINE (contextual: usage · exposure · lifetime · perf)
                                  ▼
        MIGRATION ROADMAP (derived only — never fabricated)
                                  ▼
   Analyst UI · Developer UI · Executive UI · PDF/JSON/CSV/CBOM · CLI · CI/CD
```

### Key design decisions

**1. Keep `shared/engine` as the source of truth.** It already delivers agent/server parity. Formalise it as a versioned workspace package (`@qrypto/engine`) so the CLI and agent can consume it too.

**2. Make the agent a first-class deployable.** The in-browser scan mode already proves local analysis works. Package the same engine as a CLI/container that emits CBOM + findings and pushes only results upstream. For NTRO this is the differentiator: *your source never leaves your network*, provable because the agent is auditable and the wire format contains no source.

**3. Confidence must be computed, not declared.** Replace literals with evidence fusion:

```
confidence = base(pattern_specificity)
           + 0.10 if AST confirms a call expression (not comment/string)
           + 0.10 if a corroborating dependency is present
           + 0.05 if key size was extracted
           − 0.30 if in comment or string literal
           − 0.20 if path matches test/vendor/fixture/node_modules
```

This makes the 0.70 threshold meaningful and gives the evidence panel something real to show.

**4. Separate algorithm severity from contextual risk.** Two independent axes, never collapsed:

- `algorithmSeverity` — a property of the primitive alone. ML-KEM is *always* `info`.
- `contextualRisk` 0–100 — how much this instance matters here.

This single change fixes the ML-KEM-flagged-as-high bug and makes the model explainable.

**5. Fingerprint every finding** so triage survives rescans:

```
fingerprint = sha256(repo + normalized_path + algorithm + usage + normalized_code_context)
```

Deliberately excludes line numbers, so inserting a line above doesn't resurrect a suppressed finding. Add a unique index and upsert on it — that also unlocks First Seen / Last Seen and "new since last scan".

**6. Normalize algorithms through a registry** keyed by canonical name + variant + mode + key size, carrying NIST status, quantum vulnerability, and CycloneDX primitive/OID mappings. This is what makes CycloneDX output conformant rather than hand-mapped per call site.

---

## PART D — Priority roadmap

### P0 — must have

| ID | Item | Why |
|---|---|---|
| **P0-0a** | Rotate the OpenRouter key; restore `.gitignore`; proxy LLM via backend | Live credential exposed |
| **P0-0b** | `git checkout -- .` to restore the 18 zeroed files; `core.autocrlf true` | Project cannot build |
| **P0-0c** | Fix register role injection; enforce `requireRole`; fail-fast on missing `JWT_SECRET`; rate-limit `/login` + `/register` | Critical privilege escalation |
| **P0-1** | **Delete every fabricated number** (§A.10) — remove `RiskPulse`, wire Dashboard rings to real data, drop invented deltas/LOC/penalties | Single largest credibility risk |
| **P0-2** | **Split algorithm severity from contextual risk** | Fixes PQC-flagged-as-high |
| **P0-3** | **Mosca engine** — X = Y + Z, configurable horizon, explainable derivation panel | Explicit requirement, absent |
| **P0-4** | **Computed confidence** from evidence fusion | Makes threshold real |
| **P0-5** | **Conformant CycloneDX 1.6 CBOM** + algorithm registry; wire to UI in both modes | Core deliverable |
| **P0-6** | **PDF reports** (executive / technical / developer) | Required; none exist |
| **P0-7** | Revive AST layer — add deps, run server-side, extract call args | "Multi-layer" claim must be true |
| **P0-8** | Finding fingerprints + upsert; First/Last Seen; suppression survives rescan | Enterprise minimum |
| **P0-9** | Derive migration roadmap from findings only — delete hardcoded tasks, owners, statuses | Currently ships fake "done" work |
| **P0-10** | Add `mode`, `library`, `libraryVersion`, `protocol`, `variant` to the model | Classification requirement |
| **P0-11** | Wire frontend auth: render `LoginModal`, gate the app, role-gate UI | Auth is dead code |
| **P0-12** | Per-asset context override UI (criticality, exposure, lifetime) | Removes reliance on filename guesses |

### P1 — high value

| ID | Item |
|---|---|
| P1-1 | Real X.509 parsing — issuer, subject, validity, chain, weak-signature detection |
| P1-2 | `qrypto` CLI wrapping the same engine (`scan`, `report`, `--fail-on`) |
| P1-3 | CI/CD action with configurable thresholds and build gating |
| P1-4 | GitHub/GitLab repo integration (server-side clone in a sandbox, no shell interpolation) |
| P1-5 | Container image scanning (layer walk + dependency manifests) |
| P1-6 | Binary scanning (ELF/PE symbol + string analysis) |
| P1-7 | Benchmark harness — labelled corpus, measured precision/recall. **Publish only measured numbers** |
| P1-8 | Dockerfile + compose + CI workflow (nothing exists today) |
| P1-9 | Fix dependency graph — populate real edges so AttackMap renders |
| P1-10 | Async/streaming scan: Web Worker in browser, worker pool + streaming reads on server |
| P1-11 | Harden zip: validate real extracted bytes, aggregate size cap, magic-byte check |
| P1-12 | Redis-backed rate limiting; `trust proxy`; throttle auth endpoints |
| P1-13 | Package + document the on-prem agent (the government story) |
| P1-14 | Add react-router for deep links and shareable reports |
| P1-15 | Component tests; security tests for authz, upload limits, token handling |

### P2 — future

Cloud scanning (AWS/Azure/GCP KMS) · Kubernetes/HSM discovery · SIEM export · Jira/ServiceNow · full multi-tenancy with an org model · continuous monitoring and drift alerts · SSO/MFA.

---

## PART E — Implementation sequence

**Phase 0 — Stabilise (day 1, blocking, do in this order)**
Rotate key → restore `.gitignore` → `git checkout -- .` → `core.autocrlf true` → verify `npm install && npm run build && npm test` → patch the auth vuln → commit. *Nothing else starts until the build is green.*

**Phase 1 — Truth (days 2–4)**
Strip fabricated numbers (P0-1). Split severity from contextual risk (P0-2). Computed confidence (P0-4). Derive the roadmap honestly (P0-9). After this phase every number on screen is defensible — and the product is *more* impressive, because the evidence panel finally shows real reasoning.

**Phase 2 — Requirement completion (days 5–10)**
Algorithm registry + normalization → CycloneDX 1.6 (P0-5) → Mosca engine + explainability panel (P0-3) → model fields (P0-10) → contextual PQC recommendations → PDF reports (P0-6).

Order matters: the registry unblocks both CBOM and recommendations; Mosca depends on lifetime and horizon being first-class.

**Phase 3 — Depth (days 11–16)**
Revive AST (P0-7) → fingerprints and rescan continuity (P0-8) → frontend auth and role-gating (P0-11) → context override UI (P0-12) → X.509 parsing (P1-1).

**Phase 4 — Reach (days 17–22)**
CLI (P1-2) → CI/CD action (P1-3) → Docker + CI (P1-8) → benchmark harness (P1-7) → dependency graph edges (P1-9).

**Phase 5 — Demo hardening (final 3 days)**
Rehearse end to end on a repo nobody has pre-seeded. Fix the top three things that break. Freeze the code. Prepare an offline fallback recording in case venue networking fails.

---

## PART F — Team task breakdown

Modules are cut to minimise merge conflicts: each owns distinct directories.

| Track | Owner | Directories | Deliverables |
|---|---|---|---|
| **T1 · Engine core** | Strongest systems dev | `shared/engine/{scanner,detectors,pipeline}` | Registry, computed confidence, AST revival, mode/library/protocol extraction, fingerprints |
| **T2 · Risk & Mosca** | Strongest analytical dev | `shared/engine/{riskEngine,hndlAnalyzer,mosca}` | Severity/risk split, **Mosca engine**, configurable horizon, explainability payload |
| **T3 · CBOM & reporting** | Backend dev | `server/src/routes/reports*`, `shared/cbom/` | Conformant CycloneDX 1.6, PDF/JSON/CSV, report templates |
| **T4 · Platform & security** | Security-minded dev | `server/src/{middleware,routes/auth,services}`, `prisma/` | Auth vuln fix, RBAC enforcement, zip hardening, Redis rate limit, Docker + CI |
| **T5 · Frontend truth & UX** | Strongest UI dev | `src/components/**`, `src/store/**` | Remove fabricated numbers, Mosca panel, evidence panel, context overrides, auth wiring, three dashboard personas |
| **T6 · CLI, CI & benchmark** | Any dev, later phases | `packages/cli/`, `.github/`, `benchmark/` | `qrypto` CLI, CI action, labelled corpus, measured precision/recall |

**Contract-first coordination.** T2 and T5 both need the Mosca payload; T1 and T3 both need the registry. Agree these two TypeScript interfaces in `shared/types/` on day 2 and commit them before implementation — then all six tracks build against stable contracts in parallel.

**Sequencing constraints:** T1's registry lands before T3's CBOM. T2's severity split lands before T5 rewires the dashboard. T4's Phase-0 fix precedes everything.

---

## PART G — Risks

### Architectural

| Risk | Impact | Mitigation |
|---|---|---|
| Regex-only detection hits an accuracy ceiling | False positives erode trust | Revive AST (P0-7); computed confidence; publish measured precision |
| Context inputs from filename substrings | Wrong risk on real repos | Context override UI; treat inferred values as *defaults*, labelled as such |
| Browser and backend disagree (`scan.worker.ts:86`) | Same repo, two scores | Remove the override; add a parity test asserting identical output |
| No router | No deep links or shareable reports | Add react-router (P1-14) |
| Synchronous pipeline | Browser freezes; worker concurrency 1 | Web Worker + server worker pool (P1-10) |

### Security

| Risk | Impact | Mitigation |
|---|---|---|
| Register role injection + unused RBAC | **Full cross-account read** | P0-0c, day 1 |
| Fallback JWT secret in a public repo | Forgeable tokens | Fail-fast on missing secret |
| `VITE_`-prefixed LLM key | Any visitor can spend the account | Backend proxy; rotate |
| Forgeable zip-bomb headers; no aggregate cap | Disk exhaustion (~5 GB/scan) | Validate extracted bytes, not headers |
| Findings embed source lines | Leak amplifies any authz bug | Store spans + hashes; redact by default; retention policy |
| `dangerouslySetInnerHTML` on LLM output | XSS | Delete `advisor/AIAdvisor.tsx` |

### Product & competition

| Risk | Impact | Mitigation |
|---|---|---|
| **A judge scans their own repo and sees fabricated data** | Credibility collapse | P0-1 before any demo. Highest-severity non-technical risk |
| **PQC flagged as high severity** | Inverts the entire pitch | P0-2 |
| Roadmap ships tasks pre-marked "done" | Looks fabricated because it is | P0-9 |
| Mosca absent while the PS names it | Direct requirement miss | P0-3 |
| "CBOM tool" that emits CSV named `*-cbom.csv` | Deliverable miss on inspection | P0-5 |
| Quantum dates presented as fact | Cryptographers will object | Configurable horizon; always show it as an assumption with a source |
| Scope sprawl into integrations | Core stays weak | Hold the P0 line; no P2 work before Phase 4 |

### Performance

Quadratic newline counting (`scanner.ts:134`), `readFileSync` in the worker, whole-corpus duplication in `pipeline.ts:118-129`, no scan timeout or findings cap, and an unbounded rate-limiter Map. All are P1-10/P1-11 and all are straightforward.

---

## PART H — SIH demo strategy

### What actually wins here

The judging panel is NTRO. They will not be impressed by a 3D quantum animation; they will be impressed by **explainability and honesty**. The strongest possible demo moment is not a dashboard — it is clicking a finding and seeing exactly *why* Qrypto concluded what it did, with a real file, a real line, real evidence, and a risk derivation that adds up on screen.

Counter-intuitively, **removing the fake numbers makes the demo stronger.** Right now the interesting screens are static, so a judge who scans their own repository sees a beautiful dashboard that doesn't respond to their data. After P0-1 and P0-2, every number moves when their input moves. That is the difference between a mockup and a tool.

### The eight-minute run

1. **Frame it (30 s).** Five questions: what crypto do we have, where, how exposed are we, what replaces it, how do we migrate.
2. **Scan live (60 s).** Judge's own ZIP, or the enterprise sample. Show the pipeline log — file counts, per-layer progress. *Real work, visibly happening.*
3. **Inventory (45 s).** N cryptographic assets classified by algorithm, mode, library, usage, exposure. This is the CBOM.
4. **Drill into one critical finding (90 s) — the centrepiece.** RSA-2048, `src/security/auth.py:142`, matched code, detection layers that fired, and the confidence derivation as an itemised sum. Then the risk breakdown showing all six factors and their weights. *Nothing here is a magic number.*
5. **Mosca (90 s) — the requirement nobody else will implement properly.** Data lifetime 12y + migration time 3y = 15y protection horizon vs a **configurable** threat horizon. State plainly that the horizon is an assumption, show the slider, and show the priority reorder as it moves. Saying "this is an assumption, and here is the control for it" reads as expertise, not weakness.
6. **Recommendation (45 s).** RSA-2048 → ML-DSA-65, with the reasoning: signature usage, internet-facing, long-lived data. Then the hybrid path and its trade-off.
7. **Roadmap + export (60 s).** Four phases derived from actual findings. Export **CycloneDX CBOM** and open the JSON — naming the standard matters. Then the executive PDF.
8. **Close on deployment (45 s).** Disconnect the network and rerun the scan in-browser. *"Your source code never left this laptop — this is how it deploys inside a government network."* Then show the CLI and the CI gate blocking a build.

### Three highest-impact investments

1. **The evidence + confidence derivation panel.** Directly answers "why should I believe you" — the first question any security professional asks.
2. **The Mosca panel with a configurable horizon.** The requirement most teams will hand-wave. Doing it explainably is the clearest signal of genuine understanding.
3. **The offline / on-prem demonstration.** Unlocks the NTRO conversation entirely. It also happens to be nearly free — the in-browser mode already works.

### Deliberately de-emphasise

The quantum cursor, the 3D landing scene, and the Q-Day slider are impressive engineering but cost credibility if a judge probes the numbers behind them. Keep them as ambient polish; never make them a demo beat. Either ground the Q-Day simulator in the Mosca model or cut it from the run.

### Claim discipline

Say: 71 detection patterns across 8 file types; regex plus AST plus dependency analysis (*once P0-7 lands*); CycloneDX 1.6 CBOM; measured precision and recall on a published corpus (*once P1-7 is measured*).

Do not say: AST-based semantic analysis (until true), any accuracy figure that hasn't been measured, a specific Q-Day year as fact, or "source code never leaves your browser" while metadata goes to a third-party LLM.

---

## Closing assessment

There is a real product here. The `shared/engine` single-source-of-truth design, the honest deterministic core with AI confined to explanation, the persisted triage with an audit table, the zip handling with cleanup on both paths, and the absence of any shell execution on untrusted input are all decisions I'd expect from an experienced team. That foundation is worth protecting — the right move is emphatically not a rewrite.

What holds it back is a gap between what the engine computes and what the UI claims. The engine is more honest than the interface. Roughly 60% of the P0 list is *deletion and rewiring* rather than new construction: remove the fabricated numbers, stop overwriting severity, connect the components that already exist. That work is fast, and it converts a demo into a tool.

The two genuine build items — Mosca and conformant CycloneDX CBOM — are both explicitly named in the problem statement, both absent, and both achievable within a phase. Delivering those two well, on top of an evidence panel that shows real reasoning, addresses the problem statement more completely than most competing entries will.

Priority order, unambiguously: **rotate the key, restore the build, close the auth hole, delete the fabricated numbers, stop flagging PQC as high severity, then build Mosca and CBOM.**
