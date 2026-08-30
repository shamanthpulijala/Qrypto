# Qrypto — Judge Demonstration Path (Section 56)
## 3–5 Minute Deterministic Demo | SIH 2026 Problem Statement 26164

> **Prerequisite**: This demo uses the provided benchmark corpus — NO sample/demo data is pre-loaded.
> The demo is reproducible: same input → same findings every time.

---

## Demo Setup

1. Ensure the Qrypto dev server is running: `npm run dev`
2. Open browser to `http://localhost:5173`
3. Have the `benchmark/corpus/` folder ready, OR use `qrypto-enterprise-sample.zip`
4. No API key required — AI Advisor works in offline (deterministic fallback) mode

---

## Step-by-Step Demo Flow

### Step 1 — Open Qrypto (0:00)
- Browser opens to the landing page
- Review the hero section and "Discover → Assess → Migrate" pipeline
- Click **Launch Dashboard**

### Step 2 — Show Available Scanners (0:20)
- Navigate to **Scan** in the sidebar
- Show the scanner selection UI with all categories:
  - Regex Scanner, AST Scanner, Secrets, Dependencies, HSM/PKCS#11, Cloud KMS, Container, Binary, Certificate
- **Explain**: "These are all deterministic — no AI hallucination in the detection pipeline"

### Step 3 — Choose Local Folder (0:45)
- Click **Choose Folder**
- Select `benchmark/corpus/` (or drag-and-drop `qrypto-enterprise-sample.zip`)
- **Show**: File list populated — Python, Java, JavaScript, TypeScript, Go files

### Step 4 — Select Combined Enterprise Scan (1:00)
- Select **Combined Scan** mode (all detectors enabled)
- Set repository name: `enterprise-demo`
- **Explain**: "Confidence threshold is 0.70 — anything below is filtered out"

### Step 5 — Start Scan & Show Progress (1:10)
- Click **Start Scan**
- Watch the pipeline progress bar:
  - Validate → Extract → Detect Language → Parse → Run Detectors → Deduplicate → Confidence → Risk Engine → Complete
- **Point out**: "54 raw findings collapsed to 40 after deduplication"

### Step 6 — Show Summary Dashboard (1:40)
- Scan completes — Summary cards appear:
  - `40 findings`, `Readiness: 35/100`, `6 Critical`, `20 High`, `25 Mosca at-risk`
- Navigate to **Dashboard** tab
- Show the risk distribution donut chart and top finding types

### Step 7 — Open a Critical Finding (2:00)
- Navigate to **Findings**
- Sort by Risk Score (descending)
- Click on **[CRITICAL] MD5 (hash)** from `js_crypto.js`

### Step 8 — Show Evidence (2:10)
- Finding detail modal opens
- Show:
  - **Evidence**: `crypto.createHash('md5'...)`
  - **File**: `js_crypto.js:28`
  - **Detection Layer**: `regex`
  - **Confidence**: `98%`
  - **Confidence Derivation**: shown

### Step 9 — Show Algorithm Severity vs Contextual Risk (2:20)
- Point to the two severity indicators:
  - **Algorithm Severity**: `critical` (MD5 is classically broken)
  - **Contextual Risk Score**: `53/100`
  - **Risk Breakdown**: algorithmRisk, dataSensitivity, internetExposure, lifetime
- **Explain**: "Severity is grounded in the algorithm itself, then contextually adjusted"

### Step 10 — Show Quantum Status (2:30)
- Show the **Quantum Status** badge: `classical-weak`
- **Explain**: "MD5 is broken classically first — quantum makes it worse, but it was already unacceptable"

### Step 11 — Show Mosca Analysis (2:40)
- Navigate to **ASSESS → Mosca / HNDL**
- Show the Mosca equation for the RSA finding:
  - `X = 15 years (data lifetime)`, `Y = 3 years (migration time)`, `Z = 8 years (Q-Day estimate)`
  - `X + Y > Z → HARVEST NOW DECRYPT LATER RISK`
- **Emphasize**: "Q-Day is shown as an assumption, not a fact"

### Step 12 — Show PQC Recommendation (2:55)
- Navigate to **MIGRATE → PQC Recommendations**
- Show the recommendation for the RSA finding:
  - `ML-KEM-768 (FIPS 203)` for key establishment
  - `ML-DSA-65 (FIPS 204)` for digital signatures
- **Explain**: "Usage-aware — we recommend different algorithms for encryption vs signing"

### Step 13 — Show Migration Task (3:10)
- Navigate to **MIGRATE → Migration Roadmap**
- Show auto-generated migration tasks with:
  - Priority, Effort estimate, Recommendation
- Click on a task to see the remediation guidance

### Step 14 — Show CBOM (3:20)
- Navigate to **REPORT → CBOM**
- Show the CycloneDX 1.6 JSON structured output
- **Click Export CBOM** — downloads `qrypto-cbom.json`
- Open the file briefly to show `bomFormat: "CycloneDX"`, `specVersion: "1.6"`, `type: "cryptographic-asset"`

### Step 15 — Ask AI Advisor (3:30)
- Navigate to **ASSESS → AI Advisor**
- Type: *"What is our highest quantum risk finding and how should we prioritize migration?"*
- Response appears (deterministic fallback if no API key)
- **Explain**: "AI is an explanation layer only. It does NOT invent findings — those came from the deterministic engine"

### Step 16 — Show Safe AI Recommendation (3:45)
- Point to the AI disclaimer: *"AI recommendations should be verified by a security engineer before implementation"*
- The AI cites specific finding IDs from the scan — never fabricates new ones

### Step 17 — Export Report (3:55)
- Navigate to **REPORT → Executive Report**
- Click **Download PDF**
- Show the generated PDF with:
  - Organization summary
  - Risk dashboard
  - Top findings
  - PQC migration roadmap

---

## Expected Scan Results (Reproducible)

| Metric | Value |
|--------|-------|
| Files scanned | 5 |
| Lines scanned | ~249 |
| Raw findings | ~76 |
| After deduplication | ~40 |
| Critical | 6 |
| High | 20 |
| Readiness Score | 35/100 |
| Mosca at-risk | 25 |
| Scan time | ~3-5 seconds |

---

## CLI Demo (Optional, 30 seconds extra)

```bash
# Show CLI capabilities
node packages/cli/dist/packages/cli/src/index.js --help

# Real scan
node packages/cli/dist/packages/cli/src/index.js scan benchmark/corpus --verbose

# CBOM output
node packages/cli/dist/packages/cli/src/index.js scan benchmark/corpus --cbom

# CI/CD integration with fail-on
node packages/cli/dist/packages/cli/src/index.js scan benchmark/corpus --fail-on critical
echo "Exit code: $LASTEXITCODE"  # 2 = policy violation
```
