# ⚛️ Qrypto

### See What Breaks Before Quantum Does.

**Qrypto** is an interactive **Post-Quantum Cryptography (PQC) readiness and migration intelligence platform** that helps organizations discover, understand, prioritize, simulate, and reduce their exposure to quantum-vulnerable cryptography.

Instead of simply reporting:

> `RSA-2048 detected`

Qrypto answers the questions that actually matter:

> **Where is cryptography being used?**
> **Which systems are most exposed?**
> **What happens if cryptographically relevant quantum computing becomes available?**
> **Which systems should be migrated first?**
> **How can teams move toward post-quantum cryptography safely?**

---

## 🚀 Why Qrypto?

Post-quantum migration is not simply an algorithm replacement problem.

Modern applications can contain cryptography across:

* APIs
* authentication systems
* certificates
* TLS configurations
* source code
* dependencies
* data stores
* archives
* configuration files
* hard-coded secrets
* legacy applications

The difficult part is building visibility across that entire footprint and turning technical findings into **prioritized engineering decisions**.

Qrypto turns that problem into a continuous workflow:

```text
DISCOVER
    ↓
Build a cryptographic inventory
    ↓
EVALUATE
    ↓
Prioritize quantum + business risk
    ↓
SIMULATE
    ↓
Model Q-Day impact on infrastructure
    ↓
REDUCE
    ↓
Generate migration strategies
    ↓
MONITOR
    ↓
Track readiness and migration progress
```

---

# ✨ What Qrypto Does

Qrypto combines a deterministic cryptographic analysis engine with risk modeling, infrastructure visualization, migration intelligence, and AI-assisted explanations.

The goal is not to replace security scanners.

The goal is to answer:

> **What cryptography do we have, where does it matter, what happens if it becomes vulnerable, and what should we do next?**

---

# 🔍 1. Cryptographic Discovery Engine

Qrypto scans source code and configuration files to identify cryptographic usage and security-relevant patterns.

The current detection system uses **deterministic, modular pattern-based detectors** rather than relying on an LLM to guess whether a cryptographic primitive exists.

Detected categories include:

* RSA
* ECC
* ECDH
* ECDSA
* DH / DSA
* AES
* SHA-1
* SHA-256
* MD5
* TLS versions
* certificates
* hard-coded keys
* API secrets
* JWT secrets
* SSH keys
* PQC-related algorithms and patterns

### Supported source/configuration formats

Qrypto currently analyzes multiple common programming and configuration formats, including:

```text
Python
Java
JavaScript
TypeScript
Go
YAML
JSON
XML
```

The detector architecture is modular, allowing additional cryptographic patterns to be added independently.

---

# 🧠 2. Quantum Risk Engine

Finding RSA or ECC is only the beginning.

Qrypto evaluates the context surrounding each cryptographic asset.

The risk model considers factors such as:

```text
Quantum Vulnerability
        +
Data Sensitivity
        +
Internet Exposure
        +
Confidentiality Lifetime
        +
Business Criticality
        +
Migration Difficulty
        +
Dependency Depth
```

The result is a transparent:

## Qrypto Risk Score

The score is designed to help teams prioritize remediation rather than simply produce a list of findings.

> **Important:** Qrypto's scoring system is an application-specific contextual risk model. It is not an official NIST scoring formula.

---

# 🕸️ 3. Cryptographic Digital Twin

Traditional security reports flatten infrastructure into tables.

Qrypto turns it into a **living cryptographic dependency graph**.

Example:

```text
                         INTERNET
                             │
                             ▼
                       API GATEWAY
                       /         \
                      /           \
                 AUTH              PAYMENT
                  │                   │
                  ▼                   ▼
                 RSA                 ECDH
                  │                   │
                  └─────────┬─────────┘
                            ▼
                        DATABASE
```

The Digital Twin can represent relationships between:

* applications
* services
* APIs
* cryptographic algorithms
* certificates
* data stores
* dependencies
* exposure paths
* migration states

This allows security teams to move from:

> **"RSA exists."**

to:

> **"RSA exists in a critical, internet-facing payment dependency connected to sensitive customer data."**

---

# ⚡ 4. Q-Day Simulator

## What happens if quantum capability becomes reality?

Qrypto includes a scenario-based Q-Day simulation that transforms the organization's cryptographic dependency graph.

The same infrastructure is evaluated under a simulated quantum-threat state.

```text
NORMAL STATE
     ↓
QUANTUM SIMULATION
     ↓
AFFECTED ASSETS
     ↓
DEPENDENCY IMPACT
     ↓
PRIORITIZED RESPONSE
```

The simulation highlights:

* quantum-vulnerable algorithms
* affected applications
* dependency chains
* critical business systems
* long-lived sensitive data
* attack paths
* readiness degradation

Example:

```text
Quantum Readiness

74 / 100
     ↓
Q-Day Simulation
     ↓
18 / 100
```

> The Q-Day environment is a scenario model for security planning. It is not a prediction of when quantum computers will become capable of breaking specific cryptographic systems.

---

# ⏳ 5. Harvest Now, Decrypt Later

Qrypto models the **Harvest Now, Decrypt Later (HNDL)** threat.

The concept is straightforward:

```text
Encrypted Data Today
        ↓
Collected by an Attacker
        ↓
Stored for Years
        ↓
Future Decryption Capability
        ↓
Historical Data Exposure
```

This matters for information with long confidentiality requirements, including:

* financial records
* healthcare information
* government data
* intellectual property
* customer information
* long-term archives

Qrypto allows teams to reason about:

> **How long does this information need to remain confidential?**

That helps identify data that may need migration earlier than other systems.

---

# 🧬 6. Quantum Time Machine

Qrypto provides a scenario-based timeline for exploring how cryptographic risk could evolve.

```text
2026 ─── 2027 ─── 2029 ─── 2032 ─── 2035
```

Users can compare:

```text
WITHOUT MIGRATION
        VS
WITH MIGRATION
```

The model demonstrates how proactive migration can change the organization's simulated risk profile over time.

> The timeline is a planning scenario, not a prediction of the exact date quantum computers will break current cryptography.

---

# 🛡️ 7. Post-Quantum Migration Intelligence

Qrypto does not stop after identifying a finding.

It connects findings to migration guidance.

Examples include:

| Current Technology    | Example Migration Direction       |
| --------------------- | --------------------------------- |
| RSA key establishment | Hybrid / ML-KEM strategy          |
| ECDH                  | Hybrid / ML-KEM strategy          |
| RSA signatures        | ML-DSA migration strategy         |
| ECDSA                 | ML-DSA migration strategy         |
| SHA-1                 | SHA-256 / SHA-3 where appropriate |
| TLS 1.0 / 1.1         | TLS 1.3                           |
| Hard-coded secrets    | Managed secret storage            |

Migration recommendations are intended to be **context-aware**, rather than treating every finding as equally urgent.

---

# 🤖 8. Quantum Intelligence

Qrypto includes an AI-assisted reasoning layer that turns technical findings into understandable security decisions.

Instead of asking a generic chatbot:

> "What is RSA?"

a user can ask:

> "Which system should we migrate first?"

Qrypto can use the current assessment context to explain:

```text
PAYMENT API

Risk Score: 94 / 100
Priority: CRITICAL

Why:

• Internet-facing
• RSA-2048 detected
• Handles customer PII
• Long confidentiality requirement
• High business criticality

Recommended strategy:

Hybrid ML-KEM migration

Estimated effort:

Medium
```

### Important architecture principle

The AI is **not the source of truth for cryptographic detection**.

The flow is:

```text
Deterministic Detection
        ↓
Evidence
        ↓
Risk Engine
        ↓
Assessment Context
        ↓
AI Explanation / Recommendation
```

The application also supports deterministic fallback guidance when the external AI service is unavailable.

---

# 💻 9. AI-Assisted Migration

Qrypto can turn a cryptographic finding into developer-oriented migration guidance.

Example source:

```java
KeyPairGenerator.getInstance("RSA");
```

The migration assistant can provide:

* migration strategy
* recommended direction
* compatibility considerations
* security rationale
* testing requirements
* implementation guidance

The goal is to connect:

```text
Security Finding
       ↓
Engineering Decision
       ↓
Implementation Guidance
```

rather than leaving developers with a vulnerability report they must interpret themselves.

---

# 🔄 10. Crypto-Agility Engine

Post-quantum readiness is not only about selecting new algorithms.

Organizations also need systems that can **change cryptography without major rewrites**.

Qrypto therefore analyzes crypto-agility characteristics.

### High agility

```text
Abstracted
    ↓
Configurable
    ↓
Replaceable
    ↓
Testable
```

### Low agility

```text
Hard-coded
    ↓
Tightly coupled
    ↓
Difficult to replace
    ↓
Migration bottleneck
```

The resulting **Crypto-Agility Score** helps identify systems that could become difficult to migrate later.

---

# 📊 11. The Qrypto Command Center

The dashboard is intentionally designed differently from a traditional SaaS dashboard.

Instead of:

```text
KPI Card
KPI Card
KPI Card
Chart
Chart
Table
```

Qrypto treats the dashboard as a:

# Living Cryptographic Command Center

The **Cryptographic Digital Twin** is the central visual element.

Supporting intelligence appears around it contextually.

### Core views

* Quantum Readiness
* Cryptographic Digital Twin
* Risk Constellation
* Crypto Inventory
* Q-Day Simulation
* Attack Paths
* Migration Map
* Crypto-Agility
* Quantum Intelligence
* Reports

---

# 🎨 12. Interactive Product Experience

Qrypto is designed to feel like an interactive technology product rather than a static security dashboard.

## Cursor-Reactive Quantum Field

The interface reacts to pointer movement through:

* quantum particles
* energy fields
* node interactions
* connection highlights
* parallax
* lighting
* data particles

The cursor behaves like a field interacting with the environment.

---

## Living Infrastructure

Nodes can respond to interaction.

Hovering over a cryptographic asset can reveal:

* algorithm
* risk
* exposure
* dependencies
* migration state

Selecting a node focuses its surrounding dependency graph.

---

## State-Based Visualization

The same infrastructure can move through different states:

```text
NORMAL
   ↓
AT RISK
   ↓
Q-DAY
   ↓
MIGRATION
   ↓
QUANTUM-READY
```

The goal is to make security posture **visually understandable**, not simply measurable.

---

# 🏗️ Architecture

Qrypto's current architecture is primarily a client-side React application with a deterministic analysis pipeline.

```text
                         ┌─────────────────────┐
                         │ Repository / Files  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Scan Pipeline       │
                         │                     │
                         │ Validate            │
                         │ Extract             │
                         │ Detect              │
                         │ Normalize           │
                         │ Deduplicate         │
                         │ Confidence Filter   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Crypto Detectors    │
                         │                     │
                         │ RSA / ECC / ECDH    │
                         │ Hashes              │
                         │ TLS                 │
                         │ Secrets             │
                         │ Certificates        │
                         │ PQC                 │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Crypto Inventory    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Quantum Risk Engine │
                         └──────────┬──────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  ▼                 ▼                 ▼
               HNDL            Crypto-Agility    Migration Planner
                  │                 │                 │
                  └─────────────────┼─────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ AI Intelligence     │
                         │ Layer               │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Qrypto Experience   │
                         │                     │
                         │ Dashboard           │
                         │ Digital Twin        │
                         │ Q-Day               │
                         │ Attack Map          │
                         │ Migration           │
                         │ Reports             │
                         └─────────────────────┘
```

---

# 🧰 Technology Stack

## Frontend

* React
* TypeScript
* Vite
* Tailwind CSS
* Framer Motion
* GSAP
* Lenis
* Three.js
* React Three Fiber
* React Flow
* Recharts
* Zustand

## Cryptographic Analysis

* deterministic pattern-based detection
* modular crypto detectors
* file and source analysis
* confidence filtering
* normalization and deduplication
* cryptographic risk modeling

## AI

* Google Gemini support
* OpenRouter support
* evidence-grounded contextual reasoning
* migration guidance
* deterministic fallback recommendations

## Visualization

* Three.js / React Three Fiber for the interactive quantum environment
* React Flow for dependency and attack-path visualization
* Recharts for supporting analytical visualizations

---

# 🔬 Example Detection Flow

Input:

```java
MessageDigest.getInstance("SHA-1");
```

Qrypto identifies the cryptographic usage and associates it with its source location.

Example result:

```text
Algorithm
SHA-1

Type
Hash Function

Location
HashService.java:42

Category
Legacy Cryptography
```

The finding can then be enriched with contextual information:

```text
System
Authentication Service

Exposure
High

Business Criticality
High

Migration Difficulty
Low
```

Result:

```text
Priority
HIGH

Recommendation
Consider migration to SHA-256 / SHA-3
where appropriate.
```

The important distinction is:

```text
DETECTION
   ↓
EVIDENCE
   ↓
CONTEXT
   ↓
RISK
   ↓
RECOMMENDATION
```

---

# 🔐 Security & Privacy Principles

Qrypto is designed with security boundaries in mind.

### Current prototype principles

* Repository scanning is performed client-side.
* Uploaded source code is not executed.
* Findings are generated from deterministic analysis.
* Sensitive values should be masked in displayed results.
* File validation and size limits are applied.
* Simulation results are explicitly separated from real-world claims.
* AI is not treated as the underlying cryptographic detection engine.

### Never commit

```text
API keys
Private credentials
Production secrets
Private certificates
Personal data
```

Use local environment configuration for development credentials.

---

# 🧪 Reproducible Demo

The repository includes sample repositories for demonstrating the scanner and product workflow.

Example demo flow:

```text
Sample Repository
       ↓
Upload
       ↓
Scan
       ↓
Cryptographic Inventory
       ↓
Risk Assessment
       ↓
Digital Twin
       ↓
Q-Day Simulation
       ↓
Migration Recommendations
```

The project also includes intentionally vulnerable and PQC-oriented sample environments for testing and demonstrations.

---

# ⚙️ Getting Started

## Prerequisites

* Node.js 18+
* npm
* Git

Clone the repository:

```bash
git clone https://github.com/shamanthpulijala/Qrypto.git
cd Qrypto
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Build the production application:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

Run linting:

```bash
npm run lint
```

---

# 🔑 AI Configuration

Qrypto can operate with deterministic analysis and fallback guidance without requiring an external AI service.

For AI-assisted features, configure the appropriate provider through local environment settings.

Example:

```env
VITE_AI_API_KEY=
```

> Never commit API keys to source control.

The exact provider configuration should follow the environment configuration expected by the current application.

---

# 📁 Project Structure

```text
Qrypto/
│
├── src/
│   ├── ai/
│   │   └── consultant.ts
│   │
│   ├── api/
│   │
│   ├── components/
│   │   ├── landing/
│   │   ├── dashboard/
│   │   ├── cursor/
│   │   ├── attack-map/
│   │   ├── digital-twin/
│   │   └── ...
│   │
│   ├── data/
│   │
│   ├── engine/
│   │   ├── detectors/
│   │   ├── cryptoAgility.ts
│   │   ├── hndlAnalyzer.ts
│   │   ├── migrationPlanner.ts
│   │   ├── pipeline.ts
│   │   ├── riskEngine.ts
│   │   └── scanner.ts
│   │
│   ├── store/
│   │
│   ├── tests/
│   │
│   └── types/
│
├── public/
├── package.json
├── vite.config.ts
└── README.md
```

---

# 🧭 Roadmap

## Current

* [x] Interactive landing experience
* [x] Quantum-computing-inspired visual system
* [x] Cursor-reactive interaction
* [x] Cryptographic discovery engine
* [x] Modular crypto detectors
* [x] Cryptographic inventory
* [x] Quantum Risk Engine
* [x] HNDL analysis
* [x] Crypto-Agility analysis
* [x] Migration planning
* [x] Cryptographic Digital Twin
* [x] Risk visualization
* [x] Q-Day simulation
* [x] Attack-path visualization
* [x] AI consultant with fallback guidance
* [x] Sample repositories
* [x] Client-side scanning workflow

## Next

* [ ] Expanded language and framework coverage
* [ ] Certificate-chain analysis
* [ ] Dependency-aware cryptographic discovery
* [ ] Continuous repository monitoring
* [ ] GitHub integration
* [ ] Pull-request migration workflows
* [ ] Enterprise authentication
* [ ] Multi-project organizations
* [ ] Audit trails
* [ ] Compliance reporting
* [ ] Persistent backend architecture
* [ ] Enterprise-scale CBOM management

---

# 🧠 What Makes Qrypto Different?

Traditional scanners generally answer:

> **"What did we find?"**

Qrypto aims to answer:

> **"What exists, what matters, what could be affected, and what should we do next?"**

The difference is the workflow:

```text
Traditional Scanner

FIND
 ↓
FINDING
 ↓
REPORT
```

versus:

```text
Qrypto

DISCOVER
 ↓
MAP
 ↓
EVALUATE
 ↓
SIMULATE
 ↓
PRIORITIZE
 ↓
MIGRATE
 ↓
MONITOR
```

Qrypto combines:

**Evidence**

*

**Context**

*

**Risk**

*

**Visualization**

*

**Migration Intelligence**

into one workflow.

---

# 🏆 Hackathon Demonstration

The strongest demonstration follows one continuous story.

### 01 — Discover

Upload an intentionally vulnerable sample repository.

Qrypto identifies cryptographic assets.

```text
247
CRYPTOGRAPHIC ASSETS

42
QUANTUM-VULNERABLE

17
CRITICAL
```

### 02 — Understand

Open the:

## Cryptographic Digital Twin

See how cryptographic components connect to applications and sensitive data.

### 03 — Evaluate

Select the highest-priority system.

Example:

```text
PAYMENT API

94 / 100
CRITICAL
```

### 04 — Simulate

Activate:

```text
⚡ Q-DAY
```

The same infrastructure changes state.

Attack paths illuminate.

Risk degrades.

### 05 — Explain

Ask Quantum Intelligence:

> Why is Payment API critical?

The AI explains the evidence and business context.

### 06 — Reduce

Generate a migration strategy.

```text
RSA
 ↓
Hybrid ML-KEM
```

### 07 — Recover

Run the migration scenario.

The infrastructure stabilizes and the simulated readiness improves.

```text
18 → 91
```

The story becomes:

> **We didn't just find quantum risk. We showed where it lives, why it matters, and how to reduce it.**

---

# 🎯 Design Philosophy

Qrypto intentionally has two personalities.

### The Landing Experience

**Cinematic**

**Interactive**

**Editorial**

**Quantum**

**Futuristic**

### The Product Experience

**Precise**

**Information-rich**

**Professional**

**Action-oriented**

**Enterprise-ready**

The visual system connects both experiences through one concept:

# THE QUANTUM FIELD

The Quantum Field represents:

* cryptographic dependencies
* infrastructure
* data flows
* risk
* migration

Its visual state changes:

```text
NORMAL
cyan + violet

WARNING
amber

CRITICAL
red

MIGRATED
cyan + violet + green
```

---

# 📌 Project Status

**Status:** Active Development · Hackathon Prototype

Qrypto is currently a research-driven prototype exploring how organizations can build visibility into cryptographic usage and prepare for post-quantum migration.

Some enterprise integrations and automated remediation workflows remain part of the roadmap.

The current prototype focuses on demonstrating the complete journey:

```text
DISCOVER
    ↓
UNDERSTAND
    ↓
PRIORITIZE
    ↓
SIMULATE
    ↓
MIGRATE
```

---

# ⚠️ Disclaimer

Qrypto is an educational and research-oriented prototype.

Its risk scores, future timelines, and Q-Day simulations are scenario models intended to support security planning. They should not be interpreted as guarantees about future quantum computing capabilities or timelines.

Cryptographic migration decisions should be validated against current standards, organizational requirements, implementation constraints, and expert security review.

---

# 👥 Team

Built by:

**[Your Team Name]**

| Role                            | Contributor |
| ------------------------------- | ----------- |
| Product & Architecture          | [Name]      |
| Frontend & Creative Engineering | [Name]      |
| Security & Cryptography         | [Name]      |
| AI & Intelligence               | [Name]      |

---

# 📄 License

Add your chosen project license here.

For example:

```text
MIT License
```

if the repository is intended to be open source under MIT.

---

# ⭐ The Vision

The post-quantum transition is not simply:

```text
RSA → ML-KEM
```

It is an infrastructure transformation.

Organizations first need to know:

> **What cryptography do we actually have?**

Then:

> **What matters most?**

Then:

> **What happens if it becomes vulnerable?**

And finally:

> **What should we migrate first?**

Qrypto is built around that journey.

# **See what breaks before quantum does.**

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
