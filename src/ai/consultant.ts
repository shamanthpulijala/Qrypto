// ============================================================
// QuantumGuard AI — Gemini AI Consultant
// Grounded in actual scan findings — cannot invent results
// ============================================================

import { GoogleGenerativeAI } from '@google/generative-ai';
import type { Finding, Assessment } from '../types';
import { PQC_ALGORITHMS, ALGORITHM_RISK_TABLE } from '../data/pqcKnowledge';

function buildSystemPrompt(assessment: Assessment): string {
  const findings = assessment.findings;
  const criticalFindings = findings.filter(f => f.severity === 'critical').slice(0, 10);
  const highFindings = findings.filter(f => f.severity === 'high').slice(0, 10);
  const vulnerableFindings = findings.filter(f => f.quantumStatus === 'vulnerable').slice(0, 15);

  const findingSummary = [...criticalFindings, ...highFindings]
    .slice(0, 15)
    .map(f => `  [${f.id}] ${f.algorithm} in ${f.file}:${f.line} (Service: ${f.service}, Risk: ${f.riskScore}/100, Status: ${f.remediationStatus})`)
    .join('\n');

  const serviceSummary = assessment.services
    .filter(s => s.id !== 'internet')
    .map(s => `  ${s.name}: Risk ${s.riskScore}/100, Internet-facing: ${s.internetFacing}`)
    .join('\n');

  const algoCounts: Record<string, number> = {};
  findings.forEach(f => { algoCounts[f.algorithm] = (algoCounts[f.algorithm] || 0) + 1; });

  const pqcContext = PQC_ALGORITHMS.map(a =>
    `${a.name} (${a.nistId}): ${a.category} — ${a.description}`
  ).join('\n');

  return `You are the QuantumGuard AI Security Consultant — a specialized AI assistant for quantum cryptography risk assessment.

ASSESSMENT CONTEXT:
Organization: ${assessment.organization}
Industry: ${assessment.industry}
Total Findings: ${findings.length}
Critical: ${assessment.scanStats.criticalCount}
High: ${assessment.scanStats.highCount}
Quantum-Vulnerable: ${assessment.scanStats.vulnerableAlgorithms}
Hardcoded Secrets: ${assessment.scanStats.secretsFound}
Quantum Readiness Score: ${assessment.quantumReadinessScore}/100

KEY FINDINGS (top by risk):
${findingSummary || '  No critical findings detected.'}

SERVICES:
${serviceSummary}

ALGORITHM DISTRIBUTION:
${Object.entries(algoCounts).map(([alg, count]) => `  ${alg}: ${count} occurrence${count > 1 ? 's' : ''}`).join('\n')}

PQC KNOWLEDGE BASE:
${pqcContext}

CRITICAL RULES YOU MUST FOLLOW:
1. You MUST ground all answers in the actual scan findings above. Never invent findings not in the dataset.
2. When citing findings, use the exact finding ID (e.g., [QG-0001]).
3. Use technically accurate language about quantum computing threats.
4. Do NOT claim quantum computers can currently break RSA — this is future-oriented risk assessment.
5. Do NOT claim PQC is mathematically proven unbreakable.
6. Do NOT claim AES is completely unaffected by quantum computing (Grover's algorithm applies, but doubles required key length).
7. Use terms like "quantum-vulnerable", "HNDL risk", "migration priority" — not "quantum-broken" or "quantum-safe".
8. When asked about specific algorithms, explain the ACTUAL risk vs classical vs quantum scenarios.
9. Always provide actionable recommendations citing specific NIST-standardized PQC algorithms (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205).
10. When explaining to executives, simplify without oversimplifying — use analogies but don't mislead.
11. Cite finding IDs when referencing specific issues.
12. Distinguish between "fix now" (classical weak) vs "plan migration" (quantum-vulnerable) priorities.

Be concise, authoritative, and technically accurate. Format responses with clear structure.`;
}

export async function askConsultant(
  question: string,
  assessment: Assessment,
  apiKey: string,
  chatHistory: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = []
): Promise<{ answer: string; citedFindings: string[] }> {
  if (!apiKey) {
    return {
      answer: 'Please configure your Gemini API key in Settings to use the AI Consultant.',
      citedFindings: [],
    };
  }

  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({
    model: 'gemini-2.0-flash',
    systemInstruction: buildSystemPrompt(assessment),
  });

  const chat = model.startChat({
    history: chatHistory,
  });

  try {
    const result = await chat.sendMessage(question);
    const answer = result.response.text();

    // Extract cited finding IDs
    const citedFindings: string[] = [];
    const idMatches = answer.match(/\[QG-\d{4}\]/g) || [];
    idMatches.forEach(match => {
      const id = match.replace(/[\[\]]/g, '');
      if (!citedFindings.includes(id)) citedFindings.push(id);
    });

    return { answer, citedFindings };
  } catch (error: any) {
    return {
      answer: `AI Consultant error: ${error.message || 'Unknown error'}. Please check your API key.`,
      citedFindings: [],
    };
  }
}

// Suggested questions for the UI
export const SUGGESTED_QUESTIONS = [
  'Which service should we migrate first and why?',
  'Explain our biggest quantum risk to a non-technical executive.',
  'Where are we using RSA and what should we replace it with?',
  'What is a "harvest now, decrypt later" attack and which of our systems are at risk?',
  'What is our recommended migration strategy for the Payment Service?',
  'Which of our findings are classical security problems (not quantum-related)?',
  'Explain ML-KEM and when we should use it vs ML-DSA.',
  'What should we fix in the next 30 days?',
  'How does our quantum readiness score compare to industry standards?',
  'What is crypto agility and why does it matter for us?',
];
