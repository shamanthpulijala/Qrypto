// ============================================================
// QuantumGuard AI — §18 & §22 AI Security Consultant
//
// Strictly grounded in actual scan findings via §19 Context Builder.
// §20 Rate limiting & §22 Offline Fallback handling.
// Explicitly labels offline fallback: "AI service unavailable. Showing deterministic migration guidance."
// ============================================================

import { GoogleGenerativeAI } from '@google/generative-ai';
import type { Assessment } from '../types';
import { buildAIContext, formatAIContextPrompt } from './contextBuilder';
import { aiRateLimiter } from '../engine/security';
import { getUsageAwareRecommendation } from '../engine/migrationPlanner';

// ─── Offline / Deterministic Guidance Generator (§22) ─────────

export function getDeterministicFallbackGuidance(question: string, assessment: Assessment): {
  answer: string;
  citedFindings: string[];
} {
  const qLower = question.toLowerCase();
  const findings = assessment.findings;
  const criticals = findings.filter(f => f.severity === 'critical');
  const vulnerables = findings.filter(f => f.quantumStatus === 'vulnerable');
  const secrets = findings.filter(f => f.category === 'secret');

  let answer = `> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n`;
  const citedFindings: string[] = [];

  if (qLower.includes('fix first') || qLower.includes('migrate first') || qLower.includes('priority')) {
    answer += `### Priority Migration Sequence\n\nBased on deterministic risk analysis of **${assessment.organization}**:\n\n`;

    // 1. Secrets
    if (secrets.length > 0) {
      const topSecret = secrets[0];
      citedFindings.push(topSecret.id);
      answer += `1. **Remove Hardcoded Credentials** [${topSecret.id}]\n`;
      answer += `   - **Detected**: ${topSecret.algorithm} in \`${topSecret.file}:${topSecret.line}\`\n`;
      answer += `   - **Action**: Rotate immediately and adopt HashiCorp Vault / AWS Secrets Manager.\n\n`;
    }

    // 2. Internet-facing quantum-vulnerable (Payment Service)
    const paymentVulns = vulnerables.filter(f => f.service.includes('Payment'));
    if (paymentVulns.length > 0) {
      const topPayment = paymentVulns[0];
      citedFindings.push(topPayment.id);
      answer += `2. **NovaBank Payment Service Key Establishment** [${topPayment.id}]\n`;
      answer += `   - **Detected**: ${topPayment.algorithm} (${topPayment.usage}) in \`${topPayment.file}:${topPayment.line}\`\n`;
      answer += `   - **Recommendation**: Evaluate hybrid X25519 + ML-KEM-768 key encapsulation.\n\n`;
    }

    // 3. Authentication
    const authVulns = vulnerables.filter(f => f.service.includes('Auth'));
    if (authVulns.length > 0) {
      const topAuth = authVulns[0];
      citedFindings.push(topAuth.id);
      answer += `3. **Authentication Token Signatures** [${topAuth.id}]\n`;
      answer += `   - **Detected**: ${topAuth.algorithm} in \`${topAuth.file}:${topAuth.line}\`\n`;
      answer += `   - **Recommendation**: Plan transition to ML-DSA-65 (FIPS 204) signatures.\n\n`;
    }

    // 4. Legacy / Certificates
    const certVulns = findings.filter(f => f.service.includes('Certificate') || f.algorithm.includes('SHA1'));
    if (certVulns.length > 0) {
      const topCert = certVulns[0];
      citedFindings.push(topCert.id);
      answer += `4. **Legacy Certificate Infrastructure** [${topCert.id}]\n`;
      answer += `   - **Detected**: ${topCert.algorithm} in \`${topCert.file}:${topCert.line}\`\n`;
      answer += `   - **Recommendation**: Re-issue certificates using SHA-256 and plan ML-DSA certificate authority migration.\n\n`;
    }

  } else if (qLower.includes('rsa') || qLower.includes('replace rsa')) {
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    answer += `### RSA Analysis & PQC Replacement Guidance\n\n`;
    answer += `Found **${rsaFindings.length} RSA instances** across your codebase:\n\n`;
    rsaFindings.slice(0, 3).forEach(f => {
      citedFindings.push(f.id);
      const rec = getUsageAwareRecommendation(f.algorithm, f.usage);
      answer += `- **[${f.id}]** \`${f.file}:${f.line}\` (${f.service}) — Usage: *${f.usage}*\n`;
      answer += `  - **PQC Successor**: **${rec.replacement}**\n`;
      answer += `  - **Strategy**: ${rec.strategy}\n\n`;
    });
    answer += `*Note: RSA key establishment requires ML-KEM (FIPS 203), whereas RSA signatures require ML-DSA (FIPS 204).*`;

  } else if (qLower.includes('hndl') || qLower.includes('harvest')) {
    answer += `### Harvest-Now-Decrypt-Later (HNDL) Risk Assessment\n\n`;
    answer += `HNDL attacks involve adversaries recording encrypted traffic today to decrypt once cryptographically-relevant quantum computers exist.\n\n`;
    answer += `**High HNDL Risk Assets in ${assessment.organization}**:\n`;
    findings.filter(f => f.dataLifetimeYears >= 15).slice(0, 4).forEach(f => {
      citedFindings.push(f.id);
      answer += `- **[${f.id}]** \`${f.file}:${f.line}\` (${f.service}) — Data retention: **${f.dataLifetimeYears} years**\n`;
    });
    answer += `\n**Remediation**: Prioritize hybrid key encapsulation (X25519 + ML-KEM-768) for all internet-facing channels carrying long-lived data.`;

  } else {
    // General fallback summary
    answer += `### Cryptographic Assessment Overview\n\n`;
    answer += `- **Organization**: ${assessment.organization}\n`;
    answer += `- **Quantum Readiness Score**: **${assessment.quantumReadinessScore}/100**\n`;
    answer += `- **Total Findings**: ${findings.length} (${criticals.length} Critical, ${vulnerables.length} Quantum-Vulnerable)\n\n`;
    answer += `**Immediate Recommendation**: Focus on high-risk findings in **Payment Service** and **Authentication Service**. Configure a Gemini API key in Settings for full interactive AI capabilities.`;
  }

  return { answer, citedFindings };
}

// ─── Main AI Consultant Function ──────────────────────────────

export async function askConsultant(
  question: string,
  assessment: Assessment,
  apiKey: string,
  chatHistory: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = []
): Promise<{ answer: string; citedFindings: string[] }> {

  // §22 Rule: If AI API key is missing, return clean, explicit deterministic fallback
  if (!apiKey || apiKey.trim() === '') {
    return getDeterministicFallbackGuidance(question, assessment);
  }

  // §20 Rule: Check rate limits
  const rateCheck = aiRateLimiter.canMakeCall();
  if (!rateCheck.allowed) {
    return {
      answer: `> **Rate Limit**: AI request limit reached. Please wait ${rateCheck.retryAfterSec} seconds before asking another question.\n\n${getDeterministicFallbackGuidance(question, assessment).answer}`,
      citedFindings: [],
    };
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);

    // §19 Structured context object
    const structuredContext = buildAIContext(assessment, question);
    const systemPrompt = `You are QuantumGuard AI, an enterprise cryptography and post-quantum migration assistant.

STRUCTURED ASSESSMENT DATA:
${formatAIContextPrompt(structuredContext)}

STRICT RULES YOU MUST FOLLOW:
1. Explain what was detected.
2. Explain why it matters.
3. Distinguish classical security risk (MD5, SHA-1, weak TLS) from quantum migration risk (RSA, ECC, ECDH).
4. Explain business impact when data is available.
5. Recommend a migration strategy citing NIST PQC standards (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205).
6. Mention uncertainty when information is missing.
7. Never claim a quantum computer currently breaks the asset.
8. Never claim a specific future year when RSA/ECC will be broken.
9. Never claim a migration is production-ready without testing.
10. When generating code, label it as an example unless verified.
11. Prefer hybrid migration strategies where appropriate (e.g. X25519 + ML-KEM).
12. For signatures and key establishment, distinguish their different PQC replacements (Key establishment → ML-KEM FIPS 203; Signatures → ML-DSA FIPS 204).
13. Cite the relevant finding IDs (e.g. [NB-0001] or [QG-0001]) when available.

Format responses using clean Markdown headers, bullet points, and bold text.`;

    const model = genAI.getGenerativeModel({
      model: 'gemini-2.0-flash',
      systemInstruction: systemPrompt,
    });

    const chat = model.startChat({ history: chatHistory });
    const result = await chat.sendMessage(question);
    const answer = result.response.text();

    const citedFindings: string[] = [];
    const idMatches = answer.match(/\[(?:NB|QG)-\d{4}\]/g) || [];
    idMatches.forEach(match => {
      const id = match.replace(/[\[\]]/g, '');
      if (!citedFindings.includes(id)) citedFindings.push(id);
    });

    return { answer, citedFindings };
  } catch (error: any) {
    // §22 Rule: On API error, return explicit deterministic fallback notice
    console.error('Gemini API call failed:', error);
    const fallback = getDeterministicFallbackGuidance(question, assessment);
    return {
      answer: `> **Notice**: AI service unavailable (${error.message || 'API call failed'}). Showing deterministic migration guidance.\n\n${fallback.answer.replace('> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n', '')}`,
      citedFindings: fallback.citedFindings,
    };
  }
}

export const SUGGESTED_QUESTIONS = [
  'What should we fix first?',
  'Which service should we migrate first and why?',
  'Explain our biggest quantum risk to a non-technical executive.',
  'Where are we using RSA and what should we replace it with?',
  'What is a "harvest now, decrypt later" attack and which of our systems are at risk?',
  'What is our recommended migration strategy for NovaBank Payment Service?',
  'Which of our findings are classical security problems (not quantum-related)?',
  'Explain ML-KEM vs ML-DSA and when to use each.',
];
