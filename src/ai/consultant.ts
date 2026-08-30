// ============================================================
// Qrypto AI Advisor — §18, §22, & §30 AI Security Consultant
//
// Grounded in CBOM scan findings via §19 Context Builder.
// §20 Rate limiting & §22 Offline Fallback handling.
// Explicitly labels offline fallback: "AI service unavailable. Showing deterministic migration guidance."
// ============================================================

import { GoogleGenerativeAI } from '@google/generative-ai';
import type { Assessment } from '../types';
import { buildAIContext, formatAIContextPrompt } from './contextBuilder';
import { aiRateLimiter } from '../engine/security';
import { getUsageAwareRecommendation } from '../engine/migrationPlanner';

// ─── §30 Standard Suggested Questions ─────────────────────────

export const SUGGESTED_QUESTIONS = [
  'What is our biggest quantum risk?',
  'Which system should we migrate first?',
  'Explain our Q-Day exposure.',
  'Where are we using RSA?',
  'What is our HNDL risk?',
  'How can we improve crypto-agility?',
  'Generate a migration plan.',
];

// ─── Offline / Deterministic Guidance Generator (§22 & §30) ────

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

  if (qLower.includes('biggest') && qLower.includes('risk')) {
    answer += `### Primary Quantum Risk Assessment\n\n`;
    answer += `The single biggest quantum risk for **${assessment.organization}** is long-lived confidential data protected by asymmetric key encapsulation algorithms (RSA/ECDH).\n\n`;
    const topVuln = vulnerables.find(f => f.internetFacing) || vulnerables[0];
    if (topVuln) {
      citedFindings.push(topVuln.id);
      answer += `- **Highest Risk Asset**: \`${topVuln.file}:${topVuln.line}\` in **${topVuln.service}**\n`;
      answer += `- **Algorithm**: ${topVuln.algorithm} (${topVuln.usage})\n`;
      answer += `- **Data Retention**: ${topVuln.dataLifetimeYears} years (High HNDL Exposure)\n\n`;
    }
    answer += `**Why it matters**: Adversaries can record this encrypted traffic today (*Harvest Now*) and decrypt it when a cryptographically-relevant quantum computer is built (*Decrypt Later*).`;

  } else if (qLower.includes('migrate first') || qLower.includes('which system') || qLower.includes('priority')) {
    answer += `### Priority System Migration Sequence\n\nBased on deterministic risk analysis of **${assessment.organization}**:\n\n`;
    if (secrets.length > 0) {
      const topSecret = secrets[0];
      citedFindings.push(topSecret.id);
      answer += `1. **Remove Hardcoded Credentials** [${topSecret.id}]\n`;
      answer += `   - **Detected**: ${topSecret.algorithm} in \`${topSecret.file}:${topSecret.line}\`\n`;
      answer += `   - **Action**: Rotate immediately and adopt centralized secret management.\n\n`;
    }
    const paymentVulns = vulnerables.filter(f => f.service.includes('Payment'));
    if (paymentVulns.length > 0) {
      const topPayment = paymentVulns[0];
      citedFindings.push(topPayment.id);
      answer += `2. **${topPayment.service} Key Establishment** [${topPayment.id}]\n`;
      answer += `   - **Detected**: ${topPayment.algorithm} in \`${topPayment.file}:${topPayment.line}\`\n`;
      answer += `   - **Recommendation**: Evaluate hybrid X25519 + ML-KEM-768 key encapsulation.\n\n`;
    }
    const authVulns = vulnerables.filter(f => f.service.includes('Auth'));
    if (authVulns.length > 0) {
      const topAuth = authVulns[0];
      citedFindings.push(topAuth.id);
      answer += `3. **Authentication Token Signatures** [${topAuth.id}]\n`;
      answer += `   - **Detected**: ${topAuth.algorithm} in \`${topAuth.file}:${topAuth.line}\`\n`;
      answer += `   - **Recommendation**: Plan transition to ML-DSA-65 (FIPS 204) signatures.\n\n`;
    }

  } else if (qLower.includes('q-day') || qLower.includes('qday')) {
    answer += `### Q-Day Exposure Analysis\n\n`;
    answer += `In a Q-Day scenario (sudden availability of CRQCs):\n\n`;
    answer += `- **Quantum Readiness**: **${assessment.quantumReadinessScore}/100**\n`;
    answer += `- **Direct Impact**: **${vulnerables.length}** public key cryptography instances instantly compromised.\n`;
    answer += `- **Affected Services**: Internet-facing channels like Payment Service & Authentication Service would lose key transport & digital signature integrity.\n\n`;
    answer += `**Mitigation**: Implement crypto-agility wrappers to enable rapid algorithm swapping.`;

  } else if (qLower.includes('rsa')) {
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    answer += `### RSA Usage & PQC Replacements\n\n`;
    answer += `Found **${rsaFindings.length} RSA instances** across your codebase:\n\n`;
    rsaFindings.slice(0, 4).forEach(f => {
      citedFindings.push(f.id);
      const rec = getUsageAwareRecommendation(f.algorithm, f.usage);
      answer += `- **[${f.id}]** \`${f.file}:${f.line}\` (${f.service}) — Usage: *${f.usage}*\n`;
      answer += `  - **PQC Successor**: **${rec.replacement}**\n`;
      answer += `  - **Strategy**: ${rec.strategy}\n\n`;
    });
    answer += `*Note: RSA key transport maps to ML-KEM (FIPS 203), while RSA digital signatures map to ML-DSA (FIPS 204).*`;

  } else if (qLower.includes('hndl') || qLower.includes('harvest')) {
    answer += `### Harvest-Now-Decrypt-Later (HNDL) Exposure\n\n`;
    answer += `HNDL attacks compromise confidentiality by capturing encrypted traffic today for decryption when quantum hardware matures.\n\n`;
    answer += `**High HNDL Risk Assets in ${assessment.organization}**:\n`;
    findings.filter(f => f.dataLifetimeYears >= 10).slice(0, 4).forEach(f => {
      citedFindings.push(f.id);
      answer += `- **[${f.id}]** \`${f.file}:${f.line}\` (${f.service}) — Data retention: **${f.dataLifetimeYears} years**\n`;
    });
    answer += `\n**Remediation**: Prioritize hybrid key encapsulation (X25519 + ML-KEM-768) for all channels storing or transmitting data with long shelf lives.`;

  } else if (qLower.includes('agility') || qLower.includes('crypto-agility')) {
    answer += `### Improving Crypto-Agility\n\n`;
    answer += `Current Crypto Agility Score: **${assessment.cryptoAgilityScore?.score ?? 67}/100**\n\n`;
    answer += `**Key Improvements**:\n`;
    answer += `1. **Centralize Configurations**: Avoid scattering algorithm names (\`RSA-2048\`, \`AES-256-CBC\`) directly in source code.\n`;
    answer += `2. **Introduce Provider Abstraction**: Call high-level crypto wrappers (\`CryptoProvider.encrypt()\`) rather than primitive libraries.\n`;
    answer += `3. **Eliminate Hardcoded Keys**: Move all static secret keys out of source files into secrets managers.`;

  } else if (qLower.includes('plan') || qLower.includes('roadmap')) {
    answer += `### Post-Quantum Migration Plan Roadmap\n\n`;
    answer += `- **Phase 1 (Immediate)**: Remove hardcoded secrets & deprecate classical broken algorithms (MD5, SHA-1, TLS 1.0).\n`;
    answer += `- **Phase 2 (Short-Term)**: Deploy hybrid key encapsulation (ML-KEM-768) on critical internet-facing endpoints.\n`;
    answer += `- **Phase 3 (Medium-Term)**: Transition authentication token signing from RSA/ECDSA to ML-DSA-65.\n`;
    answer += `- **Phase 4 (Long-Term)**: Migrate Certificate Authority infrastructure and enable total crypto-agility.`;

  } else {
    answer += `### Cryptographic Assessment Overview\n\n`;
    answer += `- **Organization**: ${assessment.organization}\n`;
    answer += `- **Quantum Readiness Score**: **${assessment.quantumReadinessScore}/100**\n`;
    answer += `- **Total Findings**: ${findings.length} (${criticals.length} Critical, ${vulnerables.length} Quantum-Vulnerable)\n\n`;
    answer += `**Immediate Recommendation**: Focus on high-risk findings in **Payment Service** and **Authentication Service**.`;
  }

  return { answer, citedFindings };
}

// ─── OpenRouter API Integration ────────────────────────────────
async function callOpenRouter(
  apiKey: string,
  systemPrompt: string,
  question: string
): Promise<string> {
  const models = [
    'google/gemini-2.0-flash-001',
    'meta-llama/llama-3.3-70b-instruct',
    'openai/gpt-4o-mini',
    'deepseek/deepseek-r1-distill-llama-70b',
  ];

  let lastErr: Error | null = null;
  for (const model of models) {
    try {
      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey.trim()}`,
          'HTTP-Referer': 'https://qrypto.local',
          'X-Title': 'Qrypto AI Security Consultant',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: question },
          ],
          temperature: 0.3,
          max_tokens: 2048,
        }),
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`OpenRouter ${res.status}: ${errText}`);
      }

      const data = await res.json();
      const text = data.choices?.[0]?.message?.content;
      if (text) return text;
    } catch (err: any) {
      console.warn(`OpenRouter model ${model} failed:`, err.message || err);
      lastErr = err;
    }
  }
  throw lastErr || new Error('Failed to query OpenRouter models.');
}

// ─── Main AI Consultant Function ──────────────────────────────

export async function askConsultant(
  question: string,
  assessment: Assessment,
  apiKey?: string,
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

  const structuredContext = buildAIContext(assessment, question);

  const systemPrompt = `You are Qrypto AI, an enterprise cryptography and post-quantum migration security consultant.

STRUCTURED ASSESSMENT DATA:
${formatAIContextPrompt(structuredContext)}

STRICT RULES YOU MUST FOLLOW:
1. Explain what was detected.
2. Explain why it matters.
3. Distinguish classical security risk from quantum migration risk.
4. Recommend a migration strategy citing NIST PQC standards (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205).
5. Cite finding IDs when relevant.`;

  // Branch 1: OpenRouter API Key (sk-or-...)
  if (apiKey.includes('sk-or-')) {
    try {
      const answer = await callOpenRouter(apiKey, systemPrompt, question);
      const citedFindings: string[] = [];
      const idMatches = answer.match(/\[(?:NB|QG|F|MT)-\d{3,4}\]/g) || [];
      idMatches.forEach(match => {
        const id = match.replace(/[\[\]]/g, '');
        if (!citedFindings.includes(id)) citedFindings.push(id);
      });
      return { answer, citedFindings };
    } catch (err: any) {
      console.error('OpenRouter call failed:', err);
      const fallback = getDeterministicFallbackGuidance(question, assessment);
      return {
        answer: `> ⚠️ **OpenRouter API Error**: ${err.message || 'Unable to connect'}. Showing deterministic migration guidance.\n\n${fallback.answer.replace('> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n', '')}`,
        citedFindings: fallback.citedFindings,
      };
    }
  }

  // Branch 2: Google Gemini SDK Key
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const modelsToTry = ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash'];
    let lastError: any = null;

    for (const modelName of modelsToTry) {
      try {
        const model = genAI.getGenerativeModel({
          model: modelName,
          systemInstruction: systemPrompt,
        });

        const chat = model.startChat({ history: chatHistory });
        const result = await chat.sendMessage(question);
        const answer = result.response.text();

        const citedFindings: string[] = [];
        const idMatches = answer.match(/\[(?:NB|QG|F|MT)-\d{3,4}\]/g) || [];
        idMatches.forEach(match => {
          const id = match.replace(/[\[\]]/g, '');
          if (!citedFindings.includes(id)) citedFindings.push(id);
        });

        return { answer, citedFindings };
      } catch (err: any) {
        lastError = err;
        console.warn(`Gemini model ${modelName} failed:`, err.message || err);
      }
    }

    const fallback = getDeterministicFallbackGuidance(question, assessment);
    const isQuota = lastError?.message?.includes('429') || lastError?.message?.includes('quota') || lastError?.message?.includes('Quota');
    const noticeText = isQuota
      ? `> ⚠️ **API Quota Exceeded**: The API key quota limit was reached. You can update your API key in **Settings**. Showing deterministic migration guidance.\n\n`
      : `> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n`;

    return {
      answer: `${noticeText}${fallback.answer.replace('> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n', '')}`,
      citedFindings: fallback.citedFindings,
    };
  } catch (error: any) {
    const fallback = getDeterministicFallbackGuidance(question, assessment);
    return {
      answer: `> ⚠️ **API Error**: Unable to process request (${error.message || 'Error'}). Showing deterministic migration guidance.\n\n${fallback.answer.replace('> **Notice**: AI service unavailable. Showing deterministic migration guidance.\n\n', '')}`,
      citedFindings: fallback.citedFindings,
    };
  }
}
