// ============================================================
// Qrypto — Severity Model
//
// WHY THIS MODULE EXISTS
// ---------------------------------------------------------------
// Severity used to be derived directly from the contextual risk score:
//
//     severity: riskBreakdown.totalScore >= 80 ? 'critical'
//             : riskBreakdown.totalScore >= 60 ? 'high' : ...
//
// That collapsed two genuinely independent questions into one number, and
// produced two classes of wrong answer that were verified against the live
// engine before this module was written:
//
//   1. INFLATION of safe primitives.
//      ML-KEM (NIST FIPS 203, post-quantum) in a file path containing
//      "payment" scored 61 and was reported as HIGH severity. The tool was
//      flagging the recommended fix as a vulnerability.
//
//   2. DEFLATION of broken primitives.
//      MD5 in a test fixture scored 44 and was reported as MEDIUM. MD5 has
//      practical collision attacks; its severity is a property of MD5, not of
//      the directory it appears in.
//
//   Worse, the same algorithm reported different severities depending only on
//   its path: ML-KEM was HIGH in src/payment/ and LOW in src/util/. Severity
//   was not a property of the algorithm at all.
//
// THE MODEL
// ---------------------------------------------------------------
// Two axes that are never collapsed into one another. This mirrors the
// established CVSS separation of base score (intrinsic) from environmental
// score (deployment-specific), which is the framing a security reviewer
// already expects.
//
//   algorithmSeverity  Intrinsic to the primitive and its parameters. A
//                      function of the algorithm alone. Path-independent, so
//                      the same primitive always reports the same value.
//                      ML-KEM is always 'info'. MD5 is always 'high'.
//
//   contextualRisk     0-100. Where the primitive sits: internet exposure,
//                      data sensitivity, data lifetime, business criticality,
//                      migration difficulty. Drives PRIORITISATION ORDER.
//
//   severity           The effective severity that gets displayed. Derived
//                      from the two above by the bounded, documented rules in
//                      deriveEffectiveSeverity(). Every derivation emits a
//                      human-readable rationale so the number is auditable
//                      rather than merely asserted.
//
// The governing invariants, stated so they can be tested:
//   I1. Context can never present a broken primitive as safe.
//       effective >= algorithmSeverity, always.
//   I2. Context can never present a quantum-safe primitive as a finding.
//       quantum-resistant primitives are never escalated.
//   I3. Context is an adjustment, not the answer.
//       Escalation is capped at one severity level.
// ============================================================

import type { QuantumStatus, Severity, AlgorithmCategory } from '../types';

/** Ascending order of seriousness. Index is the rank. */
export const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'] as const;

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
  // An unrecognised severity must not silently become 'info'.
  return index === -1 ? SEVERITY_ORDER.indexOf('medium') : index;
}

export function rankToSeverity(rank: number): Severity {
  const clamped = Math.max(0, Math.min(SEVERITY_ORDER.length - 1, Math.round(rank)));
  return SEVERITY_ORDER[clamped] as Severity;
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

/**
 * Contextual risk at or above which a quantum-vulnerable or classically weak
 * primitive is escalated one level.
 *
 * Set high deliberately. Context should change the answer only when it is
 * decisively bad, otherwise every finding in a business-critical service drifts
 * upward and severity stops discriminating.
 */
export const ESCALATION_RISK_THRESHOLD = 80;

/**
 * Only these statuses are eligible for contextual escalation.
 *
 * 'adequate' is excluded on purpose: AES-256 in a payment service is correct
 * engineering, not a medium-severity finding. Escalating it would bury the real
 * findings under noise — the most common way an inventory tool loses its users'
 * trust.
 */
const ESCALATABLE_STATUSES: readonly QuantumStatus[] = ['vulnerable', 'classical-weak', 'unknown'];

/**
 * Severity ceiling for primitives that are already quantum-resistant.
 *
 * Defence in depth against pattern-authoring mistakes: if a PQC pattern is ever
 * given baseSeverity 'high', this clamp catches it rather than letting Qrypto
 * report NIST-approved cryptography as a vulnerability. Kept at 'low' rather
 * than 'info' so a genuine PQC misuse finding (bad parameter set, for example)
 * can still surface.
 */
const QUANTUM_RESISTANT_CEILING: Severity = 'low';

export interface AlgorithmSeverityInput {
  algorithm: string;
  quantumStatus: QuantumStatus;
  /** Curated per-pattern severity — the primary signal. */
  baseSeverity: Severity;
  keySize?: number;
  category: AlgorithmCategory;
}

/**
 * Intrinsic severity of the primitive and its parameters.
 *
 * Deliberately takes no path, service, or exposure argument. That is the whole
 * point: this value must be reproducible from the algorithm alone, so the same
 * primitive cannot report two different severities in two different files.
 */
export function deriveAlgorithmSeverity(input: AlgorithmSeverityInput): {
  severity: Severity;
  rationale: string;
} {
  const { quantumStatus, baseSeverity, keySize, category } = input;

  // I2: quantum-resistant primitives are clamped and never refined upward.
  if (quantumStatus === 'quantum-resistant') {
    const clamped =
      severityRank(baseSeverity) > severityRank(QUANTUM_RESISTANT_CEILING)
        ? QUANTUM_RESISTANT_CEILING
        : baseSeverity;
    return {
      severity: clamped,
      rationale: `${input.algorithm} is quantum-resistant; recorded for inventory completeness, not as a weakness.`,
    };
  }

  let severity = baseSeverity;
  const reasons: string[] = [`pattern base severity ${baseSeverity}`];

  // Key-size refinement for asymmetric primitives whose security scales with
  // modulus/curve size. Only ever raises severity — a large key does not make a
  // quantum-vulnerable algorithm acceptable, it only delays classical attack.
  if (quantumStatus === 'vulnerable' && typeof keySize === 'number' && keySize > 0) {
    if (
      category === 'public-key' ||
      category === 'signature' ||
      category === 'key-exchange' ||
      category === 'certificate'
    ) {
      const isEllipticCurve = /ec|curve|ed25519|x25519/i.test(input.algorithm);

      if (isEllipticCurve && keySize < 224) {
        severity = maxSeverity(severity, 'critical');
        reasons.push(`curve size ${keySize} is below the 224-bit classical floor`);
      } else if (!isEllipticCurve && keySize <= 1024) {
        severity = maxSeverity(severity, 'critical');
        reasons.push(`${keySize}-bit modulus is classically factorable today`);
      } else if (!isEllipticCurve && keySize < 2048) {
        severity = maxSeverity(severity, 'high');
        reasons.push(`${keySize}-bit modulus is below the NIST 2048-bit minimum`);
      }
    }
  }

  // A hardcoded secret is a present-tense compromise, independent of quantum
  // computing. It must never be reported below 'high'.
  if (category === 'secret') {
    severity = maxSeverity(severity, 'high');
    reasons.push('credential material in source is an immediate exposure');
  }

  return { severity, rationale: reasons.join('; ') };
}

export interface EffectiveSeverityInput {
  algorithmSeverity: Severity;
  quantumStatus: QuantumStatus;
  /** 0-100 contextual risk from the risk engine. */
  contextualRisk: number;
}

/**
 * Combine the two axes into the severity that is displayed and sorted on.
 *
 * Enforces I1 (never below algorithmSeverity), I2 (quantum-resistant is never
 * escalated) and I3 (escalation capped at one level).
 */
export function deriveEffectiveSeverity(input: EffectiveSeverityInput): {
  severity: Severity;
  rationale: string;
  escalated: boolean;
} {
  const { algorithmSeverity, quantumStatus, contextualRisk } = input;

  if (!ESCALATABLE_STATUSES.includes(quantumStatus)) {
    return {
      severity: algorithmSeverity,
      escalated: false,
      rationale:
        `Severity fixed at ${algorithmSeverity} by the algorithm itself (${quantumStatus}). ` +
        `Deployment context scored ${contextualRisk}/100 and affects remediation priority only.`,
    };
  }

  if (contextualRisk >= ESCALATION_RISK_THRESHOLD) {
    const escalated = rankToSeverity(severityRank(algorithmSeverity) + 1);
    if (escalated !== algorithmSeverity) {
      return {
        severity: escalated,
        escalated: true,
        rationale:
          `Raised from ${algorithmSeverity} to ${escalated}: contextual risk ${contextualRisk}/100 ` +
          `is at or above the ${ESCALATION_RISK_THRESHOLD} escalation threshold. Capped at one level.`,
      };
    }
    return {
      severity: algorithmSeverity,
      escalated: false,
      rationale:
        `Already at ${algorithmSeverity}, the maximum; contextual risk ${contextualRisk}/100 cannot raise it further.`,
    };
  }

  return {
    severity: algorithmSeverity,
    escalated: false,
    rationale:
      `Severity ${algorithmSeverity} from the algorithm; contextual risk ${contextualRisk}/100 is below ` +
      `the ${ESCALATION_RISK_THRESHOLD} escalation threshold, so context sets priority only.`,
  };
}
