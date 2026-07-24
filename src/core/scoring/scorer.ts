/**
 * Deliverability scoring.
 *
 * Each mechanism produces a 0..100 sub-score from its findings; the overall
 * score is a weighted average. Weights live here so a future Pro "custom
 * scoring profile" is a config change, not a rewrite.
 */

import type { Finding, Grade, MechanismKey } from "../types.js";

/** Relative weight of each mechanism in the overall score. Sums to 100. */
export const MECHANISM_WEIGHTS: Record<MechanismKey, number> = {
  spf: 25,
  dkim: 20,
  dmarc: 35, // the enforcement layer that binds SPF+DKIM — weighted highest
  mtaSts: 10,
  bimi: 10,
};

/** Points deducted from a mechanism's 100 for a finding of each severity. */
const SEVERITY_PENALTY = {
  pass: 0,
  info: 0, // advisory only — never lowers the score
  warn: 25,
  fail: 100,
};

/**
 * Score a single mechanism from its findings.
 * A `fail` zeroes the mechanism; `warn`s deduct cumulatively; `info`/`pass`
 * never reduce the score.
 */
export function scoreMechanism(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_PENALTY[f.severity];
  }
  return Math.max(0, Math.min(100, score));
}

/** Combine mechanism sub-scores into a weighted overall 0..100 score. */
export function overallScore(subScores: Record<MechanismKey, number>): number {
  let weighted = 0;
  let totalWeight = 0;
  for (const key of Object.keys(MECHANISM_WEIGHTS) as MechanismKey[]) {
    weighted += subScores[key] * MECHANISM_WEIGHTS[key];
    totalWeight += MECHANISM_WEIGHTS[key];
  }
  return Math.round(weighted / totalWeight);
}

/** Map a 0..100 score to a letter grade. */
export function toGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
