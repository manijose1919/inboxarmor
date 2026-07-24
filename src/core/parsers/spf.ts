/**
 * SPF (Sender Policy Framework, RFC 7208) parser + validator.
 *
 * Pure functions only — no DNS, no I/O. `parseSpf` turns a raw TXT record
 * into structure; `validateSpf` turns structure (plus the set of TXT records
 * found at the domain apex) into findings.
 */

import type { Finding } from "../types.js";

export type SpfQualifier = "+" | "-" | "~" | "?";

/** Mechanisms that each cost one DNS lookup toward the RFC 7208 limit of 10. */
const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);

export interface SpfMechanism {
  qualifier: SpfQualifier;
  type: string; // include | a | mx | ip4 | ip6 | ptr | exists | all | redirect
  value?: string;
}

export interface SpfParsed {
  version: "spf1";
  mechanisms: SpfMechanism[];
  /** Qualifier of the terminal `all`, if present (e.g. "-" for -all). */
  all?: SpfQualifier;
  /** Value of a `redirect=` modifier, if present. */
  redirect?: string;
  /** Count of mechanisms that require a DNS lookup (limit is 10). */
  lookupCount: number;
}

/** Returns true if a raw TXT record is an SPF record. */
export function isSpfRecord(raw: string): boolean {
  return /^v=spf1(\s|$)/i.test(raw.trim());
}

/**
 * Parse a single raw SPF TXT record. Returns null if it is not SPF.
 * Unknown/other terms are still captured as mechanisms so validation can
 * reason about them.
 */
export function parseSpf(raw: string): SpfParsed | null {
  const trimmed = raw.trim();
  if (!isSpfRecord(trimmed)) return null;

  const terms = trimmed.split(/\s+/).slice(1); // drop "v=spf1"
  const mechanisms: SpfMechanism[] = [];
  let all: SpfQualifier | undefined;
  let redirect: string | undefined;
  let lookupCount = 0;

  for (const term of terms) {
    if (term === "") continue;

    // Modifiers use "name=value" and are not qualified.
    const modifier = /^([a-z0-9_.-]+)=(.*)$/i.exec(term);
    if (modifier && (modifier[1]!.toLowerCase() === "redirect")) {
      redirect = modifier[2];
      lookupCount += 1; // redirect costs a lookup
      continue;
    }
    if (modifier && modifier[1]!.toLowerCase() === "exp") {
      continue; // exp= is explanatory, no lookup, not scored
    }

    const qualifier = ("+-~?".includes(term[0] ?? "") ? term[0] : "+") as SpfQualifier;
    const body = "+-~?".includes(term[0] ?? "") ? term.slice(1) : term;
    const [typeRaw, ...rest] = body.split(":");
    const type = (typeRaw ?? "").toLowerCase();
    const value = rest.length > 0 ? rest.join(":") : undefined;

    if (type === "all") {
      all = qualifier;
      mechanisms.push({ qualifier, type: "all" });
      continue;
    }

    if (LOOKUP_MECHANISMS.has(type)) lookupCount += 1;
    mechanisms.push({ qualifier, type, ...(value !== undefined ? { value } : {}) });
  }

  return {
    version: "spf1",
    mechanisms,
    ...(all !== undefined ? { all } : {}),
    ...(redirect !== undefined ? { redirect } : {}),
    lookupCount,
  };
}

/**
 * Validate SPF posture.
 * @param records - all TXT records found at the domain apex (to detect the
 *                  "multiple SPF records" permerror).
 * @param parsed  - the parsed SPF record, or null if none present.
 */
export function validateSpf(records: string[], parsed: SpfParsed | null): Finding[] {
  const findings: Finding[] = [];
  const spfRecords = records.filter(isSpfRecord);

  if (spfRecords.length === 0) {
    findings.push({
      code: "SPF_MISSING",
      severity: "fail",
      message: "No SPF record was found for this domain.",
      remediation:
        'Publish a TXT record at the domain apex, e.g. "v=spf1 include:_spf.yourprovider.com -all".',
    });
    return findings;
  }

  if (spfRecords.length > 1) {
    findings.push({
      code: "SPF_MULTIPLE",
      severity: "fail",
      message: `Found ${spfRecords.length} SPF records; RFC 7208 permits exactly one. Receivers will return "permerror".`,
      remediation: "Merge all SPF rules into a single TXT record.",
    });
  }

  if (!parsed) return findings;

  if (parsed.lookupCount > 10) {
    findings.push({
      code: "SPF_TOO_MANY_LOOKUPS",
      severity: "fail",
      message: `SPF requires ${parsed.lookupCount} DNS lookups; the limit is 10. Receivers will return "permerror" and ignore SPF.`,
      remediation:
        "Flatten includes, remove unused providers, or use SPF-flattening to stay within 10 lookups.",
    });
  } else if (parsed.lookupCount >= 8) {
    findings.push({
      code: "SPF_LOOKUPS_NEAR_LIMIT",
      severity: "warn",
      message: `SPF uses ${parsed.lookupCount} of the 10 allowed DNS lookups. Adding providers risks a permerror.`,
      remediation: "Consolidate includes before adding new senders.",
    });
  }

  if (parsed.all === undefined && parsed.redirect === undefined) {
    findings.push({
      code: "SPF_NO_ALL",
      severity: "warn",
      message:
        'SPF has no terminating "all" mechanism, so its effect is undefined for unlisted senders.',
      remediation: 'End the record with "-all" (hard fail) or "~all" (soft fail).',
    });
  } else if (parsed.all === "+") {
    findings.push({
      code: "SPF_PASS_ALL",
      severity: "fail",
      message: '"+all" authorizes the entire internet to send as your domain — this negates SPF.',
      remediation: 'Replace "+all" with "-all" or "~all".',
    });
  } else if (parsed.all === "?") {
    findings.push({
      code: "SPF_NEUTRAL_ALL",
      severity: "warn",
      message: '"?all" (neutral) provides no protection against spoofing.',
      remediation: 'Use "-all" (hard fail) or at least "~all" (soft fail).',
    });
  } else {
    findings.push({
      code: parsed.all === "-" ? "SPF_HARD_FAIL" : "SPF_SOFT_FAIL",
      severity: "pass",
      message:
        parsed.all === "-"
          ? 'SPF ends with "-all" (hard fail) — strong protection.'
          : 'SPF ends with "~all" (soft fail) — acceptable protection.',
    });
  }

  return findings;
}
