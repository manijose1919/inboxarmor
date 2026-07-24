/**
 * DMARC (RFC 7489) parser + validator.
 *
 * DMARC records live at `_dmarc.<domain>` and take the form
 * `v=DMARC1; p=reject; rua=mailto:...; pct=100; ...`.
 * Pure functions only.
 */

import type { Finding } from "../types.js";

export type DmarcPolicy = "none" | "quarantine" | "reject";
export type DmarcAlignment = "r" | "s"; // relaxed | strict

export interface DmarcParsed {
  version: "DMARC1";
  policy?: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  /** Percentage of mail the policy is applied to (0..100, default 100). */
  pct: number;
  rua: string[]; // aggregate report destinations
  ruf: string[]; // forensic report destinations
  adkim: DmarcAlignment;
  aspf: DmarcAlignment;
  /** Raw tag map for any tags we did not model explicitly. */
  tags: Record<string, string>;
}

export function isDmarcRecord(raw: string): boolean {
  return /^v=DMARC1(\s*;|\s*$)/i.test(raw.trim());
}

function parseTagList(raw: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key) tags[key] = value;
  }
  return tags;
}

function parseAddresses(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function parseDmarc(raw: string): DmarcParsed | null {
  if (!isDmarcRecord(raw)) return null;
  const tags = parseTagList(raw);

  const policy = tags["p"]?.toLowerCase() as DmarcPolicy | undefined;
  const subPolicy = tags["sp"]?.toLowerCase() as DmarcPolicy | undefined;
  const pctRaw = tags["pct"];
  const pct = pctRaw !== undefined && /^\d+$/.test(pctRaw)
    ? Math.min(100, Math.max(0, parseInt(pctRaw, 10)))
    : 100;

  return {
    version: "DMARC1",
    ...(policy ? { policy } : {}),
    ...(subPolicy ? { subdomainPolicy: subPolicy } : {}),
    pct,
    rua: parseAddresses(tags["rua"]),
    ruf: parseAddresses(tags["ruf"]),
    adkim: (tags["adkim"]?.toLowerCase() === "s" ? "s" : "r"),
    aspf: (tags["aspf"]?.toLowerCase() === "s" ? "s" : "r"),
    tags,
  };
}

const VALID_POLICIES = new Set<DmarcPolicy>(["none", "quarantine", "reject"]);

export function validateDmarc(records: string[], parsed: DmarcParsed | null): Finding[] {
  const findings: Finding[] = [];
  const dmarcRecords = records.filter(isDmarcRecord);

  if (dmarcRecords.length === 0) {
    findings.push({
      code: "DMARC_MISSING",
      severity: "fail",
      message:
        "No DMARC record was found. Without DMARC, receivers cannot tell how to handle spoofed mail, and you get no visibility into abuse.",
      remediation:
        'Publish a TXT record at "_dmarc.<domain>", starting with "v=DMARC1; p=none; rua=mailto:you@domain".',
    });
    return findings;
  }

  if (dmarcRecords.length > 1) {
    findings.push({
      code: "DMARC_MULTIPLE",
      severity: "fail",
      message: `Found ${dmarcRecords.length} DMARC records; exactly one is permitted. Receivers will ignore DMARC entirely.`,
      remediation: 'Keep a single TXT record at "_dmarc.<domain>".',
    });
  }

  if (!parsed) return findings;

  if (!parsed.policy || !VALID_POLICIES.has(parsed.policy)) {
    findings.push({
      code: "DMARC_NO_POLICY",
      severity: "fail",
      message: 'DMARC record has no valid "p=" policy tag and is invalid.',
      remediation: 'Add "p=none", "p=quarantine", or "p=reject".',
    });
  } else if (parsed.policy === "none") {
    findings.push({
      code: "DMARC_POLICY_NONE",
      severity: "warn",
      message:
        '"p=none" only monitors — it does not stop spoofed mail. It is a valid starting point but not a protective end state.',
      remediation:
        'After reviewing aggregate reports, move to "p=quarantine" and then "p=reject".',
    });
  } else if (parsed.policy === "quarantine") {
    findings.push({
      code: "DMARC_POLICY_QUARANTINE",
      severity: "info",
      message: '"p=quarantine" sends failing mail to spam — good, but "reject" is stronger.',
      remediation: 'Once confident, advance to "p=reject".',
    });
  } else {
    findings.push({
      code: "DMARC_POLICY_REJECT",
      severity: "pass",
      message: '"p=reject" blocks spoofed mail outright — strongest DMARC posture.',
    });
  }

  // Subdomain policy: an enforced apex policy with sp=none leaves every
  // subdomain spoofable while the domain appears "protected".
  if (
    parsed.policy &&
    parsed.policy !== "none" &&
    parsed.subdomainPolicy === "none"
  ) {
    findings.push({
      code: "DMARC_SUBDOMAIN_UNPROTECTED",
      severity: "warn",
      message:
        'The apex policy is enforced but "sp=none" leaves subdomains unprotected — attackers can spoof any subdomain.',
      remediation: 'Remove "sp=none" (subdomains inherit "p="), or set "sp=reject".',
    });
  }

  if (parsed.policy && parsed.policy !== "none" && parsed.pct < 100) {
    findings.push({
      code: "DMARC_PARTIAL_PCT",
      severity: "warn",
      message: `Policy applies to only ${parsed.pct}% of mail (pct=${parsed.pct}); the rest is unprotected.`,
      remediation: "Raise pct to 100 once rollout is validated.",
    });
  }

  if (parsed.rua.length === 0) {
    findings.push({
      code: "DMARC_NO_RUA",
      severity: "warn",
      message:
        'No aggregate report address ("rua=") is set, so you get no visibility into who is sending as your domain.',
      remediation: 'Add "rua=mailto:dmarc@yourdomain" to receive daily aggregate reports.',
    });
  }

  return findings;
}
