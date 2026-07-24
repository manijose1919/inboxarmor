/**
 * MTA-STS (RFC 8461) TXT record parser + validator.
 *
 * The TXT record at `_mta-sts.<domain>` advertises that a domain publishes an
 * MTA-STS policy (which enforces TLS on inbound SMTP). The full policy lives
 * over HTTPS; the core stays DNS-only and validates the advertisement record.
 */

import type { Finding } from "../types.js";

export interface MtaStsParsed {
  version: "STSv1";
  /** Policy id — changes when the HTTPS policy changes. */
  id?: string;
  tags: Record<string, string>;
}

export function isMtaStsRecord(raw: string): boolean {
  return /^v=STSv1(\s*;|\s*$)/i.test(raw.trim());
}

export function parseMtaSts(raw: string): MtaStsParsed | null {
  if (!isMtaStsRecord(raw)) return null;
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key) tags[key] = value;
  }
  return { version: "STSv1", ...(tags["id"] ? { id: tags["id"] } : {}), tags };
}

export function validateMtaSts(records: string[], parsed: MtaStsParsed | null): Finding[] {
  const stsRecords = records.filter(isMtaStsRecord);
  if (stsRecords.length === 0) {
    return [
      {
        code: "MTASTS_MISSING",
        severity: "info",
        message:
          "No MTA-STS record found. MTA-STS enforces TLS on mail sent TO your domain, preventing downgrade attacks. It is recommended but optional.",
        remediation:
          'Publish "_mta-sts.<domain>" TXT "v=STSv1; id=<timestamp>" and host a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.',
      },
    ];
  }
  if (parsed && !parsed.id) {
    return [
      {
        code: "MTASTS_NO_ID",
        severity: "warn",
        message: 'MTA-STS record is missing an "id=" value; receivers use it to detect policy changes.',
        remediation: 'Add an "id=" tag that changes whenever the HTTPS policy changes.',
      },
    ];
  }
  return [
    {
      code: "MTASTS_PRESENT",
      severity: "pass",
      message: "MTA-STS is advertised, enforcing TLS on inbound mail.",
    },
  ];
}
