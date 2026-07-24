/**
 * BIMI (Brand Indicators for Message Identification) TXT parser + validator.
 *
 * BIMI records live at `default._bimi.<domain>` and let compliant mailboxes
 * show a brand logo next to authenticated mail. Requires DMARC at
 * quarantine/reject to be honored. Core validates the advertisement record.
 */

import type { Finding } from "../types.js";

export interface BimiParsed {
  version: "BIMI1";
  /** Logo location — an HTTPS URL to an SVG Tiny PS. */
  location?: string;
  /** Authority evidence (VMC certificate) URL, if any. */
  authority?: string;
  tags: Record<string, string>;
}

export function isBimiRecord(raw: string): boolean {
  return /^v=BIMI1(\s*;|\s*$)/i.test(raw.trim());
}

export function parseBimi(raw: string): BimiParsed | null {
  if (!isBimiRecord(raw)) return null;
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key) tags[key] = value;
  }
  return {
    version: "BIMI1",
    ...(tags["l"] ? { location: tags["l"] } : {}),
    ...(tags["a"] ? { authority: tags["a"] } : {}),
    tags,
  };
}

export function validateBimi(records: string[], parsed: BimiParsed | null): Finding[] {
  const bimiRecords = records.filter(isBimiRecord);
  if (bimiRecords.length === 0) {
    return [
      {
        code: "BIMI_MISSING",
        severity: "info",
        message:
          "No BIMI record found. BIMI displays your brand logo next to authenticated mail, improving recognition and trust. It is optional and requires enforced DMARC.",
        remediation:
          'Once DMARC is at quarantine/reject, publish "default._bimi.<domain>" TXT "v=BIMI1; l=https://.../logo.svg".',
      },
    ];
  }
  if (parsed && !parsed.location) {
    return [
      {
        code: "BIMI_NO_LOGO",
        severity: "warn",
        message: 'BIMI record has no logo location ("l=").',
        remediation: 'Add "l=https://<domain>/path/logo.svg" pointing to an SVG Tiny PS asset.',
      },
    ];
  }
  return [
    {
      code: "BIMI_PRESENT",
      severity: "pass",
      message: "BIMI is published; compliant mailboxes can display your brand logo.",
    },
  ];
}
