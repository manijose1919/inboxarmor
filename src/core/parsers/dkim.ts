/**
 * DKIM (RFC 6376) parser + validator.
 *
 * DKIM public keys live at `<selector>._domainkey.<domain>` as TXT records of
 * the form `v=DKIM1; k=rsa; p=<base64 public key>`. Selectors cannot be
 * enumerated from DNS, so the engine probes a set of common selectors and
 * reports on whichever are found.
 */

import type { Finding } from "../types.js";

/** Common DKIM selectors used by major providers. */
export const COMMON_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "mail",
  "dkim",
  "s1",
  "s2",
  "mandrill",
  "mxvault",
  "zoho",
] as const;

export interface DkimKey {
  selector: string;
  version?: string; // DKIM1
  keyType: string; // rsa | ed25519 (default rsa)
  publicKey: string; // p= value ("" means revoked)
  /** Estimated RSA modulus size in bits (best-effort from base64 length). */
  keyBits?: number;
  tags: Record<string, string>;
}

export function isDkimRecord(raw: string): boolean {
  const t = raw.trim();
  // Reject records that explicitly declare a different mechanism version —
  // DMARC/SPF/STS/BIMI records also carry a "p=" or "v=" tag and must not be
  // misclassified as DKIM keys.
  if (/(^|;)\s*v\s*=\s*(DMARC1|spf1|STSv1|BIMI1)/i.test(t)) return false;
  // A DKIM key record either declares v=DKIM1 or carries a bare p= key tag.
  return /(^|;)\s*v\s*=\s*DKIM1/i.test(t) || /(^|;)\s*p\s*=/i.test(t);
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

/** Rough bit-length of an RSA key from the base64-encoded SubjectPublicKeyInfo. */
function estimateRsaBits(publicKey: string): number | undefined {
  const b64 = publicKey.replace(/\s+/g, "");
  if (b64.length === 0) return undefined;
  const bytes = Math.floor((b64.length * 3) / 4);
  // SPKI wrapper overhead is ~38 bytes for RSA; the rest is modulus+exponent.
  const modulusBytes = Math.max(0, bytes - 38);
  return Math.round((modulusBytes * 8) / 128) * 128; // snap to nearest 128
}

export function parseDkim(selector: string, raw: string): DkimKey | null {
  if (!isDkimRecord(raw)) return null;
  const tags = parseTagList(raw);
  const publicKey = tags["p"] ?? "";
  return {
    selector,
    ...(tags["v"] ? { version: tags["v"] } : {}),
    keyType: (tags["k"] ?? "rsa").toLowerCase(),
    publicKey,
    ...(publicKey && (tags["k"] ?? "rsa").toLowerCase() === "rsa"
      ? { keyBits: estimateRsaBits(publicKey) }
      : {}),
    tags,
  };
}

/**
 * Validate DKIM posture given the keys discovered by probing selectors.
 * @param keys - successfully parsed keys (one per selector that resolved).
 */
export function validateDkim(keys: DkimKey[]): Finding[] {
  const findings: Finding[] = [];

  if (keys.length === 0) {
    // DKIM selectors cannot be enumerated from DNS — we can only probe known
    // names. "Not found" therefore means "unconfirmed", not "definitely
    // absent", so this is a warning rather than a hard failure to avoid
    // false negatives for domains using custom/rotating selectors.
    findings.push({
      code: "DKIM_MISSING",
      severity: "warn",
      message:
        "DKIM could not be confirmed for any of the probed selectors. The domain may still sign mail using a custom selector we did not test.",
      remediation:
        "If you sign with a custom selector, re-run with --selectors <name>. Otherwise, enable DKIM signing and publish the key at <selector>._domainkey.<domain>.",
    });
    return findings;
  }

  for (const key of keys) {
    if (key.publicKey === "") {
      findings.push({
        code: "DKIM_REVOKED",
        severity: "warn",
        message: `Selector "${key.selector}" has an empty public key (p=), which marks it as revoked.`,
        remediation: "Remove unused selectors or republish a valid key.",
      });
      continue;
    }

    if (key.keyType === "rsa" && key.keyBits !== undefined && key.keyBits < 1024) {
      findings.push({
        code: "DKIM_WEAK_KEY",
        severity: "warn",
        message: `Selector "${key.selector}" uses an ~${key.keyBits}-bit RSA key; keys under 1024 bits are considered weak and may be ignored.`,
        remediation: "Rotate to at least a 2048-bit RSA key.",
      });
    } else {
      findings.push({
        code: "DKIM_VALID",
        severity: "pass",
        message: `Selector "${key.selector}" publishes a valid ${
          key.keyType === "rsa" && key.keyBits ? `${key.keyBits}-bit RSA` : key.keyType
        } DKIM key.`,
      });
    }
  }

  return findings;
}
