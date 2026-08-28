/**
 * Hostname validation for untrusted CLI input.
 *
 * The auditor looks names up in DNS (and later tiers may fetch HTTPS
 * policies). Rejecting junk before those lookups keeps `localhost`, IP
 * literals, and path-like strings from becoming accidental probes.
 */

import { InvalidDomainError } from "./types.js";

const DNS_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Normalize and accept a domain the way email-auth records are published:
 * lowercased, trailing-dot stripped, LDH labels only.
 */
export function normalizeDomain(input: string): string {
  const host = input.trim().toLowerCase().replace(/\.$/, "");
  if (!host) {
    throw new InvalidDomainError(input, "domain must not be empty");
  }
  if (host.length > 253) {
    throw new InvalidDomainError(input, "domain is too long");
  }
  if (host.includes(":") || IPV4.test(host)) {
    throw new InvalidDomainError(input, "IP addresses cannot be audited");
  }
  const labels = host.split(".");
  if (labels.length < 2) {
    throw new InvalidDomainError(input, "expected a fully-qualified domain");
  }
  if (labels.some((label) => !DNS_LABEL.test(label))) {
    throw new InvalidDomainError(input, "not a valid DNS hostname");
  }
  return host;
}

/** DKIM selectors become `<selector>._domainkey.<domain>` lookups. */
export function assertDkimSelector(selector: string): void {
  const name = selector.trim().toLowerCase();
  if (!name || !DNS_LABEL.test(name)) {
    throw new InvalidDomainError(selector, "not a valid DKIM selector");
  }
}
