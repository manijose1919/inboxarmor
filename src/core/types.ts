/**
 * Shared domain types for the InboxArmor core auditing engine.
 *
 * These types form the stable contract that the premium/ and pro/ modules
 * consume. The core never imports from those modules — dependencies point
 * inward only.
 */

/** Product tier. Gates premium/pro CLI subcommands; core always works. */
export type Tier = "free" | "premium" | "pro";

/** Severity of a single finding, ordered from best to worst. */
export type Severity = "pass" | "info" | "warn" | "fail";

/** Numeric weight used to order/aggregate severities. */
export const SEVERITY_RANK: Record<Severity, number> = {
  pass: 0,
  info: 1,
  warn: 2,
  fail: 3,
};

/** A single machine- and human-readable observation about a mechanism. */
export interface Finding {
  /** Stable machine code, e.g. "SPF_MISSING". Safe for alerting/dedup. */
  code: string;
  severity: Severity;
  /** Plain-English description of what was observed. */
  message: string;
  /** Optional actionable remediation guidance. */
  remediation?: string;
}

/** Which email-auth mechanism a report covers. */
export type MechanismKey = "spf" | "dkim" | "dmarc" | "mtaSts" | "bimi";

/**
 * Result of auditing a single mechanism.
 * @typeParam T - the shape of the parsed record for this mechanism.
 */
export interface MechanismReport<T = unknown> {
  mechanism: MechanismKey;
  /** Was any record for this mechanism found in DNS? */
  present: boolean;
  /** Raw DNS record string(s) exactly as published. */
  raw: string[];
  /** Structured parse of the record, when present and parseable. */
  parsed?: T;
  findings: Finding[];
  /** 0..100 posture score for this mechanism alone. */
  score: number;
}

/** Overall letter grade derived from the weighted score. */
export type Grade = "A" | "B" | "C" | "D" | "F";

/** The complete audit of one domain. */
export interface AuditResult {
  domain: string;
  /** ISO-8601 timestamp the audit was produced. */
  timestamp: string;
  /** Weighted 0..100 deliverability posture score. */
  score: number;
  grade: Grade;
  mechanisms: {
    spf: MechanismReport;
    dkim: MechanismReport;
    dmarc: MechanismReport;
    mtaSts: MechanismReport;
    bimi: MechanismReport;
  };
  /** Flattened, de-duplicated list of all findings across mechanisms. */
  findings: Finding[];
}

/** Options accepted by the audit engine. */
export interface AuditOptions {
  /**
   * DKIM selectors to probe. DKIM keys live at
   * `<selector>._domainkey.<domain>` and selectors cannot be enumerated
   * from DNS, so we probe a set of common/known selectors.
   */
  selectors?: string[];
}

/** Error thrown when the caller passes a name that is not a DNS domain. */
export class InvalidDomainError extends Error {
  constructor(public readonly domain: string, reason: string) {
    super(`Invalid domain "${domain}": ${reason}`);
    this.name = "InvalidDomainError";
  }
}

/** Error thrown for genuine DNS infrastructure failures (not "not found"). */
export class DnsLookupError extends Error {
  constructor(
    public readonly hostname: string,
    public readonly recordType: string,
    public override readonly cause: unknown,
  ) {
    super(
      `DNS ${recordType} lookup failed for "${hostname}": ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = "DnsLookupError";
  }
}
