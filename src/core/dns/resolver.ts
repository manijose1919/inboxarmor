/**
 * DNS access seam for the core engine.
 *
 * Everything that needs DNS depends on the {@link DnsResolver} interface,
 * never on `node:dns` directly. This lets tests inject fixture records and
 * keeps the auditing logic fully deterministic and offline-testable.
 */

import { Resolver } from "node:dns/promises";
import { DnsLookupError } from "../types.js";

/** A single MX record. */
export interface MxRecord {
  exchange: string;
  priority: number;
}

/** Minimal DNS surface the auditing engine relies on. */
export interface DnsResolver {
  /** Returns each TXT record with its character-strings concatenated. */
  resolveTxt(hostname: string): Promise<string[]>;
  resolveMx(hostname: string): Promise<MxRecord[]>;
}

/** DNS error codes that mean "the name/record simply doesn't exist". */
const NOT_FOUND_CODES = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);

/** Default per-lookup timeout. Audits run against untrusted third-party DNS. */
const DEFAULT_TIMEOUT_MS = 5000;

function isNotFound(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return typeof code === "string" && NOT_FOUND_CODES.has(code);
}

/** Rejects if `promise` does not settle within `ms`. */
async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  hostname: string,
  recordType: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          Object.assign(new Error(`timed out after ${ms}ms`), {
            code: "ETIMEOUT",
          }),
        ),
      ms,
    );
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

/**
 * Production resolver backed by `node:dns/promises`.
 *
 * "Not found" conditions resolve to empty results (a missing record is a
 * finding, not a crash); all other failures surface as {@link DnsLookupError}.
 */
export class NodeDnsResolver implements DnsResolver {
  private readonly resolver: Resolver;
  private readonly timeoutMs: number;

  constructor(servers?: string[], timeoutMs: number = DEFAULT_TIMEOUT_MS) {
    this.resolver = new Resolver();
    this.timeoutMs = timeoutMs;
    if (servers && servers.length > 0) {
      this.resolver.setServers(servers);
    }
  }

  async resolveTxt(hostname: string): Promise<string[]> {
    const host = hostname.toLowerCase();
    try {
      const records = await withTimeout(
        this.resolver.resolveTxt(host),
        this.timeoutMs,
        host,
        "TXT",
      );
      // node returns string[][] — each record is an array of char-strings
      // that must be concatenated with no separator (RFC 7208 §3.3). Trim
      // stray whitespace some nameservers pad onto the assembled string.
      return records.map((chunks) => chunks.join("").trim());
    } catch (err) {
      if (isNotFound(err)) return [];
      throw new DnsLookupError(host, "TXT", err);
    }
  }

  async resolveMx(hostname: string): Promise<MxRecord[]> {
    const host = hostname.toLowerCase();
    try {
      const records = await withTimeout(
        this.resolver.resolveMx(host),
        this.timeoutMs,
        host,
        "MX",
      );
      return records.map((r) => ({ exchange: r.exchange, priority: r.priority }));
    } catch (err) {
      if (isNotFound(err)) return [];
      throw new DnsLookupError(host, "MX", err);
    }
  }
}

/**
 * In-memory resolver for tests and offline/deterministic runs.
 * Seed it with a map of hostname -> TXT records (and optionally MX).
 */
export class StaticDnsResolver implements DnsResolver {
  constructor(
    private readonly txt: Record<string, string[]> = {},
    private readonly mx: Record<string, MxRecord[]> = {},
  ) {}

  async resolveTxt(hostname: string): Promise<string[]> {
    return this.txt[hostname.toLowerCase()] ?? [];
  }

  async resolveMx(hostname: string): Promise<MxRecord[]> {
    return this.mx[hostname.toLowerCase()] ?? [];
  }
}
