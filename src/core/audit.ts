/**
 * AuditEngine — the single orchestration point for the core (Free) tier.
 *
 * This is the only place DNS fan-out happens; parsers/validators stay pure.
 * Given a domain it fetches records, parses them, runs validators, scores each
 * mechanism, and assembles a fully-typed {@link AuditResult}.
 */

import type { DnsResolver } from "./dns/resolver.js";
import type {
  AuditOptions,
  AuditResult,
  Finding,
  MechanismKey,
  MechanismReport,
} from "./types.js";
import { isSpfRecord, parseSpf, validateSpf } from "./parsers/spf.js";
import { isDmarcRecord, parseDmarc, validateDmarc } from "./parsers/dmarc.js";
import {
  COMMON_SELECTORS,
  parseDkim,
  validateDkim,
  type DkimKey,
} from "./parsers/dkim.js";
import { isMtaStsRecord, parseMtaSts, validateMtaSts } from "./parsers/mtaSts.js";
import { isBimiRecord, parseBimi, validateBimi } from "./parsers/bimi.js";
import { overallScore, scoreMechanism, toGrade } from "./scoring/scorer.js";

export class AuditEngine {
  constructor(private readonly dns: DnsResolver) {}

  async audit(domain: string, options: AuditOptions = {}): Promise<AuditResult> {
    const host = domain.trim().toLowerCase().replace(/\.$/, "");
    const selectors = options.selectors?.length
      ? options.selectors
      : [...COMMON_SELECTORS];

    // Fan out every independent DNS lookup concurrently.
    const [apexTxt, dmarcTxt, mtaStsTxt, bimiTxt, dkimKeys] = await Promise.all([
      this.dns.resolveTxt(host),
      this.dns.resolveTxt(`_dmarc.${host}`),
      this.dns.resolveTxt(`_mta-sts.${host}`),
      this.dns.resolveTxt(`default._bimi.${host}`),
      this.probeDkim(host, selectors),
    ]);

    const spf = this.buildSpf(apexTxt);
    const dmarc = this.buildDmarc(dmarcTxt);
    const dkim = this.buildDkim(dkimKeys);
    const mtaSts = this.buildMtaSts(mtaStsTxt);
    const bimi = this.buildBimi(bimiTxt);

    const subScores: Record<MechanismKey, number> = {
      spf: spf.score,
      dkim: dkim.score,
      dmarc: dmarc.score,
      mtaSts: mtaSts.score,
      bimi: bimi.score,
    };
    const score = overallScore(subScores);

    const findings = dedupeFindings([
      ...spf.findings,
      ...dkim.findings,
      ...dmarc.findings,
      ...mtaSts.findings,
      ...bimi.findings,
    ]);

    return {
      domain: host,
      timestamp: new Date().toISOString(),
      score,
      grade: toGrade(score),
      mechanisms: { spf, dkim, dmarc, mtaSts, bimi },
      findings,
    };
  }

  private async probeDkim(host: string, selectors: string[]): Promise<DkimKey[]> {
    const results = await Promise.all(
      selectors.map(async (selector) => {
        const txt = await this.dns.resolveTxt(`${selector}._domainkey.${host}`);
        for (const raw of txt) {
          const key = parseDkim(selector, raw);
          if (key) return key;
        }
        return null;
      }),
    );
    return results.filter((k): k is DkimKey => k !== null);
  }

  private buildSpf(apexTxt: string[]): MechanismReport {
    const raw = apexTxt.filter(isSpfRecord);
    const parsed = raw.length > 0 ? parseSpf(raw[0]!) : null;
    const findings = validateSpf(apexTxt, parsed);
    return report("spf", raw, parsed, findings);
  }

  private buildDmarc(dmarcTxt: string[]): MechanismReport {
    const raw = dmarcTxt.filter(isDmarcRecord);
    const parsed = raw.length > 0 ? parseDmarc(raw[0]!) : null;
    const findings = validateDmarc(dmarcTxt, parsed);
    return report("dmarc", raw, parsed, findings);
  }

  private buildDkim(keys: DkimKey[]): MechanismReport {
    const findings = validateDkim(keys);
    return report(
      "dkim",
      keys.map((k) => `${k.selector}._domainkey: ${k.publicKey ? "key" : "revoked"}`),
      keys.length > 0 ? keys : undefined,
      findings,
    );
  }

  private buildMtaSts(txt: string[]): MechanismReport {
    const raw = txt.filter(isMtaStsRecord);
    const parsed = raw.length > 0 ? parseMtaSts(raw[0]!) : null;
    return report("mtaSts", raw, parsed, validateMtaSts(txt, parsed));
  }

  private buildBimi(txt: string[]): MechanismReport {
    const raw = txt.filter(isBimiRecord);
    const parsed = raw.length > 0 ? parseBimi(raw[0]!) : null;
    return report("bimi", raw, parsed, validateBimi(txt, parsed));
  }
}

function report(
  mechanism: MechanismKey,
  raw: string[],
  parsed: unknown,
  findings: Finding[],
): MechanismReport {
  return {
    mechanism,
    present: raw.length > 0,
    raw,
    ...(parsed !== undefined && parsed !== null ? { parsed } : {}),
    findings,
    score: scoreMechanism(findings),
  };
}

/** Remove exact-duplicate findings (same code) while preserving order. */
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.code}:${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
