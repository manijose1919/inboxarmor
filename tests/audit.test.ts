import { describe, it, expect } from "vitest";
import { AuditEngine } from "../src/core/audit.js";
import { StaticDnsResolver } from "../src/core/dns/resolver.js";
import {
  overallScore,
  scoreMechanism,
  toGrade,
  MECHANISM_WEIGHTS,
} from "../src/core/scoring/scorer.js";
import { renderText, renderJson } from "../src/core/report/reporter.js";
import type { Finding } from "../src/core/types.js";

const f = (severity: Finding["severity"]): Finding => ({
  code: "X",
  severity,
  message: "m",
});

describe("scorer", () => {
  it("info/pass never reduce a mechanism score", () => {
    expect(scoreMechanism([f("pass"), f("info")])).toBe(100);
  });

  it("a fail zeroes the mechanism", () => {
    expect(scoreMechanism([f("fail")])).toBe(0);
  });

  it("warns deduct cumulatively and clamp at 0", () => {
    expect(scoreMechanism([f("warn")])).toBe(75);
    expect(scoreMechanism([f("warn"), f("warn"), f("warn"), f("warn"), f("warn")])).toBe(0);
  });

  it("weights sum to 100 and produce a weighted overall", () => {
    const total = Object.values(MECHANISM_WEIGHTS).reduce((a, b) => a + b, 0);
    expect(total).toBe(100);
    const perfect = overallScore({ spf: 100, dkim: 100, dmarc: 100, mtaSts: 100, bimi: 100 });
    expect(perfect).toBe(100);
  });

  it("maps scores to grades at the boundaries", () => {
    expect(toGrade(90)).toBe("A");
    expect(toGrade(89)).toBe("B");
    expect(toGrade(60)).toBe("C");
    expect(toGrade(39)).toBe("F");
  });
});

describe("AuditEngine (offline, StaticDnsResolver)", () => {
  const goodDkim = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".repeat(12);

  function wellConfigured() {
    return new StaticDnsResolver({
      "good.test": ["v=spf1 include:_spf.google.com -all"],
      "_dmarc.good.test": ["v=DMARC1; p=reject; rua=mailto:d@good.test"],
      "_mta-sts.good.test": ["v=STSv1; id=20240101T000000"],
      "default._bimi.good.test": ["v=BIMI1; l=https://good.test/logo.svg"],
      "google._domainkey.good.test": [`v=DKIM1; k=rsa; p=${goodDkim}`],
    });
  }

  it("gives a well-configured domain a top grade", async () => {
    const engine = new AuditEngine(wellConfigured());
    const r = await engine.audit("good.test");
    expect(r.grade).toBe("A");
    expect(r.score).toBeGreaterThanOrEqual(90);
    expect(r.mechanisms.dmarc.parsed).toBeDefined();
  });

  it("fails a bare domain with no auth records", async () => {
    const engine = new AuditEngine(new StaticDnsResolver());
    const r = await engine.audit("bare.test");
    expect(r.grade).toBe("F");
    const codes = r.findings.map((x) => x.code);
    expect(codes).toContain("SPF_MISSING");
    expect(codes).toContain("DMARC_MISSING");
    expect(codes).toContain("DKIM_MISSING");
  });

  it("normalizes trailing dots and casing in the domain", async () => {
    const engine = new AuditEngine(wellConfigured());
    const r = await engine.audit("GOOD.test.");
    expect(r.domain).toBe("good.test");
    expect(r.grade).toBe("A");
  });

  it("rejects empty, IP, and non-hostname inputs before touching DNS", async () => {
    const engine = new AuditEngine(new StaticDnsResolver());
    await expect(engine.audit("")).rejects.toMatchObject({ name: "InvalidDomainError" });
    await expect(engine.audit("127.0.0.1")).rejects.toMatchObject({ name: "InvalidDomainError" });
    await expect(engine.audit("localhost")).rejects.toMatchObject({ name: "InvalidDomainError" });
    await expect(engine.audit("not a domain")).rejects.toMatchObject({ name: "InvalidDomainError" });
    await expect(engine.audit("https://example.com")).rejects.toMatchObject({
      name: "InvalidDomainError",
    });
  });

  it("rejects a selector that would not be a legal DNS label", async () => {
    const engine = new AuditEngine(new StaticDnsResolver());
    await expect(
      engine.audit("sel.test", { selectors: ["../x"] }),
    ).rejects.toMatchObject({ name: "InvalidDomainError" });
  });

  it("honors custom DKIM selectors", async () => {
    const dns = new StaticDnsResolver({
      "custom._domainkey.sel.test": [`v=DKIM1; k=rsa; p=${goodDkim}`],
    });
    const engine = new AuditEngine(dns);
    const r = await engine.audit("sel.test", { selectors: ["custom"] });
    expect(r.mechanisms.dkim.present).toBe(true);
  });

  it("renders text and JSON without throwing", async () => {
    const engine = new AuditEngine(wellConfigured());
    const r = await engine.audit("good.test");
    expect(renderText(r)).toContain("InboxArmor");
    expect(() => JSON.parse(renderJson(r))).not.toThrow();
  });
});
