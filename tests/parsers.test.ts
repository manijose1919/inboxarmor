import { describe, it, expect } from "vitest";
import { parseSpf, validateSpf, isSpfRecord } from "../src/core/parsers/spf.js";
import { parseDmarc, validateDmarc } from "../src/core/parsers/dmarc.js";
import { parseDkim, validateDkim } from "../src/core/parsers/dkim.js";
import { parseMtaSts, validateMtaSts } from "../src/core/parsers/mtaSts.js";
import { parseBimi, validateBimi } from "../src/core/parsers/bimi.js";

const codes = (fs: { code: string }[]) => fs.map((f) => f.code);

describe("SPF parser", () => {
  it("identifies SPF records case-insensitively", () => {
    expect(isSpfRecord("v=spf1 -all")).toBe(true);
    expect(isSpfRecord("V=SPF1 include:x -all")).toBe(true);
    expect(isSpfRecord("v=DMARC1; p=none")).toBe(false);
    expect(isSpfRecord("spf1 stuff")).toBe(false);
  });

  it("parses mechanisms, qualifiers, and the terminal all", () => {
    const p = parseSpf("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all")!;
    expect(p.all).toBe("~");
    expect(p.mechanisms.find((m) => m.type === "include")?.value).toBe(
      "_spf.google.com",
    );
    expect(p.lookupCount).toBe(1); // only the include costs a lookup
  });

  it("counts all DNS-lookup mechanisms including redirect", () => {
    const p = parseSpf(
      "v=spf1 a mx include:a.com include:b.com exists:%{i}.x redirect=c.com",
    )!;
    // a, mx, include x2, exists, redirect = 6
    expect(p.lookupCount).toBe(6);
  });

  it("flags +all as a fail", () => {
    const p = parseSpf("v=spf1 +all");
    expect(codes(validateSpf(["v=spf1 +all"], p))).toContain("SPF_PASS_ALL");
  });

  it("flags a missing SPF record", () => {
    expect(codes(validateSpf([], null))).toContain("SPF_MISSING");
  });

  it("flags multiple SPF records (permerror)", () => {
    const recs = ["v=spf1 -all", "v=spf1 include:x -all"];
    expect(codes(validateSpf(recs, parseSpf(recs[0]!)))).toContain(
      "SPF_MULTIPLE",
    );
  });

  it("flags exceeding the 10-lookup limit", () => {
    const inc = Array.from({ length: 11 }, (_, i) => `include:h${i}.com`).join(" ");
    const raw = `v=spf1 ${inc} -all`;
    expect(codes(validateSpf([raw], parseSpf(raw)))).toContain(
      "SPF_TOO_MANY_LOOKUPS",
    );
  });

  it("passes a clean hard-fail record", () => {
    const raw = "v=spf1 include:_spf.google.com -all";
    expect(codes(validateSpf([raw], parseSpf(raw)))).toContain("SPF_HARD_FAIL");
  });
});

describe("DMARC parser", () => {
  it("parses policy, pct, and rua", () => {
    const p = parseDmarc("v=DMARC1; p=reject; pct=100; rua=mailto:a@x.com,mailto:b@x.com")!;
    expect(p.policy).toBe("reject");
    expect(p.pct).toBe(100);
    expect(p.rua).toHaveLength(2);
  });

  it("defaults pct to 100 when absent and clamps out-of-range", () => {
    expect(parseDmarc("v=DMARC1; p=none")!.pct).toBe(100);
    expect(parseDmarc("v=DMARC1; p=none; pct=250")!.pct).toBe(100);
  });

  it("flags p=none as monitor-only", () => {
    const raw = "v=DMARC1; p=none; rua=mailto:a@x.com";
    expect(codes(validateDmarc([raw], parseDmarc(raw)))).toContain(
      "DMARC_POLICY_NONE",
    );
  });

  it("passes p=reject", () => {
    const raw = "v=DMARC1; p=reject; rua=mailto:a@x.com";
    expect(codes(validateDmarc([raw], parseDmarc(raw)))).toContain(
      "DMARC_POLICY_REJECT",
    );
  });

  it("warns on missing rua and partial pct", () => {
    const raw = "v=DMARC1; p=reject; pct=50";
    const c = codes(validateDmarc([raw], parseDmarc(raw)));
    expect(c).toContain("DMARC_NO_RUA");
    expect(c).toContain("DMARC_PARTIAL_PCT");
  });

  it("flags missing DMARC", () => {
    expect(codes(validateDmarc([], null))).toContain("DMARC_MISSING");
  });

  it("flags sp=none leaving subdomains unprotected", () => {
    const raw = "v=DMARC1; p=reject; sp=none; rua=mailto:a@x.com";
    expect(codes(validateDmarc([raw], parseDmarc(raw)))).toContain(
      "DMARC_SUBDOMAIN_UNPROTECTED",
    );
  });
});

describe("DKIM parser", () => {
  it("parses a valid RSA key and estimates bit length", () => {
    // ~2048-bit key => base64 SPKI ~392 chars; use a representative length
    const p = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".repeat(12);
    const k = parseDkim("google", `v=DKIM1; k=rsa; p=${p}`)!;
    expect(k.keyType).toBe("rsa");
    expect(k.keyBits).toBeGreaterThanOrEqual(1024);
  });

  it("detects a revoked (empty p=) key", () => {
    const k = parseDkim("s1", "v=DKIM1; k=rsa; p=")!;
    expect(codes(validateDkim([k]))).toContain("DKIM_REVOKED");
  });

  it("flags missing DKIM when no selectors resolve", () => {
    expect(codes(validateDkim([]))).toContain("DKIM_MISSING");
  });

  it("flags a weak sub-1024-bit key", () => {
    const k = parseDkim("s1", "v=DKIM1; k=rsa; p=QUJD")!; // tiny key
    expect(codes(validateDkim([k]))).toContain("DKIM_WEAK_KEY");
  });

  it("does not misclassify a DMARC record as a DKIM key", () => {
    // Regression: DMARC records carry p= too and must be rejected.
    expect(parseDkim("_dmarc", "v=DMARC1; p=reject")).toBeNull();
  });
});

describe("MTA-STS and BIMI", () => {
  it("reports MTA-STS present", () => {
    const raw = "v=STSv1; id=20240101T000000";
    expect(codes(validateMtaSts([raw], parseMtaSts(raw)))).toContain(
      "MTASTS_PRESENT",
    );
  });

  it("treats missing MTA-STS as info, not fail", () => {
    const f = validateMtaSts([], null);
    expect(f[0]!.severity).toBe("info");
  });

  it("reports BIMI present with a logo", () => {
    const raw = "v=BIMI1; l=https://x.com/logo.svg";
    expect(codes(validateBimi([raw], parseBimi(raw)))).toContain("BIMI_PRESENT");
  });
});
