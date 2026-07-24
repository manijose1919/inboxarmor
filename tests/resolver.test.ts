import { describe, it, expect, vi } from "vitest";
import {
  NodeDnsResolver,
  StaticDnsResolver,
} from "../src/core/dns/resolver.js";
import { DnsLookupError } from "../src/core/types.js";

describe("StaticDnsResolver", () => {
  it("returns seeded TXT records case-insensitively", async () => {
    const r = new StaticDnsResolver({ "example.com": ["v=spf1 -all"] });
    expect(await r.resolveTxt("EXAMPLE.com")).toEqual(["v=spf1 -all"]);
  });

  it("returns empty array for unknown hosts", async () => {
    const r = new StaticDnsResolver();
    expect(await r.resolveTxt("nothing.test")).toEqual([]);
    expect(await r.resolveMx("nothing.test")).toEqual([]);
  });
});

describe("NodeDnsResolver", () => {
  it("concatenates multi-chunk TXT character-strings", async () => {
    const r = new NodeDnsResolver();
    // @ts-expect-error accessing private for a focused unit test
    r.resolver.resolveTxt = vi.fn().mockResolvedValue([["v=DKIM1; ", "p=abc"]]);
    expect(await r.resolveTxt("sel._domainkey.example.com")).toEqual([
      "v=DKIM1; p=abc",
    ]);
  });

  it("maps ENOTFOUND to an empty result, not an error", async () => {
    const r = new NodeDnsResolver();
    // @ts-expect-error accessing private for a focused unit test
    r.resolver.resolveTxt = vi.fn().mockRejectedValue(
      Object.assign(new Error("not found"), { code: "ENOTFOUND" }),
    );
    expect(await r.resolveTxt("missing.example.com")).toEqual([]);
  });

  it("trims whitespace padded onto assembled TXT strings", async () => {
    const r = new NodeDnsResolver();
    // @ts-expect-error accessing private for a focused unit test
    r.resolver.resolveTxt = vi.fn().mockResolvedValue([["  v=spf1 -all  "]]);
    expect(await r.resolveTxt("example.com")).toEqual(["v=spf1 -all"]);
  });

  it("times out a hung lookup as a DnsLookupError", async () => {
    const r = new NodeDnsResolver(undefined, 20);
    // @ts-expect-error accessing private for a focused unit test
    r.resolver.resolveTxt = vi.fn(() => new Promise(() => {})); // never resolves
    await expect(r.resolveTxt("hung.example.com")).rejects.toBeInstanceOf(
      DnsLookupError,
    );
  });

  it("wraps genuine failures in DnsLookupError", async () => {
    const r = new NodeDnsResolver();
    // @ts-expect-error accessing private for a focused unit test
    r.resolver.resolveTxt = vi.fn().mockRejectedValue(
      Object.assign(new Error("server failure"), { code: "SERVFAIL" }),
    );
    await expect(r.resolveTxt("broken.example.com")).rejects.toBeInstanceOf(
      DnsLookupError,
    );
  });
});
