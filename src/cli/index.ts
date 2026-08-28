#!/usr/bin/env node
/**
 * InboxArmor (Free) CLI — standalone email-authentication auditor.
 *
 * This is the complete open-source core: a single `audit` command with no paid
 * modules present. It imports only from ./core, demonstrating that the free
 * tier is a fully independent application.
 */

import { Command } from "commander";
import { NodeDnsResolver } from "../core/dns/resolver.js";
import { AuditEngine } from "../core/audit.js";
import { renderJson, renderText } from "../core/report/reporter.js";
import { DnsLookupError, InvalidDomainError } from "../core/types.js";

const program = new Command();

program
  .name("inboxarmor")
  .description("Email authentication & deliverability auditor (SPF/DKIM/DMARC) — Free")
  .version("0.1.0");

program
  .command("audit", { isDefault: true })
  .description("Audit a single domain's email-authentication posture")
  .argument("<domain>", "domain to audit, e.g. example.com")
  .option("--json", "output machine-readable JSON", false)
  .option(
    "-s, --selectors <list>",
    "comma-separated DKIM selectors to probe",
    (v) => v.split(",").map((s) => s.trim()).filter(Boolean),
  )
  .option(
    "--dns <servers>",
    "comma-separated custom DNS resolvers",
    (v) => v.split(",").map((s) => s.trim()).filter(Boolean),
  )
  .action(async (domain: string, opts: { json: boolean; selectors?: string[]; dns?: string[] }) => {
    const servers =
      opts.dns ??
      (process.env["INBOXARMOR_DNS_SERVERS"]
        ? process.env["INBOXARMOR_DNS_SERVERS"].split(",").map((s) => s.trim())
        : undefined);
    const engine = new AuditEngine(new NodeDnsResolver(servers));
    const result = await engine.audit(domain, {
      ...(opts.selectors ? { selectors: opts.selectors } : {}),
    });
    process.stdout.write((opts.json ? renderJson(result) : renderText(result)) + "\n");
    process.exitCode = result.grade === "F" ? 2 : 0;
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  if (err instanceof InvalidDomainError) {
    process.stderr.write(`\n✖ ${err.message}\n`);
    process.exitCode = 2;
  } else if (err instanceof DnsLookupError) {
    process.stderr.write(`\n✖ ${err.message}\n`);
    process.exitCode = 4;
  } else {
    process.stderr.write(`\n✖ Unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
});
