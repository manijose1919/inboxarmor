/**
 * Rendering of an {@link AuditResult} into human- or machine-readable output.
 * No I/O — returns strings the CLI (or any module) writes wherever it likes.
 */

import type { AuditResult, MechanismReport, Severity } from "../types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  pass: "PASS",
  info: "INFO",
  warn: "WARN",
  fail: "FAIL",
};

const MECHANISM_LABEL: Record<string, string> = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  mtaSts: "MTA-STS",
  bimi: "BIMI",
};

/** JSON output — stable, machine-consumable, pretty-printed. */
export function renderJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

/** Plain-text report suitable for a terminal or a log. */
export function renderText(result: AuditResult): string {
  const lines: string[] = [];
  lines.push("=".repeat(60));
  lines.push(`  InboxArmor — Email Authentication Audit`);
  lines.push(`  Domain: ${result.domain}`);
  lines.push(`  Score:  ${result.score}/100   Grade: ${result.grade}`);
  lines.push(`  Time:   ${result.timestamp}`);
  lines.push("=".repeat(60));

  for (const key of ["spf", "dkim", "dmarc", "mtaSts", "bimi"] as const) {
    lines.push("");
    lines.push(renderMechanism(MECHANISM_LABEL[key]!, result.mechanisms[key]));
  }

  lines.push("");
  lines.push("-".repeat(60));
  const actionable = result.findings.filter(
    (f) => f.severity === "warn" || f.severity === "fail",
  );
  if (actionable.length === 0) {
    lines.push("  No action required — posture looks strong. ✔");
  } else {
    lines.push(`  ${actionable.length} issue(s) to address:`);
    for (const f of actionable) {
      lines.push(`   • [${SEVERITY_LABEL[f.severity]}] ${f.message}`);
      if (f.remediation) lines.push(`       Fix: ${f.remediation}`);
    }
  }
  lines.push("-".repeat(60));
  return lines.join("\n");
}

function renderMechanism(label: string, m: MechanismReport): string {
  const lines: string[] = [];
  const status = m.present ? `${m.score}/100` : "not found";
  lines.push(`[${label}]  ${status}`);
  for (const f of m.findings) {
    lines.push(`   ${SEVERITY_LABEL[f.severity]}: ${f.message}`);
    // `pass`/`info` findings legitimately have no remediation — render nothing.
    if (f.remediation) lines.push(`      → ${f.remediation}`);
  }
  return lines.join("\n");
}
