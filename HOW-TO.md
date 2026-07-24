# How-To — InboxArmor (Free)

Practical recipes for the `audit` command.

## Audit a domain

```bash
inboxarmor audit example.com
```

Prints a human-readable report: per-mechanism scores, findings, and a summary
of actions to take.

## Get JSON (for scripts / dashboards)

```bash
inboxarmor audit example.com --json
```

Emits the full `AuditResult` object — `score`, `grade`, per-mechanism `parsed`
records, and the flattened `findings` array. Pipe it anywhere:

```bash
inboxarmor audit example.com --json | jq '.score, .findings[].code'
```

## Probe a custom DKIM selector

DKIM selectors can't be discovered from DNS, so InboxArmor probes common ones.
If your provider uses a custom selector (e.g. Mailchimp's `k1`, a dated Google
selector, or your own), name it:

```bash
inboxarmor audit example.com --selectors k1,mail2024
```

## Use a specific DNS resolver

```bash
inboxarmor audit example.com --dns 1.1.1.1,8.8.8.8
# or persistently:
export INBOXARMOR_DNS_SERVERS=1.1.1.1
inboxarmor audit example.com
```

## Gate a CI pipeline on posture

The CLI sets a non-zero exit code when the grade is **F**, so you can fail a
build if a domain's email auth regresses badly:

```yaml
# .github/workflows/email-auth.yml
- run: node dist/cli/index.js audit ${{ vars.SENDING_DOMAIN }}
  # exit 2 (grade F) fails the job
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Audit completed, grade A–D |
| `2` | Audit completed, grade **F** |
| `4` | DNS infrastructure failure (not "record missing") |
| `1` | Unexpected error |

## Reading the report

- **SPF** — Is there exactly one record? Does it end in `-all`/`~all`? Does it
  stay under 10 DNS lookups? (Exceeding 10 silently breaks SPF.)
- **DKIM** — Were valid keys found for the probed selectors? Weak (<1024-bit) or
  revoked keys are flagged.
- **DMARC** — Is the policy `reject`/`quarantine` (not just `none`)? Is `pct=100`?
  Does `sp=none` leave subdomains exposed? Is a `rua=` report address set?
- **MTA-STS / BIMI** — Advisory. Nice-to-have TLS enforcement and brand logos.

## Want monitoring, alerts, and client reports?

Those live in Premium/Pro. See the upgrade table in [README.md](./README.md).
