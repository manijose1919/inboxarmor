# InboxArmor (Free)

**Audit any domain's email-authentication posture in seconds.** InboxArmor
checks SPF, DKIM, DMARC, MTA-STS, and BIMI, scores your deliverability, and
tells you — in plain English — exactly what to fix.

Bad email authentication is why legitimate mail lands in spam and why anyone can
spoof your domain. Since Google and Yahoo's 2024 bulk-sender rules, getting this
right is mandatory. InboxArmor makes it a one-command check.

```
$ inboxarmor audit example.com
```

```
============================================================
  InboxArmor — Email Authentication Audit
  Domain: example.com
  Score:  95/100   Grade: A
============================================================

[SPF]  100/100
   PASS: SPF ends with "-all" (hard fail) — strong protection.
[DKIM]  75/100
   WARN: DKIM could not be confirmed for any of the probed selectors...
[DMARC]  100/100
   PASS: "p=reject" blocks spoofed mail outright — strongest DMARC posture.
...
```

## What the Free tier does

- ✅ Full audit of **any single domain**, on demand
- ✅ **SPF** — syntax, the 10-DNS-lookup limit, `all` qualifier strength, multi-record errors
- ✅ **DKIM** — probes common selectors, detects revoked/weak keys (custom selectors via `--selectors`)
- ✅ **DMARC** — policy strength, `pct`, `sp` subdomain gaps, missing aggregate reporting
- ✅ **MTA-STS** and **BIMI** advisory checks
- ✅ Weighted **0–100 score + A–F grade**
- ✅ Plain-English remediation for every issue
- ✅ `--json` output and CI-friendly exit codes (grade F → exit 2)
- ✅ 100% local — no account, no data leaves your machine, no paid DNS API

## Quick start

```bash
npm install          # install dependencies
npm run build        # compile
node dist/cli/index.js audit yourdomain.com
```

See [SETUP.md](./SETUP.md) for details and [HOW-TO.md](./HOW-TO.md) for usage recipes.

## Upgrade to Premium / Pro

The Free tier audits one domain at a time. When you need to **watch** posture
over time, get **alerted** on regressions, or hand **branded reports** to
clients, upgrade:

| | Free | Premium — $29/mo | Pro — $119/mo |
|---|---|---|---|
| Single-domain audit | ✅ | ✅ | ✅ |
| Continuous monitoring | — | ✅ up to 25 domains | ✅ unlimited |
| Drift alerts (Slack / webhook / PagerDuty / Datadog) | — | ✅ | ✅ |
| AI-powered remediation assistant | — | — | ✅ |
| DMARC aggregate (RUA) parsing + trend analysis | — | — | ✅ |
| Active MTA-STS & BIMI validation | — | — | ✅ |
| White-label PDF reports | — | — | ✅ |
| Multi-client workspaces | — | — | ✅ |
| REST API + GitHub Action | — | — | ✅ |

Learn more at **inboxarmor.example** or contact **sales@inboxarmor.example**.

## License

MIT — see [LICENSE](./LICENSE). Use it, fork it, ship it.
