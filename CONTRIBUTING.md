# Contributing to InboxArmor

Thanks for your interest in improving InboxArmor! This is the open-source **Free
core** — a standalone SPF/DKIM/DMARC/MTA-STS/BIMI auditor. Contributions of all
kinds are welcome: bug reports, new checks, better remediation copy, docs, and
tests.

> The Premium/Pro tiers (monitoring, alerts, reports, API) live in a separate
> proprietary repository and are **not** part of this project. Please keep
> contributions here focused on the free auditing core.

## Ways to contribute

- **Report a bug** — open an issue with the domain/record that reproduces it and
  what you expected. Redact anything sensitive.
- **Improve a check** — more accurate SPF/DKIM/DMARC validation, new RFC edge
  cases, clearer plain-English findings.
- **Add a check** — a new mechanism or a new finding, with tests.
- **Docs** — fixes and clarifications to `README.md`, `SETUP.md`, `HOW-TO.md`.

## Development setup

Requires **Node.js ≥ 20** and npm.

```bash
git clone https://github.com/manijose1919/inboxarmor.git
cd inboxarmor
npm install
npm test          # run the suite
npm run dev -- audit example.com   # run the CLI from source
```

| Script | Purpose |
|--------|---------|
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run dev` | Run the CLI from source via `tsx` |
| `npm test` | Run the Vitest suite |
| `npm run test:watch` | Watch-mode tests |
| `npm run typecheck` | Type-check without emitting |

## Architecture in 60 seconds

The engine is organized so parsing logic is pure and testable in isolation:

- `src/core/dns/resolver.ts` — the `DnsResolver` **seam**. Nothing else calls
  `node:dns` directly.
- `src/core/parsers/*` — **pure functions**: `parse*` turns a raw record into
  structure; `validate*` turns structure into `Finding[]`. No I/O.
- `src/core/scoring/scorer.ts` — weighted score + grade.
- `src/core/audit.ts` — `AuditEngine`, the single place DNS lookups fan out.
- `src/core/report/reporter.ts` — text + JSON rendering.

Because DNS access is behind an interface, tests inject `StaticDnsResolver` with
fixture records — the whole suite runs **offline and deterministically, with no
network**. Please preserve this: new logic should be reachable in tests without
real DNS.

## Making a change

1. **Fork** the repo and create a branch: `git checkout -b fix/spf-redirect-count`.
2. Make your change. Keep parsers pure — do DNS/orchestration only in `audit.ts`.
3. **Add or update tests** in `tests/`. New findings need a test asserting the
   finding `code`; parser changes need a case covering the RFC behavior.
4. Ensure the gates pass locally:
   ```bash
   npm run typecheck && npm test
   ```
5. Match the surrounding style — the codebase runs TypeScript `strict` with
   `noUncheckedIndexedAccess`; avoid `any`, prefer explicit types on exports.
6. **Open a pull request** describing the change and the motivation. Link any
   related issue. Keep PRs focused — one logical change per PR.

## Finding conventions

Findings are the product's value, so consistency matters:

- `code` is a stable, uppercase, mechanism-prefixed identifier
  (e.g. `SPF_TOO_MANY_LOOKUPS`, `DMARC_POLICY_NONE`). Don't rename existing codes
  without reason — downstream users may alert on them.
- `severity` is one of `pass | info | warn | fail`. Use `info` for advisory-only
  items that must **not** lower the score (e.g. optional MTA-STS/BIMI).
- `warn`/`fail` findings should include a concrete, actionable `remediation`.
- `pass`/`info` findings should **not** carry remediation.

## Reporting security issues

If you find a security issue in the auditing logic (e.g. a way to make the tool
report a spoofable domain as safe), please **do not** open a public issue.
Report it privately to `security@inboxarmor.example`.

## Code of conduct

Be respectful and constructive. Assume good intent, keep discussion technical,
and help newcomers. Harassment of any kind is not tolerated.

## License

By contributing, you agree that your contributions will be licensed under the
project's [MIT License](./LICENSE).
