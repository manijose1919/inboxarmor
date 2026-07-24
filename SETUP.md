# Setup — InboxArmor (Free)

## Requirements

- **Node.js ≥ 20** (uses the built-in `node:dns` resolver — no external DNS service)
- npm

## Install & build

```bash
npm install      # installs commander + dev tooling
npm run build    # compiles TypeScript to ./dist
```

## Run

Directly from source (no build needed) during development:

```bash
npm run dev -- audit example.com
```

Or from the compiled output:

```bash
node dist/cli/index.js audit example.com
```

### Optional: install globally

```bash
npm run build
npm link                 # exposes `inboxarmor` on your PATH
inboxarmor audit example.com
```

## Scripts

| Script | Purpose |
|--------|---------|
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run dev` | Run the CLI from source via `tsx` |
| `npm test` | Run the test suite (Vitest) |
| `npm run test:watch` | Watch-mode tests |
| `npm run typecheck` | Type-check without emitting |

## Environment variables

| Variable | Effect |
|----------|--------|
| `INBOXARMOR_DNS_SERVERS` | Comma-separated custom DNS resolvers (e.g. `1.1.1.1,8.8.8.8`). Overridable per-run with `--dns`. |

## Verifying your install

```bash
npm test                       # should report all tests passing
node dist/cli/index.js audit google.com
```

If the audit prints a score and grade, you're ready.

## Troubleshooting

- **All lookups fail / timeouts** — check outbound DNS (UDP/TCP 53) is allowed,
  or pass a reachable resolver: `--dns 1.1.1.1`.
- **DKIM shows "not confirmed" for a domain you know signs mail** — it uses a
  custom selector. Pass it: `--selectors myselector`.
