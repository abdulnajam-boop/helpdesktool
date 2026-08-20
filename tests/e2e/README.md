# Browser end-to-end tests

Real-browser smoke test against the actual production Docker images (API +
nginx-served frontend build), not a dev server and not jsdom. Requires only
Docker.

```bash
bash tests/e2e/run.sh
```

This builds both images, starts a throwaway Postgres + API + frontend on an
isolated Docker network, seeds one tenant/device/incident through the real
HTTP API, runs `browser_e2e.mjs` inside the official Playwright container
against the running frontend, and tears everything down on exit (success or
failure). Screenshots and a `results.json` land in `tests/e2e/out/`
(gitignored).

Not wired into CI (needs Docker-in-Docker or a dedicated runner) — run it
manually before a release, and any time frontend routing/data-fetching
changes. It exists specifically because neither the SQLite-backed pytest
suite nor the Vitest/jsdom suite can catch a bug that only manifests in the
browser's real render/effect loop — see `browser_e2e.mjs`'s header comment
for the real bug (an infinite fetch loop on the Reports page) this caught
on its first run.
