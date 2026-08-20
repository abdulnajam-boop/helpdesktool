# Dependency audit

Date: 2026-08-20 (Phase 22 of the governing roadmap; see
`docs/IMPLEMENTATION_PLAN.md`'s Milestone log for how this fits the
overall sequence). Companion documents: `docs/THIRD_PARTY_LICENSES.md`
(what license obligations each dependency actually carries) and
`docs/SOFTWARE_PROVENANCE.md` (where code in this repository actually
comes from, and what runtime code-fetching does and does not happen).

This document records what was actually run and what it actually
reported — not a static list copied from `pyproject.toml`/`package.json`.
Versions are the versions genuinely installed in this environment on the
date above; re-run the commands in each section to get current numbers
before trusting this as anything other than a point-in-time snapshot.

## 1. Backend (Python) — declared runtime dependencies

From `pyproject.toml`'s `[project.dependencies]`, with the actual
installed version and its real license (queried via
`importlib.metadata`'s `License-Expression` field, not guessed):

| Package | Constraint | Installed | License |
|---|---|---|---|
| alembic | `>=1.13,<2` | 1.19.1 | MIT |
| cryptography | `>=48.0.1,<51` | 50.0.0 | Apache-2.0 OR BSD-3-Clause (dual) |
| fastapi | `>=0.115,<1` | 0.141.1 | MIT |
| psycopg[binary] | `>=3.2,<4` | 3.3.4 | **LGPL-3.0-only** |
| prometheus-client | `>=0.20,<1` | 0.26.0 | Apache-2.0 AND BSD-2-Clause |
| pydantic-settings | `>=2.6,<3` | 2.15.0 | MIT |
| pyjwt[crypto] | `>=2.9,<3` | 2.13.0 | MIT |
| sqlalchemy | `>=2.0,<3` | 2.0.52 | MIT |
| uvicorn[standard] | `>=0.32,<1` | 0.52.3 | BSD-3-Clause |

`pyjwt[crypto]` and `uvicorn[standard]` each pull in their own
sub-dependency sets (`cryptography` again, `httptools`/`websockets`/
`uvloop`/`watchfiles` etc. for uvicorn's `standard` extra) — not
enumerated individually here since they're transitive, but covered by the
`pip-audit` sweep in section 3, which scans the full installed set.

**`psycopg` is LGPL-3.0-only — the one dependency here that isn't a
permissive MIT/BSD/Apache license.** This project does not modify
`psycopg`'s own source (it's used unmodified as installed from PyPI),
which is the normal, unencumbered case under LGPL — the obligations that
matter (making *modified* library source available) only trigger if
`psycopg` itself were patched and distributed. Recorded here so it's a
conscious, documented fact rather than something a future contributor
discovers by surprise.

## 2. Backend — optional dependency groups

`dev = ["httpx>=0.27,<1", "mypy>=1.13,<2", "pytest>=8,<10", "ruff>=0.8,<1"]`
— development/test/lint tooling only, never imported by `helpdesktool/`,
`linux_agent/`, or `windows_agent/` at runtime; not part of what ships in
the production Docker image (see `Dockerfile` — the runtime stage never
installs the `dev` extra).

| Package | Installed | License |
|---|---|---|
| httpx | 0.28.1 | BSD-3-Clause |
| mypy | 1.20.2 | MIT |
| pytest | 9.1.1 | MIT |
| ruff | 0.16.3 | MIT |

`windows = ["psutil>=6,<8", "pywin32>=306; sys_platform == \"win32\""]` —
see `CLAUDE.md`'s Windows agent section for why `psutil` is genuinely
cross-platform (installed and exercised on Linux CI too) while `pywin32`
is Windows-only via its `sys_platform` marker.

| Package | Installed | License |
|---|---|---|
| psutil | 7.2.2 | BSD-3-Clause |
| pywin32 | 312 | PSF-2.0 (Python Software Foundation License) |

## 3. Backend CVE scan (`pip-audit`)

Command run: `python -m pip_audit` against this environment's full
installed set (everything in section 1 and 2, plus every transitive
dependency).

**Result: zero known vulnerabilities in any dependency `pyproject.toml`
actually declares.** The only findings are six advisories against `pip`
25.0.1 itself (`PYSEC-2026-196`, `-1795`, `-1796`, `-2875`, `-2876`) —
`pip` is the packaging/installer tool used to *build* this environment,
not a runtime dependency the deployed application imports or ships;
it is not listed in `pyproject.toml` and does not appear in the built
Docker image's Python environment as an importable package the
application code touches. Recorded honestly rather than omitted, but not
a defect in this project's own dependency set.

This matches `docs/IMPLEMENTATION_PLAN.md`'s Milestone 6 record of the
real `cryptography` upper-bound regression `pip-audit` caught and the fix
that resolved it (`cryptography>=42,<46` → `>=48.0.1,<51`) — this section
reconfirms that fix is still holding as of this date, not re-discovering
it.

CI enforces this on every push/PR via `.github/workflows/ci.yml`'s
`security` job (`pip-audit` step) — this section is a manual point-in-time
re-verification, not a new check.

## 4. Frontend (npm) — declared dependencies

From `frontend/package.json`, with installed version and license queried
directly from each package's own `package.json` in `node_modules/`
(not assumed):

**Runtime (`dependencies` — what actually ships to the browser):**

| Package | Constraint | Installed | License |
|---|---|---|---|
| react | `^19.1.1` | 19.2.8 | MIT |
| react-dom | `^19.1.1` | 19.2.8 | MIT |

That's the entire runtime dependency footprint — two packages, both MIT,
both from the same well-known publisher (Meta/React core team). Worth
stating plainly: this is a deliberately minimal browser-shipped surface,
not an oversight — `frontend/src/main.tsx`'s single-file app has no
router, state-management, or UI-component-library dependency.

**Build/test tooling (`devDependencies` — never shipped to the browser):**

| Package | Constraint | Installed | License |
|---|---|---|---|
| @playwright/test | `^1.62.1` | 1.62.1 | Apache-2.0 |
| @types/react | `^19.1.10` | (types-only, no runtime code) | MIT |
| @types/react-dom | `^19.1.7` | (types-only, no runtime code) | MIT |
| @vitejs/plugin-react | `^5.0.2` | — | MIT |
| jsdom | `^30.0.1` | 30.0.1 | MIT |
| typescript | `^5.9.2` | 5.9.3 | Apache-2.0 |
| vite | `^7.1.3` | 7.3.6 | MIT |
| vitest | `^4.1.11` | 4.1.11 | MIT |

## 5. Frontend CVE scan (`npm audit`)

Command run: `npm audit --audit-level=high` in `frontend/`.

**Result: 0 vulnerabilities.** CI runs the identical command on every
push/PR (`.github/workflows/ci.yml`'s `security` job) — this is a manual
re-verification of the same gate, run on this date, not a new check.

## 6. Container base images

| Image | Used for | Tag pinned in |
|---|---|---|
| `python:3.13-slim` | backend builder + runtime stages | `Dockerfile` |
| `node:22-alpine` | frontend build stage | `frontend/Dockerfile` |
| `nginx:1.31-alpine` | frontend runtime stage | `frontend/Dockerfile` |
| `postgres:17` | database (Compose/CI) | `compose.yaml`, CI service container |

CI's `docker` job (`.github/workflows/ci.yml`) scans both built images
(API and frontend) with `trivy`, failing the build on any fixable
CRITICAL/HIGH finding — this is an existing, already-running gate (see
`CLAUDE.md`'s CI description), not new as of this pass.

## 7. What this audit did not (and could not) do

- **No SBOM (Software Bill of Materials) file was generated.** A
  machine-readable SBOM (CycloneDX/SPDX) is real, tractable future work
  (`docs/HELPDESK_MATURITY_GAP_ANALYSIS.md`'s P5 tier) — this document is
  a manually-compiled equivalent for the current dependency set, not a
  substitute for tooling that would stay current automatically as
  dependencies change.
- **No dependency-confusion / typosquatting review was performed** beyond
  confirming every declared package resolves to its expected, well-known
  publisher on PyPI/npm — a deeper supply-chain review (package-signing
  verification, reproducible-build verification) is out of scope for a
  point-in-time manual audit and is not claimed here.
- **License-compatibility legal analysis was not performed** by a
  qualified professional — section 1's LGPL-3.0 flag on `psycopg` is a
  factual note for future reviewers, not a legal opinion that this
  project's overall licensing posture is compliant for any particular
  use case or jurisdiction.
