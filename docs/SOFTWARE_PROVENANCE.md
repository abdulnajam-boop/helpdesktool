# Software provenance

Date: 2026-08-20 (Phase 22 of the governing roadmap). Companion to
`docs/DEPENDENCY_AUDIT.md` (versions/CVEs) and
`docs/THIRD_PARTY_LICENSES.md` (license obligations). This document
answers two specific questions the roadmap asks for directly: **where
does the code in this repository actually come from**, and **does
anything in this system fetch and execute arbitrary remote code at
runtime** — the second being a direct safety question, not just a
supply-chain hygiene one, given this project's core invariant that no
input (chat message, AI suggestion, ticket text) can ever become an
arbitrary executable command.

## 1. First-party code

Everything under `helpdesktool/`, `linux_agent/`, `windows_agent/`,
`agent_common/`, `frontend/src/`, `migrations/`, and `tests/` is authored
directly in this repository — none of it is vendored, copy-pasted, or
generated from another project's source. Ownership of this first-party
code is exactly what it appears to be: it belongs to whoever owns this
repository, under the license `pyproject.toml` declares (Apache-2.0 —
see `docs/THIRD_PARTY_LICENSES.md`'s note on the missing `LICENSE` file).

**Being explicit about a boundary the roadmap specifically calls out:**
using a third-party open-source package (FastAPI, SQLAlchemy, React, ...)
does not make that package's code "exclusively owned" by this project —
each remains the property of its own upstream authors under its own
license (see `docs/THIRD_PARTY_LICENSES.md`), consumed here as an
unmodified, declared dependency. This project has never claimed otherwise
anywhere in its code or documentation, and this document exists partly to
make that boundary explicit rather than assumed.

## 2. Third-party code: how it enters this codebase

Every third-party capability is consumed exactly one way: as a versioned
package declared in `pyproject.toml` (backend) or
`frontend/package.json` (frontend), installed from the official public
registry (PyPI, npm) by `pip`/`npm` at build/install time. There is no
mechanism anywhere in this codebase that downloads a third-party
package's source ad hoc, patches it in place, or embeds a third-party
file directly into a first-party module without that dependency being
declared. `docs/DEPENDENCY_AUDIT.md` enumerates exactly what's declared
and what version/license each resolves to.

## 3. The one place this project fetches its own code from a URL at
   install time — and why it's different from what the roadmap warns
   against

`deploy/install-linux-agent.sh`'s default `--package-source` installs the
Linux agent via `pip install git+https://...` pointing at **this
repository's own default branch** — because, as the script's own comment
states, there is no published PyPI/private-index release yet. This *is*
fetching code from GitHub at install time, and it is called out here
deliberately rather than glossed over.

**Why this is not the "arbitrary remote code execution" the roadmap's
Phase 1/7 safety invariants are actually concerned with:** the safety
invariant those phases protect is that no *untrusted, dynamically-chosen*
input — a chat message, an AI-generated suggestion, a ticket description,
a piece of "knowledge" — can ever become code that executes on an
endpoint. Installing this project's own, single, fixed, human-reviewed
Git ref (the default branch, chosen by whoever runs the installer, not by
any request-time input) is a conventional software-installation step, not
a dynamic remote-code-execution path — no request ever handled by the
control plane, no AI provider response, and no chat message can influence
*what* gets installed or *when*. It's also already self-documented as a
demo/pilot-only default in the script's own comments, with the explicit
recommendation to pin a reviewed wheel/sdist for a real fleet rollout —
this document doesn't add a new caveat, it just surfaces the existing one
here where a provenance audit will actually find it.

`deploy/install-windows-agent.ps1` and every other installer/deployment
script in `deploy/` were checked the same way (`grep` for
`curl`/`wget`/`Invoke-WebRequest`/`git clone` across the directory) —
none of the others fetch anything from a URL at all.

## 4. Runtime: nothing fetches and executes remote code

Checked directly (`grep` across `helpdesktool/`, `linux_agent/`,
`windows_agent/`, `agent_common/` for any HTTP client call), every
network call this system's own runtime code makes falls into one of
exactly three categories, none of which is "fetch code and execute it":

1. **Structured API calls between this system's own components** —
   `linux_agent/client.py`/`windows_agent/client.py`'s `ControlPlaneClient`
   talks to this project's own control plane over its own versioned,
   signed-envelope job protocol (`agent_common/signing.py`,
   `helpdesktool/job_signing.py`); `helpdesktool/integrations.py`'s
   webhook delivery POSTs a signed, structured JSON payload to a
   tenant-configured URL (SSRF-guarded — see its module docstring); none
   of these ever fetch a response and hand it to `exec`/`eval`/a
   subprocess.
2. **The advisory AI provider call** — `helpdesktool/ai/provider.py`'s
   `OpenAICompatibleProvider` POSTs to a configured `/chat/completions`
   endpoint and parses the response as *structured diagnostic text*
   (`suggested_skill_id`/rationale), validated against the real skill
   registry inside the provider before it's trusted at all (see that
   module's docstring) — the response is never treated as code, a
   command, or a script, in any form, at any point.
3. **The endpoint agent's own inventory collection** — read-only local
   `/proc` reads (Linux) or `psutil`/`winreg` calls (Windows), never a
   network fetch at all.

**There is no code path anywhere in this repository — control plane,
either agent, or the frontend — that takes a piece of dynamically
obtained content (an AI response, a webhook payload, a chat message, a
"knowledge" record) and executes it as a shell command, script, or
imported module.** The only thing that ever executes on an endpoint is a
fixed, hardcoded executor function selected by an exact, allowlisted
`skill_id` string match (`linux_agent/executor.py`/
`windows_agent/executor.py`) — see `CLAUDE.md`'s "Data flow / safety
invariants to preserve" section, which this provenance check reconfirms
rather than newly establishes.

## 5. What this audit did not do

- Did not independently re-derive or verify the cryptographic checksum of
  every installed package against its registry-published hash beyond
  what `pip`/`npm`'s own installers already verify during install — a
  deeper supply-chain attestation (Sigstore/in-toto style) is real,
  separate future work.
- Did not audit the *build infrastructure* GitHub Actions itself runs on
  (runner images, Actions marketplace actions this repo's own workflows
  reference) — `.github/workflows/ci.yml`'s own action references
  (`actions/checkout`, `gitleaks-action`, etc.) are widely-used, official/
  verified-publisher actions, but a formal review of their own supply
  chain is out of scope here.
