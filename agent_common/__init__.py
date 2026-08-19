"""Shared, dependency-light primitives used by both endpoint agents
(``linux_agent``, ``windows_agent``) but never by the control plane's own
runtime request path.

This package intentionally depends on nothing beyond the standard library
and ``cryptography`` (already a transitive dependency via ``pyjwt[crypto]``)
so that installing either agent stays lightweight and independent of the
control plane's FastAPI/SQLAlchemy stack -- see ``CLAUDE.md``. The control
plane's own ``helpdesktool.job_signing`` imports the verification-side
primitives from here too, so "what bytes get signed" has exactly one
definition shared by the signer and every verifier.
"""
