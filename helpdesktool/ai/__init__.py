"""Provider-neutral AI diagnosis: advisory only, never self-authorizing.

See ``helpdesktool.ai.provider`` for the trust model in detail. In one
sentence: an AI provider may only ever produce data an operator reviews and
a human still has to explicitly submit through the existing
policy/approval/execution pipeline (``POST /v1/actions``) — it can never
itself create, approve, or execute anything.
"""
