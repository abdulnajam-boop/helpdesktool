FROM python:3.13-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY helpdesktool ./helpdesktool
COPY agent_common ./agent_common
COPY linux_agent ./linux_agent
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir . \
    # pip/setuptools/wheel are only needed to install the app, never to run
    # it -- removing them drops their own vulnerable transitive footprint
    # (e.g. pip's vendored msgpack, an old bundled setuptools) from the
    # runtime image entirely. Console scripts (uvicorn, alembic,
    # helpdesk-seed, etc.) are plain files with a venv-python shebang and
    # keep working without pip present.
    && /opt/venv/bin/pip uninstall -y pip setuptools wheel

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:${PATH}"
# Pulls in upstream Debian security fixes for base-image OS packages
# (util-linux/bsdutils/etc.) that python:3.13-slim was built against, not
# just what pip installs -- trivy scans the whole image, not just the
# Python dependency tree.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
# python:3.13-slim itself preinstalls pip at /usr/local -- distinct from
# and in addition to the builder stage's venv pip already removed above.
# pip vendors its own copies of setuptools (as pkg_resources) and msgpack
# internally (see its vendor.txt), which is exactly what CVE-2025-47273
# and GHSA-6v7p-g79w-8964 were flagging here even after the venv was
# already clean. Nothing at runtime needs this system pip.
RUN python -m pip uninstall -y pip 2>/dev/null || true
RUN addgroup --system helpdesk && adduser --system --ingroup helpdesk helpdesk
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini ./
COPY migrations ./migrations
USER helpdesk
EXPOSE 8000
CMD ["uvicorn", "helpdesktool.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
