FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN addgroup --system helpdesk && adduser --system --ingroup helpdesk helpdesk
WORKDIR /app
COPY pyproject.toml README.md ./
COPY helpdesktool ./helpdesktool
COPY agent_common ./agent_common
COPY linux_agent ./linux_agent
COPY alembic.ini ./
COPY migrations ./migrations
RUN pip install --no-cache-dir .
USER helpdesk
EXPOSE 8000
CMD ["uvicorn", "helpdesktool.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
