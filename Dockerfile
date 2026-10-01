FROM python:3.12.14-slim

# uv is copied from its official image instead of pip-installed: one pinned
# binary, no extra layer of Python tooling.
COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Dependencies first, so code changes don't reinstall them.
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-dev --no-install-project

COPY radar ./radar
RUN uv sync --no-dev

EXPOSE 8000
CMD ["uvicorn", "radar.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
