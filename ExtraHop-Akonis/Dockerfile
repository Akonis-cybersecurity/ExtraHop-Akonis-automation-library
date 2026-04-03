ARG python_version=3.12
FROM python:${python_version}-slim AS builder

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock ./
COPY . /app/
RUN poetry config virtualenvs.in-project true && \
    poetry install --only main --no-root
RUN mv /app/.venv /.venv

FROM python:${python_version}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /.venv /.venv
COPY . /app

WORKDIR /app

ENV PATH="/.venv/bin:${PATH}"

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "main.py"]
