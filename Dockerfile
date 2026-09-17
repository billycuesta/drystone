# syntax=docker/dockerfile:1
#
# Reproducible Drystone distribution image (P3: Dockerfile for reproducible
# distribution). Multi-stage: a builder installs the package into a throwaway
# prefix, the runtime stage only carries the installed files plus the shared
# libraries weasyprint needs at runtime for PDF report generation.
#
# Build:
#   docker build -t drystone .
#
# Run (non-interactive; the wizard's interactive prompts don't fit a
# container well -- pass config via CLI flags/env vars instead):
#   docker run --rm \
#     -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... \
#     -e ANTHROPIC_API_KEY=... \
#     -v "$(pwd)/audit-logs:/data/audit-logs" \
#     drystone audit --client "ACME" --region us-east-1 --skills iam \
#       --formats markdown --non-interactive
#
# Recommended inside a container: --ai-provider is not a real audit flag
# today (see WizardConfig.ai_provider), so set claude-api explicitly via a
# saved config or a future --ai-provider flag; the interactive `claude` CLI
# provider doesn't make sense in an unattended container.

FROM python:3.11-slim AS builder

WORKDIR /build

# weasyprint (the `pdf` extra) needs Cairo/Pango/GDK-Pixbuf headers to build
# its own dependencies' wheels on some platforms.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libcairo2-dev \
        libpango1.0-dev \
        libgdk-pixbuf-2.0-dev \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY drystone/ ./drystone/

RUN pip install --no-cache-dir --prefix=/install ".[pdf,llm]"

FROM python:3.11-slim AS runtime

# Runtime-only counterparts of the builder's dev libraries, needed by
# weasyprint to actually render PDFs (no compiler needed here).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN useradd --create-home --uid 1000 drystone
WORKDIR /data
RUN chown drystone:drystone /data
USER drystone
ENV HOME=/home/drystone

ENTRYPOINT ["drystone"]
CMD ["--help"]
