# aifuzz image — Linux toolchain so Echidna / solc "just work" on any host.
FROM python:3.12-slim

ARG SOLC_VERSION=0.8.25
ARG ECHIDNA_VERSION=2.2.6
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 SOLC_VERSION=${SOLC_VERSION}

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates build-essential libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# solc version manager + crytic-compile (Echidna's compiler frontend).
# Version chosen at build time, not hardcoded in code.
RUN pip install solc-select crytic-compile \
    && solc-select install "${SOLC_VERSION}" \
    && solc-select use "${SOLC_VERSION}" \
    && solc --version

# Echidna (the fuzzer) — prebuilt release binary; version via build arg.
# Note: Anvil/Foundry are deferred to M5 (PoC exploits); the core fuzz loop
# runs in Echidna's own EVM and needs only solc + crytic-compile.
RUN curl -fsSL -o /tmp/echidna.tar.gz "https://github.com/crytic/echidna/releases/download/v${ECHIDNA_VERSION}/echidna-${ECHIDNA_VERSION}-x86_64-linux.tar.gz" \
    && tar -xzf /tmp/echidna.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/echidna \
    && rm /tmp/echidna.tar.gz \
    && echidna --version

WORKDIR /app
COPY . /app
RUN pip install -e ".[dev]"

# Default: serve the dashboard. Override to run the CLI or fuzz.
CMD ["python", "dashboard/app.py"]
