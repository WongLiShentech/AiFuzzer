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
    && solc-select install 0.4.26 \
    && solc-select use "${SOLC_VERSION}" \
    && solc --version

# Echidna (the fuzzer) — prebuilt release binary; version via build arg.
# The core fuzz loop runs in Echidna's own EVM and needs only solc + crytic-compile.
RUN curl -fsSL -o /tmp/echidna.tar.gz "https://github.com/crytic/echidna/releases/download/v${ECHIDNA_VERSION}/echidna-${ECHIDNA_VERSION}-x86_64-linux.tar.gz" \
    && tar -xzf /tmp/echidna.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/echidna \
    && rm /tmp/echidna.tar.gz \
    && echidna --version

# Foundry — provides `anvil`, the local blockchain node used to deploy contracts
# and run transactions against them (deliverable #2 + PoC exploits).
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup && anvil --version

WORKDIR /app
COPY . /app
# `static` adds Slither — used for AST/semantic shape detection (synthesize.py),
# a robust upgrade from regex. Detection falls back to regex if Slither is absent.
# `ai` adds chromadb + ollama for the RAG retrieval / AI-guided generation (M3).
RUN pip install -e ".[dev,chain,static,ai]"

# Default: serve the dashboard. Override to run the CLI or fuzz.
CMD ["python", "dashboard/app.py"]
