"""Echidna fuzzing engine — the core analysis engine.

Runs Echidna against a contract in one of two modes:
  * "random"     — stock coverage-guided random fuzzing (the baseline).
  * "ai-guided"  — properties + seed sequences from aifuzz.ai_guidance (the experiment).

The headline result of the project is the comparison between these two modes
(coverage reached, vulnerabilities found). Echidna runs inside the Linux
container (see Dockerfile) so it works regardless of host OS.

Status: random mode implemented (M2). AI-guided mode = M3.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .config import settings
from .report import Finding, Severity

# Echidna prints one line per property in its summary. The wording varies:
#   echidna_owner_is_deployer: failed!           (a violation, with a Call sequence)
#   echidna_no_reentrancy_theft: failed with no transactions made 
#   echidna_count_within_bound: passing            (held — present tense when ALL pass)
#   echidna_x: passed!                             (held — past tense in other runs)
# We match pass*/fail* so a clean contract ("passing") is recognised as a real
# result, not mistaken for "no properties evaluated".
_RESULT_RE = re.compile(r"^(\w+):\s*(pass(?:ed|ing)|fail(?:ed|ing))\b")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
# Echidna status lines carry `cov: N` — the count of unique code points reached.
_COV_RE = re.compile(r"cov:\s*(\d+)")

# Every echidna_ invariant this project's harness synthesiser can emit (aifuzz/synthesize.py),
# mapped to the vulnerability class an examiner or dashboard user actually asks about. Without
# this, a finding's title is just the raw property name (`echidna_no_theft`), which is meaningless
# to anyone who hasn't read the harness -- observed directly in a demo, where a genuine
# tx.origin/access-control exploit showed no indication of its vulnerability class anywhere in
# the UI. `echidna_no_theft` covers BOTH unguarded senders and tx.origin-guarded-only senders
# (a guard trivially satisfiable by the caller), both of which are access-control weaknesses.
# Every echidna_ oracle the synthesiser can emit, mapped to ONE of the project's four in-scope
# vulnerability classes (EEA EthTrust v3). A finding is always reported as a named class -- never
# a bare "vulnerable" -- because the class is what a reader acts on. Selfdestruct is reported as
# Access Control, which is what it is: an unauthorised caller reaching a privileged operation.
_REENTRANCY = "Reentrancy"
_ACCESS = "Access Control"
_ORACLE = "Oracle Manipulation"
_ORDERING = "Ordering Attack (TOD)"

_ORACLE_CLASS = {
    "echidna_no_value_extraction": (_REENTRANCY,
        "the contract paid out more value than it had received, consistent with a re-entrant "
        "withdrawal draining funds before its own balance update took effect"),
    "echidna_no_reentrancy_theft": (_REENTRANCY,
        "an attacker re-entered the withdrawal path and extracted more than it deposited"),
    "echidna_no_theft": (_ACCESS,
        "a function with no authorization check, or one guarded only by a caller-supplied "
        "tx.origin comparison, allowed an attacker to drain ether it never deposited or earned"),
    "echidna_owner_unchanged": (_ACCESS,
        "a non-owner caller successfully changed contract ownership"),
    "echidna_owner_retained": (_ACCESS,
        "a non-owner caller successfully seized a privileged role"),
    "echidna_not_destroyed": (_ACCESS,
        "an unauthorised caller reached selfdestruct and destroyed the contract"),
    "echidna_price_solvent": (_ORACLE,
        "an unguarded price/reference update broke a solvency invariant the contract itself declares"),
    "echidna_reward_not_stolen": (_ORDERING,
        "an account that never contributed claimed the reward, so the outcome depends on the "
        "order transactions are executed in"),
}

# Contracts that ship their OWN echidna_ invariant (dataset harnesses, CTF challenges) violate a
# property name this project never generated, so it cannot be mapped from a table. Classify those
# by what the property name says about the shape it guards -- checked in order, first match wins.
_NAME_CLASS_HINTS = (
    (re.compile(r"reentran|re_ent|reenter", re.I), _REENTRANCY),
    (re.compile(r"price|oracle|quote|solven|collater|leverage|margin|redeem|ltv|feed"
                r"|loan|credit|backed|vote|bounded|covered", re.I), _ORACLE),
    (re.compile(r"order|front.?run|\btod\b|sequence|race|first|winner|claim", re.I), _ORDERING),
    (re.compile(r"owner|admin|auth|access|privile|role|destroy|suicide|kill|withdraw|drain|balance|theft|steal|fund",
                re.I), _ACCESS),
)


def _classify_invariant(name: str) -> tuple[str, str] | None:
    """Vulnerability class for a violated echidna_ property. Uses the exact map first, then falls
    back to the property NAME for contracts carrying their own oracle. Returns None only when the
    name carries no usable signal -- the caller then reports the raw property rather than guessing
    a class, since a wrong class is worse than an unclassified one."""
    hit = _ORACLE_CLASS.get(name)
    if hit:
        return hit
    for pat, cls in _NAME_CLASS_HINTS:
        if pat.search(name):
            return (cls, f"the contract's own invariant `{name}` was falsified by a generated "
                         f"transaction sequence, and the property it guards is characteristic of "
                         f"this class")
    return None


def _solc_for_pragma(contract_path: str) -> str | None:
    """Pick an installed solc matching the file's pragma. solc-select honours the
    SOLC_VERSION env var per run, so old dataset contracts compile without
    changing the global default; the fuzzer self-heals (installs) a missing one.

    Handles the legacy 0.4.x line two ways:
      * an exact pin (`pragma solidity 0.4.24;`) -> that precise version, because
        a non-range pragma rejects any other compiler;
      * a caret/range (`^0.4.2`, `>=0.4.0 <0.5.0`) -> the newest 0.4 we ship.
    A 0.8.x (or anything else) pragma falls through to the image default."""
    try:
        text = open(contract_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = _PRAGMA_RE.search(text)
    if not m:
        return None
    spec = m.group(1).strip()
    # Resolve with the SAME logic the harness synthesiser uses to decide which syntax to emit.
    # The previous substring test ("0.4" in spec -> 0.4.26) mis-read upper-bounded ranges like
    # `>=0.4.22 <0.6.0`, where 0.5.x is valid and the synthesiser targets 0.5.17: the harness was
    # written with 0.5 syntax (`address payable`) but handed to solc 0.4, so every such contract
    # failed to compile and Echidna reported "no properties".
    try:
        from .synthesize import _resolve_solc
        return "{}.{}.{}".format(*_resolve_solc(spec))
    except Exception:
        if re.fullmatch(r"0\.4\.\d+", spec):
            return spec
        return "0.4.26" if "0.4" in spec else None


class EchidnaFuzzer:
    def __init__(self, mode: str = "random") -> None:
        if mode not in ("random", "ai-guided", "ai-seed", "ai-seed-cot"):
            raise ValueError(f"unknown mode: {mode!r}")
        self.mode = mode
        self.test_limit = settings.echidna_test_limit  # configurable, not hardcoded
        self.coverage: int | None = None    # unique code points Echidna reached (last run)
        self.elapsed: float | None = None   # wall-clock seconds of the last run

    def _run_in_docker(self, contract_path: str, contract: str | None,
                       config: str | None, seeds: list | None) -> list[Finding]:
        """Run Echidna inside the compose service on a staged copy of the harness.

        The harness and its target are copied into a scratch directory under the repo (which is
        bind-mounted into the container), so the container sees exactly the files the host wrote.
        SOLC_VERSION is exported rather than `solc-select use`d because crytic-compile only
        honours the env var; without it every old-pragma harness silently compiles with 0.8.x."""
        root = Path(__file__).resolve().parent.parent
        svc = os.getenv("AIFUZZ_DOCKER_SVC", "aifuzz")
        # Unique staging dir per run. A single fixed path was rmtree'd at the start of every
        # run, so two overlapping runs (dashboard click + batch scan, or any concurrent
        # request) deleted each other's config.yaml -- Echidna then exited 1 with
        # "config.yaml: withBinaryFile: does not exist" and, with no result lines to parse,
        # the run was reported as CLEAN. Measured 0/5 detections on contracts that detect
        # reliably in isolation.
        run = root / "_dash" / f"run-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        run.mkdir(parents=True, exist_ok=True)

        src_dir = Path(contract_path).parent
        for f in src_dir.glob("*.sol"):          # harness + its target(s)
            shutil.copy2(f, run / f.name)
        if config and Path(config).exists():
            shutil.copy2(config, run / "config.yaml")
        if seeds:
            from .ai_guidance import write_seed_corpus
            try:
                write_seed_corpus(run / "corpus", seeds)
            except Exception:
                pass

        hname = Path(contract_path).name
        ver = _solc_for_pragma(contract_path) or "0.8.25"
        cfg = "--config config.yaml " if (run / "config.yaml").exists() else ""
        cname = f"--contract {contract} " if contract else ""
        inner = (f"cd /app/_dash/{run.name} && solc-select install {ver} >/dev/null 2>&1; "
                 f"export SOLC_VERSION={ver}; "
                 f"echidna {hname} {cname}{cfg}--test-limit {self.test_limit} "
                 f"--corpus-dir corpus 2>&1")
        started = time.monotonic()
        try:
            proc = subprocess.run(["docker", "compose", "exec", "-T", svc, "sh", "-c", inner],
                                  cwd=str(root), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace")
            self.elapsed = round(time.monotonic() - started, 2)
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        finally:
            shutil.rmtree(run, ignore_errors=True)
        if "not found" in output and "docker" in output.lower() and "echidna" not in output:
            raise RuntimeError(
                "Echidna could not be reached: Docker is not running, or the compose service "
                f"'{svc}' is down. Start it with `docker compose up -d {svc}`.")
        self.coverage = self._parse_coverage(output)
        # Same honesty guard the in-process path applies: an "all clear" is only
        # trustworthy if Echidna actually evaluated a property. Without this, a run that
        # died before starting (bad config path, compile failure, container gone) returned
        # no findings and was rendered as a green CLEAN verdict.
        if not any(_RESULT_RE.match(line.strip()) for line in output.splitlines()):
            tail = "\n".join(output.strip().splitlines()[-12:])
            raise RuntimeError(
                "Echidna evaluated no properties (compile error, or the run failed to start). "
                f"Exit code {proc.returncode}. Echidna output:\n" + tail)
        return self._parse(output, contract_path)

    def fuzz(self, contract_path: str, contract: str | None = None,
             config: str | None = None, seeds: list | None = None) -> list[Finding]:
        """Fuzz the contract and return any property violations as Findings.

        Args:
            contract_path: path to the .sol file containing the Echidna harness.
            contract: optional name of the test contract (the one with the
                echidna_* properties). If omitted, Echidna auto-selects.
            config: optional path to an Echidna YAML config (e.g. to fund the
                harness via `balanceContract`).
            seeds: optional AI-proposed transaction sequences. They are written into
                Echidna's corpus before the run, so the fuzzer REPLAYS them as starting
                points instead of beginning from purely random input. The caller decides
                where they come from; both modes execute the same Echidna afterwards.
        """
        return self._run_random(contract_path, contract, config, seeds)

    def _run_random(self, contract_path: str, contract: str | None,
                    config: str | None = None, seeds: list | None = None) -> list[Finding]:
        if shutil.which("echidna") is None:
            # Host-side execution (dashboard / CLI on Windows or macOS): Slither, solcx and the
            # LLM live here, but Echidna only exists in the Linux image. Rather than refusing,
            # delegate the fuzzing step to the container over `docker compose exec` -- the same
            # split the evaluation harness uses. Both call sites therefore run one Echidna.
            return self._run_in_docker(contract_path, contract, config, seeds)
        # Use an absolute path so we can run Echidna from a throwaway working
        # directory. Echidna/crytic-compile drop a `crytic-export/` folder in the
        # CWD; running from a temp dir keeps that scratch out of the user's repo.
        # portion that does up the enabling of coverafe tracking
        #runs on its own EVM, no RPC URL, host, chain address etc
        abs_path = os.path.abspath(contract_path)
        cmd = ["echidna", abs_path, "--test-limit", str(self.test_limit)]
        if contract:
            cmd += ["--contract", contract]
        if config:
            cmd += ["--config", os.path.abspath(config)]
        env = dict(os.environ)
        solc = _solc_for_pragma(contract_path)
        if solc:
            env["SOLC_VERSION"] = solc  # solc-select honours this per run
            # ensure that compiler is available (idempotent; downloads only if missing)
            subprocess.run(["solc-select", "install", solc],
                           capture_output=True, text=True, env=env)
        with tempfile.TemporaryDirectory(prefix="aifuzz-") as workdir:
            # --corpus-dir makes Echidna emit coverage (the cov: lines + an annotated
            # report); it lives in the temp dir and is cleaned up with it.
            corpus = os.path.join(workdir, "corpus")
            if seeds:
                # Pre-load AI-proposed sequences so Echidna replays them before random search.
                from pathlib import Path as _P
                from .ai_guidance import write_seed_corpus
                try:
                    write_seed_corpus(_P(corpus), seeds)
                except Exception:
                    pass          # a bad seed must never block the run; degrade to random
            run_cmd = cmd + ["--corpus-dir", corpus]
            started = time.monotonic() #start timer
            # Run FROM the directory holding the harness: a synthesized harness imports its
            # target relatively (`import "./Target.sol"`), and crytic-compile resolves that
            # against the working directory. Running from an unrelated scratch dir left the
            # import unresolvable, so Echidna compiled nothing and reported no properties.
            proc = subprocess.run(run_cmd, capture_output=True, text=True,
                                  cwd=os.path.dirname(abs_path) or workdir, env=env)
            self.elapsed = round(time.monotonic() - started, 2) #stop timer
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        self.coverage = self._parse_coverage(output)
        # Honesty guard: only trust an "all clear" if Echidna actually evaluated a
        # property. No result lines => compile error / no echidna_* props => surface it
        # rather than silently reporting "no vulnerabilities found".
        if not any(_RESULT_RE.match(line.strip()) for line in output.splitlines()):
            tail = "\n".join(output.strip().splitlines()[-12:])
            raise RuntimeError(
                "Echidna evaluated no properties (likely a compile error or no "
                "echidna_* functions in the contract). Echidna output:\n" + tail
            )
        return self._parse(output, contract_path)

    @staticmethod
    def _parse_coverage(output: str) -> int | None:
        """The last `cov:` value Echidna printed — unique code points reached.
        Echidna prints it on every status line; the final one is the campaign total."""
        matches = _COV_RE.findall(output)
        return int(matches[-1]) if matches else None

    @staticmethod
    def _parse(output: str, contract_path: str) -> list[Finding]:
        """Turn Echidna's text summary into Findings (one per falsified property)."""
        findings: list[Finding] = []
        lines = output.splitlines()
        for i, raw in enumerate(lines):
            m = _RESULT_RE.match(raw.strip())
            if not m or not m.group(2).startswith("fail"):
                continue
            name = m.group(1)
            sequence = _collect_call_sequence(lines, i + 1)
            cls = _classify_invariant(name)
            title = f"{cls[0]} — invariant `{name}` violated" if cls else f"Invariant `{name}` violated by fuzzing"
            mechanism = f"This is an {cls[0]} finding: {cls[1]}.\n\n" if cls else ""
            findings.append(
                Finding(
                    rule_id="invariant-violation",
                    title=title,
                    severity=Severity.HIGH,
                    description=(
                        f"{mechanism}Echidna falsified the property `{name}`. A generated "
                        f"transaction sequence drove the contract into a state "
                        f"that breaks the invariant:\n"
                        + ("\n".join(f"  {c}" for c in sequence) or "  (sequence unavailable)")
                    ),
                    contract=os.path.basename(contract_path),
                    engine="echidna",
                    sequence=sequence,
                )
            )
        return findings


def _collect_call_sequence(lines: list[str], start: int) -> list[str]:
    """Read the indented call-sequence block after a falsified property."""
    seq: list[str] = []
    for j in range(start, len(lines)):
        s = lines[j].strip()
        if s.startswith("Call sequence:"):
            continue
        # stop at a blank line, the traces section, or the next property result
        if not s or s.startswith("Traces") or _RESULT_RE.match(s):
            break
        seq.append(s)
    return seq
