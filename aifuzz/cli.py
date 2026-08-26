"""Command-line entry point: `aifuzz`.

    aifuzz analyze <contract.sol> [--mode random|ai-seed|ai-guided] [--contract-name NAME] [--format ...]
    aifuzz deploy <contract.sol> --contract-name NAME [--call viewFn]   # local Anvil chain
    aifuzz benchmark            # held-out A/B1/B2/B3 comparison (see benchmark_testset.py)

Implemented: argument parsing, report formatting, graceful messaging. The
analysis engines themselves are wired up in milestones M2 (random fuzzing) and
M3 (AI-guided); until then `analyze` explains what's pending rather than faking
a result.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        report = analyze(args.contract, mode=args.mode, contract=args.contract_name,
                         config=args.config, auto=args.auto)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except NotImplementedError as e:
        print(f"[aifuzz] analysis engine not yet implemented: {e}", file=sys.stderr)
        print("        (AI-guided fuzzing = M3)", file=sys.stderr)
        return 3
    except RuntimeError as e:
        print(f"[aifuzz] {e}", file=sys.stderr)
        return 4

    out = {
        "json": report.to_json,
        "markdown": report.to_markdown,
        "sarif": lambda: __import__("json").dumps(report.to_sarif(), indent=2),
    }[args.format]()
    print(out)
    return 0


def _cmd_deploy(args: argparse.Namespace) -> int:
    from .local_chain import LocalChain  # lazy: only needs web3 + anvil

    try:
        with LocalChain() as chain:
            print(f"[aifuzz] local chain up — chain id {chain.chain_id}, block {chain.block_number}")
            dep = chain.deploy(args.contract, args.contract_name)
            print(f"[aifuzz] deployed {args.contract_name} at {dep.address}")
            if args.call:
                value = chain.call(dep, args.call)
                print(f"[aifuzz] {args.call}() = {value}")
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"[aifuzz] {e}", file=sys.stderr)
        return 4
    return 0


def _cmd_suite(args: argparse.Namespace) -> int:
    from .suite import run_suite, format_table

    try:
        results = run_suite(args.registry, mode=args.mode)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    print(format_table(results))
    # non-zero exit if any case did not match its ground-truth expectation
    return 0 if all(r.passed for r in results) else 5


def _cmd_benchmark(args: argparse.Namespace) -> int:
    print("[aifuzz] run the evaluation with:  python benchmark_testset.py --approach both", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aifuzz", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"aifuzz {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze a single contract")
    a.add_argument("contract", help="path to a .sol contract / Echidna harness")
    a.add_argument("--mode", default="random",
                   choices=["random", "ai-seed", "ai-seed-cot", "ai-guided"])
    a.add_argument("--contract-name", dest="contract_name", default=None,
                   help="name of the Echidna test contract (the one with echidna_* properties)")
    a.add_argument("--config", default=None,
                   help="optional Echidna YAML config (e.g. to fund the harness)")
    a.add_argument("--auto", action="store_true",
                   help="if the contract has no echidna_* oracle, synthesize a harness "
                        "from its structure (Tier-2 templates) and fuzz that")
    a.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    a.set_defaults(func=_cmd_analyze)

    d = sub.add_parser("deploy", help="deploy a contract to a local Anvil chain and query it")
    d.add_argument("contract", help="path to a .sol contract")
    d.add_argument("--contract-name", dest="contract_name", required=True,
                   help="name of the contract to deploy")
    d.add_argument("--call", default=None,
                   help="optional view function to read after deploy (e.g. owner)")
    d.set_defaults(func=_cmd_deploy)

    s = sub.add_parser("suite", help="run every fuzzing case in the registry and check vs ground truth")
    s.add_argument("--registry", default="tests/harnesses/registry.yaml",
                   help="path to the fuzzing-case registry (default: tests/harnesses/registry.yaml)")
    s.add_argument("--mode", choices=["random", "ai-guided"], default="random")
    s.set_defaults(func=_cmd_suite)

    b = sub.add_parser("benchmark", help="evaluate over the labeled dataset")
    b.set_defaults(func=_cmd_benchmark)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
