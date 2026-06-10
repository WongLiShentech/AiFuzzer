"""Command-line entry point: `aifuzz`.

    aifuzz analyze <contract.sol> [--mode random|ai-guided] [--contract-name NAME] [--format ...]
    aifuzz benchmark            # run over the evaluation dataset (see benchmark.py)

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
        report = analyze(args.contract, mode=args.mode, contract=args.contract_name)
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


def _cmd_benchmark(args: argparse.Namespace) -> int:
    print("[aifuzz] run the evaluation harness with:  python benchmark.py", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aifuzz", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"aifuzz {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze a single contract")
    a.add_argument("contract", help="path to a .sol contract / Echidna harness")
    a.add_argument("--mode", choices=["random", "ai-guided"], default="random")
    a.add_argument("--contract-name", dest="contract_name", default=None,
                   help="name of the Echidna test contract (the one with echidna_* properties)")
    a.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    a.set_defaults(func=_cmd_analyze)

    b = sub.add_parser("benchmark", help="evaluate over the labeled dataset")
    b.set_defaults(func=_cmd_benchmark)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
