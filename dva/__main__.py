from __future__ import annotations
import argparse
import importlib
import sys
from dva.errors import DvaError

# Each module exposes register(subparsers) and its command functions set parser.set_defaults(func=...)
COMMAND_MODULES = ["dva.doctor", "dva.run", "dva.mde", "dva.hunting", "dva.cloud", "dva.enrich", "dva.score_cmd", "dva.report_cmd"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description="Defender vulnerability assessment helper")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in COMMAND_MODULES:
        try:
            mod = importlib.import_module(name)
        except ModuleNotFoundError:
            continue  # allows the CLI to work before every module exists
        mod.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    from dva.dotenv import load as load_dotenv
    load_dotenv()  # .env in the cwd or repo root; exported shell variables take precedence
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DvaError as exc:
        print(f"dva: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
