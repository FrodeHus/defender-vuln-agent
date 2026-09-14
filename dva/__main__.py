from __future__ import annotations
import argparse
import importlib
import os
import sys
from dva.errors import DvaError

# Each module exposes register(subparsers) and its command functions set parser.set_defaults(func=...)
COMMAND_MODULES = ["dva.tenant", "dva.doctor", "dva.run", "dva.mde", "dva.hunting", "dva.cloud", "dva.enrich", "dva.exceptions", "dva.score_cmd", "dva.report_cmd"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description="Defender vulnerability assessment helper")
    parser.add_argument("--tenant", metavar="NAME", help="tenant to act on (a directory under tenants/); or set DVA_TENANT")
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
    from dva import tenant as _tenant
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        selected = args.tenant or os.environ.get("DVA_TENANT")
        manages_tenants = args.command == "tenant" and getattr(args, "tenant_cmd", None) != "show"
        if selected and not manages_tenants:
            _tenant.activate(selected)  # tenant .env wins; nothing from the shell or repo .env leaks across tenants
        else:
            load_dotenv()  # single-tenant mode: .env in the cwd or repo root; exported shell variables take precedence
        return int(args.func(args) or 0)
    except DvaError as exc:
        print(f"dva: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
