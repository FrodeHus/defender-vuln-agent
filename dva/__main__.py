from __future__ import annotations
import argparse
import importlib
import os
import sys
from dva.errors import DvaError

# Each module exposes register(subparsers) and its command functions set parser.set_defaults(func=...)
COMMAND_MODULES = ["dva.tenant", "dva.doctor", "dva.run", "dva.mde", "dva.hunting", "dva.cloud", "dva.enrich", "dva.kev", "dva.exceptions", "dva.score_cmd", "dva.report_cmd"]


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
        is_show = args.command == "tenant" and getattr(args, "tenant_cmd", None) == "show"
        needs_tenant = args.command != "tenant" or is_show
        if needs_tenant and not selected and not os.environ.get("DVA_TENANT_DIR"):
            # An explicit DVA_TENANT_DIR from the shell (fixtures, scripts, tests) is honoured as-is;
            # auto-selecting the lone tenant would silently redirect runs and caches into it.
            names = _tenant.list_tenants()
            if len(names) == 1:
                selected = names[0]  # a lone tenant needs no explicit selection
            elif len(names) > 1 and not is_show:
                raise DvaError(f"several tenants configured ({', '.join(names)}); choose one with --tenant NAME or DVA_TENANT=NAME")
        if needs_tenant and selected:
            _tenant.activate(selected)  # tenant .env wins; nothing from the shell or repo .env leaks across tenants
        else:
            load_dotenv()  # single-tenant mode: .env in the cwd or repo root; exported shell variables take precedence
        return int(args.func(args) or 0)
    except DvaError as exc:
        print(f"dva: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
