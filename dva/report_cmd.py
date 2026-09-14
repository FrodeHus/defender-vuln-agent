from __future__ import annotations
from dva.run import add_run_arg, resolve_run
from dva import report_md, report_json, report_brief


def register(sub) -> None:
    p = sub.add_parser("report", help="Render reports from findings.json"); add_run_arg(p)
    for f in ("md", "html", "json", "tickets", "all"):
        p.add_argument(f"--{f}", action="store_true")
    p.add_argument("--brief", action="store_true", help="print the reply summary (top 3, counts, SLA, EOS, long-standing, trend, sources, suggestions) and write nothing")
    p.set_defaults(func=_run)


def _run(args) -> int:
    run = resolve_run(args)
    doc = run.read_json("findings.json")
    if getattr(args, "brief", False):
        suggestions = run.read_json("exception-suggestions.json") if run.path("exception-suggestions.json").exists() else None
        print(report_brief.render(doc, suggestions, str(run.dir)), end="")
        return 0
    any_flag = args.md or args.html or args.json or args.tickets
    want = {"md", "html", "json", "tickets"} if args.all or not any_flag else {f for f in ("md", "html", "json", "tickets") if getattr(args, f)}
    written = []
    if "md" in want:
        run.path("report.md").write_text(report_md.render(doc)); written.append("report.md")
    if "json" in want:
        run.path("report.json").write_text(report_json.render(doc)); written.append("report.json")
    if "html" in want:
        from dva import report_html
        run.path("report.html").write_text(report_html.render(doc)); written.append("report.html")
    if "tickets" in want:
        from dva import report_tickets
        run.path("tickets.json").write_text(report_tickets.render(doc)); written.append("tickets.json")
    run.summary("Reports written: " + ", ".join(written) + f" in {run.dir}")
    return 0
