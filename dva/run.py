from __future__ import annotations
import json, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from dva.errors import DvaError


class Run:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.id = self.dir.name
        self._manifest_path = self.dir / "manifest.json"
        if self._manifest_path.exists():
            try:
                self.manifest = json.loads(self._manifest_path.read_text())
            except json.JSONDecodeError as exc:
                raise DvaError(f"corrupt manifest in run {self.id}: {exc}")
        else:
            self.manifest = {
                "run_id": self.id, "started_at": datetime.now(timezone.utc).isoformat(), "sources": {}}

    @classmethod
    def create(cls, runs_dir: Path) -> "Run":
        base_rid = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")[:-4] + "Z"  # YYYYMMDDTHHMMSSmmZ
        runs_dir = Path(runs_dir)
        for attempt in range(101):
            if attempt == 0:
                rid = base_rid
            else:
                rid = base_rid + f"-{attempt:03d}"
            d = runs_dir / rid
            try:
                d.mkdir(parents=True, exist_ok=False)
                run = cls(d)
                run._save()
                return run
            except FileExistsError:
                if attempt == 100:
                    raise DvaError(f"cannot create run directory after 100 attempts: {runs_dir / base_rid}")
                continue

    @classmethod
    def open(cls, path: Path) -> "Run":
        p = Path(path)
        if not (p / "manifest.json").exists():
            raise DvaError(f"not a run directory: {p}")
        return cls(p)

    @classmethod
    def latest(cls, runs_dir: Path, before: str | None = None) -> "Run | None":
        runs_dir = Path(runs_dir)
        if not runs_dir.exists():
            return None
        candidates = sorted(p.name for p in runs_dir.iterdir() if (p / "manifest.json").exists())
        if before:
            candidates = [i for i in candidates if i < before]
        for rid in reversed(candidates):
            try:
                return cls(runs_dir / rid)
            except DvaError:
                continue
        return None

    def path(self, name: str) -> Path:
        return self.dir / name

    def write_json(self, name: str, obj: Any) -> None:
        self.path(name).write_text(json.dumps(obj, indent=2, default=str))

    def read_json(self, name: str) -> Any:
        p = self.path(name)
        if not p.exists():
            raise DvaError(f"missing {name} in run {self.id}; run the collector first")
        return json.loads(p.read_text())

    def write_jsonl(self, name: str, rows: Iterable[dict]) -> int:
        n = 0
        with open(self.path(name), "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, default=str) + "\n"); n += 1
        return n

    def read_jsonl(self, name: str) -> Iterator[dict]:
        p = self.path(name)
        if not p.exists():
            raise DvaError(f"missing {name} in run {self.id}; run the collector first")
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def log(self, msg: str) -> None:
        with open(self.path("log.txt"), "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")

    def set_source(self, name: str, status: str, count: int | None = None, error: str | None = None) -> None:
        self.manifest["sources"][name] = {"status": status, "count": count, "error": error}
        self._save()

    def summary(self, text: str) -> None:
        print(text)
        with open(self.path("summary.txt"), "a", encoding="utf-8") as fh:
            fh.write(text + "\n")

    def _save(self) -> None:
        self._manifest_path.write_text(json.dumps(self.manifest, indent=2))


def runs_dir() -> Path:
    return Path(os.environ.get("DVA_RUNS_DIR", "runs"))


def cache_dir() -> Path:
    return Path(os.environ.get("DVA_CACHE_DIR", ".cache"))


def add_run_arg(parser) -> None:
    parser.add_argument("--run", help="run directory (default: $DVA_RUN or latest under runs/)")


def resolve_run(args) -> Run:
    target = getattr(args, "run", None) or os.environ.get("DVA_RUN")
    if target:
        return Run.open(Path(target))
    latest = Run.latest(runs_dir())
    if latest is None:
        raise DvaError("no run found; create one with `dva run new`")
    return latest


def register(sub) -> None:
    p = sub.add_parser("run", help="Manage run directories")
    s = p.add_subparsers(dest="run_cmd", required=True)
    n = s.add_parser("new"); n.add_argument("--runs-dir", help="run directory (default: $DVA_RUNS_DIR or runs)"); n.set_defaults(func=_new)
    l = s.add_parser("latest"); l.add_argument("--runs-dir", help="run directory (default: $DVA_RUNS_DIR or runs)"); l.set_defaults(func=_latest)


def _new(args) -> int:
    rd = Path(args.runs_dir) if args.runs_dir else runs_dir()
    print(Run.create(rd).dir); return 0


def _latest(args) -> int:
    rd = Path(args.runs_dir) if args.runs_dir else runs_dir()
    r = Run.latest(rd)
    if r is None:
        raise DvaError("no runs yet")
    print(r.dir); return 0
