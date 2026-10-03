"""Task runner behind every Makefile target.

Usage:  python scripts/tasks.py <task> [options]     (same as: make <task> ARGS="options")

Examples:
    python scripts/tasks.py ingest                  daily pull, last 3 days
    python scripts/tasks.py ingest --days 90        first fill
    python scripts/tasks.py ingest --offline data/snapshots/2026-10-01

Why this exists: Windows has no GNU make by default, so each Makefile target
only forwards to this file. It uses the standard library only and runs on the
host Python (3.10+); the actual work happens inside the radar-api container.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UV_IMAGE = "ghcr.io/astral-sh/uv:0.12.21-python3.12-trixie-slim"


def run(cmd: list[str]) -> int:
    print("$ " + " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=ROOT)


def compose(*args: str) -> int:
    return run(["docker", "compose", *args])


def in_api(*args: str) -> int:
    # Runs a command inside the already running radar-api container.
    # -T: no terminal needed, so this also works from make and from n8n.
    return compose("exec", "-T", "radar-api", *args)


def not_yet(phase: int):
    def task() -> int:
        print(f"Not implemented yet - arrives in phase {phase}.", file=sys.stderr)
        return 2

    return task


def up() -> int:
    if not (ROOT / ".env").exists():
        print("Missing .env - copy .env.example to .env and fill it in first.", file=sys.stderr)
        return 1
    return compose("up", "-d", "--build")


def down() -> int:
    return compose("down")


def logs() -> int:
    return compose("logs", "-f", "--tail", "100")


def test() -> int:
    # Prefer a host uv; otherwise run the tests in a throwaway container so a
    # fresh Windows machine needs nothing but Docker.
    if shutil.which("uv"):
        return run(["uv", "run", "pytest", "-q"])
    return run([
        "docker", "run", "--rm",
        "-v", f"{ROOT}:/src", "-w", "/src",
        # Keep the Linux venv out of the repo folder.
        "-e", "UV_PROJECT_ENVIRONMENT=/tmp/venv",
        UV_IMAGE, "uv", "run", "pytest", "-q",
    ])


def ingest() -> int:
    return in_api("python", "-m", "radar.cli", "ingest", *EXTRA_ARGS)


def migrate() -> int:
    return in_api("python", "-m", "radar.cli", "migrate")


def lock() -> int:
    # Regenerates uv.lock without needing uv on the host.
    if shutil.which("uv"):
        return run(["uv", "lock"])
    return run(["docker", "run", "--rm", "-v", f"{ROOT}:/src", "-w", "/src", UV_IMAGE, "uv", "lock"])


# Options after the task name, passed on to the command (e.g. --days 90).
EXTRA_ARGS: list[str] = sys.argv[2:]

TASKS = {
    "up": up,
    "down": down,
    "logs": logs,
    "test": test,
    "lock": lock,
    "ingest": ingest,
    "migrate": migrate,
    "seed": not_yet(2),
    "import-workflows": not_yet(3),
    "export-workflows": not_yet(3),
    "eval": not_yet(4),
    "demo": not_yet(5),
    "demo-offline": not_yet(5),
    "reset": not_yet(5),
    "stats": not_yet(5),
}


def main() -> int:
    if len(sys.argv) == 1:
        print(__doc__)
        print("Tasks: " + ", ".join(TASKS))
        return 0
    if sys.argv[1] not in TASKS:
        print("Unknown task. Tasks: " + ", ".join(TASKS), file=sys.stderr)
        return 1
    return TASKS[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
