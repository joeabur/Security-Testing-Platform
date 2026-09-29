"""The lab's entry point: `python -m lab.main <service>`.

One module so the three services share the isolation guard and the banner. The
compose file names the service; there is no default, because starting "the lab"
without saying which part is a question this should ask rather than guess.
"""

import argparse
import sys

import uvicorn

from lab.isolation import LabRefusedToStart, bind_host

SERVICES = {
    "vulnerable-ai-app": ("lab.vulnerable_ai_app.app", 8081),
    "content-server": ("lab.content_server.app", 8082),
    "collaborator": ("lab.collaborator.app", 8083),
    "web-app": ("lab.web_app.app", 8084),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lab",
        description="Run one Kervy demo-target service. Everything here is "
        "intentionally vulnerable.",
    )
    parser.add_argument("service", choices=sorted(SERVICES))
    parser.add_argument(
        "--host", default=None, help="defaults to 127.0.0.1, or LAB_HOST"
    )
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    module, default_port = SERVICES[args.service]
    try:
        # Raises before a socket is opened if a provider credential is present.
        # Importing the app module also calls `announce`, which re-checks.
        uvicorn.run(
            f"{module}:create_app",
            factory=True,
            host=args.host or bind_host(),
            port=args.port or default_port,
            log_level="info",
        )
    except LabRefusedToStart as exc:
        print(f"lab: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - the container's entry point
    raise SystemExit(main())
