from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="robot-md-dispatcher")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run the dispatcher HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument(
        "--robot-md", default=None, help="Path to ROBOT.md (sets ROBOT_MD_PATH)"
    )
    serve.add_argument(
        "--bearers",
        default=None,
        help="Path to bearers YAML (sets ROBOT_MD_BEARERS_FILE)",
    )
    serve.add_argument(
        "--mcp-command",
        default=None,
        help="Stdio MCP command to spawn (default: robot-md-mcp)",
    )

    init = sub.add_parser(
        "init",
        help="Generate bearers.yaml and .env for a ROBOT.md robot",
    )
    init.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive: take all defaults, no prompts",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing bearers.yaml and .env (invalidates old tokens)",
    )
    init.add_argument(
        "--no-token-stdout",
        action="store_true",
        help="Do not echo the generated token to stdout "
        "(used by the Claude Code plugin slash command)",
    )

    args = parser.parse_args()

    if args.cmd == "serve":
        if args.robot_md:
            os.environ["ROBOT_MD_PATH"] = args.robot_md
        if args.bearers:
            os.environ["ROBOT_MD_BEARERS_FILE"] = args.bearers
        if args.mcp_command:
            os.environ["ROBOT_MD_MCP_COMMAND"] = args.mcp_command

        logging.basicConfig(
            level=os.environ.get("ROBOT_MD_LOG_LEVEL", "INFO"),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

        import uvicorn

        from .app import create_app_from_env

        uvicorn.run(create_app_from_env(), host=args.host, port=args.port)
        return

    if args.cmd == "init":
        from .init_wizard import run as wizard_run

        rc = wizard_run(
            interactive=not args.yes,
            cwd=Path.cwd(),
            force=args.force,
            no_token_stdout=args.no_token_stdout,
        )
        sys.exit(rc)


if __name__ == "__main__":
    main()
