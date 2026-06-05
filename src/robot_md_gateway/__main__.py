from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .cert.policy import ToolAllowlist

_TRUTHY = {"1", "true", "yes", "on"}


def _validate_actuator_config(*, actuator_instance: object, config: dict) -> None:
    """Validate the actuator's config dict against its config_schema.

    Raises jsonschema.ValidationError on mismatch. No-op when config_schema
    is empty.
    """
    import jsonschema

    schema = getattr(actuator_instance, "config_schema", None) or {}
    if not schema:
        return
    jsonschema.validate(instance=config, schema=schema)


def _require_envelope_signature_from_env() -> bool:
    """Read ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE from env. Defaults to False.

    Recognized true values: 1 / true / yes / on (case-insensitive).
    Any other value (including empty) is False — preserves the receiver's
    development-mode default while letting production deployments turn the
    gate on without code changes.
    """
    raw = os.environ.get("ROBOT_MD_REQUIRE_ENVELOPE_SIGNATURE", "")
    return raw.strip().lower() in _TRUTHY


def _hitl_from_manifest_from_env() -> bool:
    """Read ROBOT_MD_HITL_FROM_MANIFEST from env. Defaults to False.

    When on, make_app builds the HiTL policy from the manifest's declared
    `safety.hitl_gates` (B3) instead of the hardcoded set — production/HIL flips
    it on via the env var without code changes.
    """
    return os.environ.get("ROBOT_MD_HITL_FROM_MANIFEST", "").strip().lower() in _TRUTHY


def _require_rrn_binding_from_env() -> bool:
    """Read ROBOT_MD_REQUIRE_RRN_BINDING from env. Defaults to False.

    When on, the gate chain requires the envelope ruri's RRN to match the
    manifest's `metadata.rrn` (B4, fail-closed 403). Off preserves the receiver's
    development-mode default.
    """
    return os.environ.get("ROBOT_MD_REQUIRE_RRN_BINDING", "").strip().lower() in _TRUTHY


def _build_tool_allowlist_from_env() -> ToolAllowlist | None:
    """Read ROBOT_MD_TOOL_ALLOWLIST (comma-separated) into a ToolAllowlist.

    Returns None when the env var is unset, empty, or contains only whitespace.
    Operators wire this via /etc/robot-md-gateway/gateway.env (or equivalent),
    e.g.: ROBOT_MD_TOOL_ALLOWLIST=mcp__robot__execute_capability,mcp__robot__render
    Empty/whitespace entries between commas are dropped silently.
    """
    raw = os.environ.get("ROBOT_MD_TOOL_ALLOWLIST")
    if not raw:
        return None
    tools = tuple(t.strip() for t in raw.split(",") if t.strip())
    if not tools:
        return None
    return ToolAllowlist(allowed_tools=tools)


class _LegacyByokAction(argparse.Action):
    """Print a deprecation banner to stderr the moment --legacy-byok-launcher is parsed.

    Done as a custom action so the warning fires even when --help is also passed
    (argparse's --help short-circuits parsing, so a post-parse_args() print would
    never run in that path).
    """

    def __call__(self, parser, namespace, values, option_string=None):
        print(
            "warning: --legacy-byok-launcher is deprecated and removed in v0.4.0. "
            "Migrate callers to send signed RCAN INVOKE envelopes instead.",
            file=sys.stderr,
        )
        setattr(namespace, self.dest, True)


def main() -> None:
    parser = argparse.ArgumentParser(prog="robot-md-gateway")
    parser.add_argument(
        "--legacy-byok-launcher",
        action=_LegacyByokAction,
        nargs=0,
        default=False,
        help=(
            "DEPRECATED. Run in v0.2.x BYOK Claude Agent SDK launcher mode. "
            "The gateway will spawn a planner per request rather than receive "
            "signed RCAN envelopes. Removed in v0.4.0."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run the gateway HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--robot-md", default=None, help="Path to ROBOT.md (sets ROBOT_MD_PATH)")
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

    list_p = sub.add_parser(
        "list-actuators",
        help="List actuators discovered via the robot_md_gateway.actuators entry-point group.",
    )
    list_p.add_argument(
        "--bearers",
        help="Path to bearers.yaml (used to mark the currently-active actuator).",
        default=None,
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

        if args.legacy_byok_launcher:
            from .app import create_app_from_env

            fastapi_app = create_app_from_env()
        else:
            from .auth import RRFResolverFromEnv, BearerStore
            from .receiver import make_app
            from .actuator import resolve_actuator
            from .auth import load_actuator_section, load_actuators_section
            from pathlib import Path as _P

            tool_allowlist = _build_tool_allowlist_from_env()
            require_envelope_signature = _require_envelope_signature_from_env()
            hitl_from_manifest = _hitl_from_manifest_from_env()
            require_rrn_binding = _require_rrn_binding_from_env()

            # Load bearer tiers from bearers.yaml if provided.
            bearer_tiers: dict[str, str] = {}
            if args.bearers:
                store = BearerStore.from_yaml(_P(args.bearers))
                # _by_token is the canonical map; build a name → tier dict.
                bearer_tiers = {token: entry.tier for token, entry in store._by_token.items()}

            # Prefer the list-shape `actuators:` section if present — that
            # turns on multi-actuator routing in the receiver. Fall back to the
            # singular `actuator:` section for backward compat.
            actuators_list = load_actuators_section(_P(args.bearers)) if args.bearers else []
            if actuators_list:
                actuators: dict = {}
                actuator_configs: dict[str, dict] = {}
                for entry in actuators_list:
                    cls = resolve_actuator(entry["name"])
                    instance = cls()
                    _validate_actuator_config(
                        actuator_instance=instance,
                        config=entry["config"],
                    )
                    actuators[instance.name] = instance
                    actuator_configs[instance.name] = entry["config"]
                fastapi_app = make_app(
                    resolver=RRFResolverFromEnv.from_env(),
                    tool_allowlist=tool_allowlist,
                    require_envelope_signature=require_envelope_signature,
                    hitl_from_manifest=hitl_from_manifest,
                    require_rrn_binding=require_rrn_binding,
                    actuators=actuators,
                    actuator_configs=actuator_configs,
                    bearer_tiers=bearer_tiers,
                )
            else:
                actuator_section = (
                    load_actuator_section(_P(args.bearers))
                    if args.bearers
                    else {"name": "noop", "config": {}}
                )
                actuator_cls = resolve_actuator(actuator_section["name"])
                actuator_instance = actuator_cls()
                _validate_actuator_config(
                    actuator_instance=actuator_instance,
                    config=actuator_section["config"],
                )
                fastapi_app = make_app(
                    resolver=RRFResolverFromEnv.from_env(),
                    tool_allowlist=tool_allowlist,
                    require_envelope_signature=require_envelope_signature,
                    hitl_from_manifest=hitl_from_manifest,
                    require_rrn_binding=require_rrn_binding,
                    actuator=actuator_instance,
                    actuator_config=actuator_section["config"],
                    bearer_tiers=bearer_tiers,
                )

        uvicorn.run(fastapi_app, host=args.host, port=args.port)
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

    if args.cmd == "list-actuators":
        from .actuator import discover_actuators
        from .auth import load_actuator_section

        discovered = discover_actuators()
        active_name: str | None = None
        if args.bearers:
            section = load_actuator_section(Path(args.bearers))
            active_name = section["name"]

        for name in sorted(discovered):
            cls = discovered[name]
            # Instantiate to read instance metadata. Built-ins should not
            # take args; if a user-defined actuator's __init__ requires
            # args, we just print its name without metadata.
            try:
                inst = cls()
                desc = getattr(inst, "description", "")
                schema = getattr(inst, "config_schema", {})
            except Exception as exc:  # noqa: BLE001
                desc = f"<could not instantiate: {exc}>"
                schema = {}
            marker = " *" if active_name and active_name == name else ""
            print(f"{name}{marker}\t{desc}\t{schema}")
        return


if __name__ == "__main__":
    main()
