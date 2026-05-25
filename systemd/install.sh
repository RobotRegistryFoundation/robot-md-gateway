#!/usr/bin/env bash
# robot-md-dispatcher install script
#
# Provisions:
#   /opt/robot-md-dispatcher/.venv  — Python virtualenv with the package
#   /etc/robot-md-dispatcher/       — config dir (ROBOT.md, bearers.yaml, env)
#   /var/log/robot-md-dispatcher/   — writable log path (journal is primary; this is a spare)
#   /etc/systemd/system/robot-md-dispatcher.service  — symlink to the unit
#
# After running this, edit /etc/robot-md-dispatcher/{dispatcher.env, bearers.yaml}
# and place ROBOT.md next to them, then:
#
#   systemctl daemon-reload
#   systemctl enable --now robot-md-dispatcher
#
# Ingress (Tailscale Funnel):
#   tailscale serve --bg --https=443 http://127.0.0.1:8080
#   tailscale funnel 443 on
#
# That's named, revocable, TLS-terminated ingress. Do NOT open 8080 to the public
# internet directly — the dispatcher binds to 127.0.0.1 by design.

set -euo pipefail

ADD_INTERACTIVE_USER=1
for arg in "$@"; do
    case "$arg" in
        --no-interactive-user)
            ADD_INTERACTIVE_USER=0
            ;;
        -h|--help)
            sed -n '1,21p' "$0" | sed 's/^# \{0,1\}//'
            echo
            echo "Flags:"
            echo "  --no-interactive-user   Don't add \$SUDO_USER to the dialout group."
            echo "                          Use for service-only installs where no human"
            echo "                          will talk to the actuator from a shell."
            exit 0
            ;;
        *)
            echo "error: unknown flag: $arg" >&2
            exit 2
            ;;
    esac
done

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/robot-md-dispatcher"
CONFIG_DIR="/etc/robot-md-dispatcher"
LOG_DIR="/var/log/robot-md-dispatcher"

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root (use sudo)" >&2
    exit 1
fi

id robot >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin robot
usermod -aG dialout robot

# Mirror the service user's group membership for the human who ran `sudo`.
# Without this, the interactive user can't open /dev/ttyACM0 from their own
# shell — robot-md-mcp falls through to "no backend" mode silently
# (robot-md-gateway#21). The gateway service itself uses `robot:dialout`
# regardless of this step.
INTERACTIVE_USER_NOTE=""
if [[ "$ADD_INTERACTIVE_USER" == "1" ]]; then
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        if id "$SUDO_USER" >/dev/null 2>&1; then
            usermod -aG dialout "$SUDO_USER"
            INTERACTIVE_USER_NOTE="$SUDO_USER"
        fi
    fi
fi

install -d -o robot -g robot -m 0755 "$INSTALL_DIR" "$LOG_DIR"
install -d -o root -g robot -m 0750 "$CONFIG_DIR"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install "$REPO_DIR"

# Fail loudly here if the claude-agent-sdk version we just resolved has drifted
# away from the option shape the dispatcher uses. Much cheaper to catch this at
# install time than at first dispatch.
"$INSTALL_DIR/.venv/bin/python" -c "
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher
ClaudeAgentOptions(max_turns=1, max_budget_usd=0.01, permission_mode='default')
print('claude-agent-sdk: option shape OK')
"

chown -R robot:robot "$INSTALL_DIR"

if [[ ! -f "$CONFIG_DIR/dispatcher.env" ]]; then
    cat >"$CONFIG_DIR/dispatcher.env" <<'EOF'
ROBOT_MD_PATH=/etc/robot-md-dispatcher/ROBOT.md
ROBOT_MD_BEARERS_FILE=/etc/robot-md-dispatcher/bearers.yaml
ROBOT_MD_MCP_COMMAND=robot-md-mcp
ROBOT_MD_LOG_LEVEL=INFO
EOF
    chmod 0640 "$CONFIG_DIR/dispatcher.env"
    chown root:robot "$CONFIG_DIR/dispatcher.env"
fi

if [[ ! -f "$CONFIG_DIR/bearers.yaml" ]]; then
    cat >"$CONFIG_DIR/bearers.yaml" <<'EOF'
# One entry per caller. Rotate by replacing tokens and reloading the service.
# Generate tokens with: python3 -c "import secrets;print(secrets.token_urlsafe(32))"
# - token: REPLACE_ME
#   tier: read
#   caller: example-read
# - token: REPLACE_ME
#   tier: actuate
#   caller: example-actuate
EOF
    chmod 0640 "$CONFIG_DIR/bearers.yaml"
    chown root:robot "$CONFIG_DIR/bearers.yaml"
    echo "created $CONFIG_DIR/bearers.yaml — edit it before enabling the service"
fi

install -m 0644 "$REPO_DIR/systemd/robot-md-dispatcher.service" \
    /etc/systemd/system/robot-md-dispatcher.service

echo "installed. next steps:"
echo "  1. edit $CONFIG_DIR/bearers.yaml and place ROBOT.md at $CONFIG_DIR/ROBOT.md"
echo "  2. systemctl daemon-reload && systemctl enable --now robot-md-dispatcher"
echo "  3. tailscale serve --bg --https=443 http://127.0.0.1:8080"
echo "  4. tailscale funnel 443 on"

if [[ -n "$INTERACTIVE_USER_NOTE" ]]; then
    echo
    echo "added $INTERACTIVE_USER_NOTE to the 'dialout' group so the interactive shell"
    echo "can open /dev/ttyACM0 (needed for robot-md-mcp, robot-md doctor, calibration)."
    echo
    echo "  IMPORTANT: log out and back in (or run 'newgrp dialout') for the group"
    echo "  change to take effect in your current shell."
    echo
    echo "  Verify with:"
    echo "      groups | tr ' ' '\\n' | grep -q dialout && ls -l /dev/ttyACM0 && echo OK"
fi
