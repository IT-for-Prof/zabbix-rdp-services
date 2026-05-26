#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
# install.sh — one-shot deploy for rdp_check.
#
# Usage (recommended pinned to a release tag):
#   curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-rdp-services/v0.2.1/scripts/deploy/install.sh | sudo sh
# or rolling-main:
#   curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-rdp-services/main/scripts/deploy/install.sh | sudo sh
#
# What this does:
#   1. Bootstraps `uv` (Astral) if absent.
#   2. uv-managed Python 3.12 in /opt/rdp_check/python/ (no dep on distro python).
#   3. venv in /opt/rdp_check/venv/, pinned deps from requirements.lock.
#   4. Drops rdp_check.py into the configured Zabbix ExternalScripts directory.
#   5. Runs `rdp_check.py self-test` as a smoke check.
#
# Run on the Zabbix server AND every proxy that monitors RDP hosts (egress parity).
# Idempotent. Re-running upgrades to the latest release pinned in REF. Root required.

set -eu

# ----- configurable -----
INSTALL_ROOT="${INSTALL_ROOT:-/opt/rdp_check}"
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/IT-for-Prof/zabbix-rdp-services}"
REF="${REF:-main}"                          # git ref: tag (v0.2.1), branch, or commit sha
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
ZBX_USER="${ZBX_USER:-zabbix}"
ZBX_GROUP="${ZBX_GROUP:-zabbix}"
# ------------------------

# ----- externalscripts detection helpers -----
detect_external_dir() {
    if [ "${EXTERNAL_DIR+x}" = x ] && [ -n "$EXTERNAL_DIR" ]; then
        printf '%s\t%s\n' "$EXTERNAL_DIR" "EXTERNAL_DIR"
        return 0
    fi

    config_paths=""
    if [ "${ZABBIX_CONF+x}" = x ] && [ -n "$ZABBIX_CONF" ]; then
        config_paths="$ZABBIX_CONF"
    fi
    config_paths="${config_paths}${config_paths:+
}/etc/zabbix/zabbix_server.conf
/etc/zabbix/zabbix_proxy.conf"

    for config_path in $config_paths; do
        if [ -r "$config_path" ]; then
            detected_dir="$(
                awk '
                    /^[[:space:]]*#/ { next }
                    /^[[:space:]]*ExternalScripts[[:space:]]*=/ {
                        sub(/^[^=]*=/, "")
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                        if ($0 != "") { print; exit }
                    }
                ' "$config_path"
            )"
            if [ -n "$detected_dir" ]; then
                printf '%s\t%s\n' "$detected_dir" "$config_path"
                return 0
            fi
            break
        fi
    done

    fallback_dirs="${EXTERNAL_FALLBACK_DIRS:-/usr/lib/zabbix/externalscripts
/usr/lib64/zabbix/externalscripts
/usr/share/zabbix/externalscripts
/usr/local/share/zabbix/externalscripts}"
    old_ifs="$IFS"
    IFS='
'
    for fallback_dir in $fallback_dirs; do
        [ -n "$fallback_dir" ] || continue
        if [ -d "$fallback_dir" ]; then
            IFS="$old_ifs"
            printf '%s\t%s\n' "$fallback_dir" "fallback"
            return 0
        fi
    done
    IFS="$old_ifs"

    echo "Could not determine Zabbix ExternalScripts directory." >&2
    echo "Set it explicitly and rerun, e.g.:  EXTERNAL_DIR=/real/path sh install.sh" >&2
    return 2
}
# ----- end externalscripts detection helpers -----

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root (sudo)." >&2
    exit 2
fi

external_dir_detection="$(detect_external_dir)"
EXTERNAL_DIR="${external_dir_detection%%	*}"
EXTERNAL_DIR_SOURCE="${external_dir_detection#*	}"
echo "+ externalscripts: $EXTERNAL_DIR from $EXTERNAL_DIR_SOURCE"

if [ ! -d "$EXTERNAL_DIR" ]; then
    echo "Zabbix externalscripts directory not found at $EXTERNAL_DIR. Is Zabbix server/proxy installed?" >&2
    exit 2
fi

URL_BASE="$REPO_RAW/$REF"

# 1. Bootstrap uv (single static binary). Idempotent.
if ! command -v uv >/dev/null 2>&1; then
    echo "+ installing uv (Astral)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
for d in /root/.local/bin "$HOME/.local/bin"; do
    [ -x "$d/uv" ] && export PATH="$d:$PATH"
done
echo "+ uv $(uv --version)"

# 2. uv-managed Python + venv (under our control, not the distro's)
export UV_PYTHON_INSTALL_DIR="$INSTALL_ROOT/python"
mkdir -p "$INSTALL_ROOT"
uv python install "$PYTHON_VERSION"
uv venv --clear --python "$PYTHON_VERSION" "$INSTALL_ROOT/venv"
echo "+ venv $("$INSTALL_ROOT"/venv/bin/python --version)"

# 3. Pinned deps.
LOCK_TMP="$(mktemp)"
trap 'rm -f "$LOCK_TMP"' EXIT
curl -fsSL "$URL_BASE/scripts/deploy/requirements.lock" -o "$LOCK_TMP"
uv pip install --quiet --python "$INSTALL_ROOT/venv/bin/python" -r "$LOCK_TMP"
cp "$LOCK_TMP" "$INSTALL_ROOT/requirements.lock"
echo "+ deps installed"

# 4. Script itself, run by the venv python (shebang rewritten to the venv).
curl -fsSL "$URL_BASE/scripts/externalscripts/rdp_check.py" -o "$EXTERNAL_DIR/rdp_check.py"
sed -i "1s|.*|#!$INSTALL_ROOT/venv/bin/python|" "$EXTERNAL_DIR/rdp_check.py"
chown "$ZBX_USER:$ZBX_GROUP" "$EXTERNAL_DIR/rdp_check.py"
chmod 0750 "$EXTERNAL_DIR/rdp_check.py"
echo "+ rdp_check.py deployed to $EXTERNAL_DIR"

# 5. Smoke
echo "+ self-test"
"$EXTERNAL_DIR/rdp_check.py" self-test
echo "+ installed rdp_check $("$EXTERNAL_DIR"/rdp_check.py --version) [ref: $REF]"
