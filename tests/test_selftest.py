import json
import subprocess
import sys
from pathlib import Path

import rdp_check as rdp

SCRIPT = Path(__file__).parent.parent / "scripts" / "externalscripts" / "rdp_check.py"


def test_error_envelope_shape():
    env = rdp.error_envelope("not_rdp", "no TPKT", host="h")
    assert env["ok"] is False
    assert env["error_code"] == "not_rdp"
    assert env["host"] == "h"
    assert env["schema_version"] == rdp.SCHEMA_VERSION


def test_self_test_exits_zero():
    r = subprocess.run([sys.executable, str(SCRIPT), "self-test"], capture_output=True, text=True)
    assert r.returncode == 0
    assert json.loads(r.stdout)["ok"] is True


def test_cert_cmd_unreachable_emits_envelope():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "cert", "127.0.0.1:9"], capture_output=True, text=True
    )
    assert r.returncode == 0
    assert json.loads(r.stdout)["error_code"] in ("unreachable", "not_rdp")
