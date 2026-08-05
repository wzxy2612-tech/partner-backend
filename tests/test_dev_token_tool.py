"""The local token tool refuses unless it is named. No database.

The tool decrypts queued invitation tokens and prints them. That is the one
capability the outbox encryption exists to deny, so the refusal is the part
worth pinning -- and it has to happen before any import that would build a
keyring or open a connection, which is why these tests can run with no database
at all. If the gate ever moved below the imports, importing the module would
start requiring OUTBOX_KEYS and these would fail for the wrong reason.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "dev" / "dev_decode_invite_token.py"


def _run(env_value):
    """Invoked the way the docstring says to invoke it (as a script path)."""
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)}
    if env_value is not None:
        env["ALLOW_TOKEN_DECRYPT"] = env_value
    return subprocess.run([sys.executable, str(TOOL)], env=env, cwd=str(ROOT),
                          capture_output=True, text=True, timeout=60)


def test_it_lives_outside_scripts():
    """scripts/ reads as operational -- provision_dispatcher_role.sql is there.
    A decryption oracle sitting beside it invites being run the same way."""
    assert TOOL.exists(), TOOL
    assert not (TOOL.parents[2] / "scripts" / TOOL.name).exists()
    assert TOOL.name.startswith("dev_")


@pytest.mark.parametrize("value", [None, "", "true", "1", "yes", "I-UNDERSTAND"])
def test_it_refuses_without_the_exact_phrase(value):
    """Truthiness is not consent. `ALLOW_TOKEN_DECRYPT=1` is the kind of thing
    that ends up in a compose file by habit; an exact phrase does not."""
    result = _run(value)
    assert result.returncode == 1, result.stdout
    assert "ALLOW_TOKEN_DECRYPT" in result.stderr


def test_the_refusal_precedes_the_keyring():
    """Runs with no OUTBOX_KEYS in the environment at all. If the gate were
    below the imports this would raise on import rather than exit 1, and the
    tool would be constructing a keyring before deciding it may not run."""
    result = _run(None)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr


def test_the_gate_ordering_and_the_documented_invocation():
    """The refusal has to stay above the imports, and the only way that ordering
    survives an edit is if something reads it. Source inspection, because there
    is no runtime signal that distinguishes 'refused early' from 'refused after
    importing sqlalchemy' once both exit 1."""
    src = TOOL.read_text()
    assert "python3 tools/dev/dev_decode_invite_token.py" in src, (
        "the docstring must document the path form with PYTHONPATH=/app")
    gate = src.index("if os.environ.get(GATE_ENV)")
    for late_import in ("from sqlalchemy import", "from app.db import",
                        "from app.services.outbox_crypto import"):
        assert src.index(late_import) > gate, late_import
