"""
Tests for the config file and the ``file-dropbox`` command (pytest).

Each test points FILE_DROPBOX_CONFIG at a config file in a temp folder.

Run:  pytest -v
"""

import json
import os
import stat
from typing import Iterator

import pytest

from file_dropbox import __version__
from file_dropbox import cli
from file_dropbox.config import CONFIG_ENV
from file_dropbox.config import load_config
from file_dropbox.security import verify_password


@pytest.fixture
def config_file(tmp_path, monkeypatch) -> Iterator[str]:
    """Path of a not-yet-existing config file that the code under test will use."""
    path = str(tmp_path / "conf" / "config.json")
    monkeypatch.setenv(CONFIG_ENV, path)
    yield path


def read(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# --------------------------------------------------------------------------
# config.json
# --------------------------------------------------------------------------


def test_first_run_creates_private_config_with_secrets(config_file, capsys):
    cfg = load_config()
    assert os.path.exists(config_file)
    assert mode(config_file) == 0o600
    assert len(cfg["api_token"]) >= 40
    out = capsys.readouterr().out
    assert cfg["api_token"] in out

    # The admin password is printed once, and only its hash is stored.
    password = out.split("shown only this once):\n")[1].split("\n")[0].strip()
    assert password not in json.dumps(read(config_file))
    assert verify_password(password, read(config_file)["admin_password_hash"])


def test_upgrade_adds_admin_password_and_keeps_settings(config_file):
    os.makedirs(os.path.dirname(config_file))
    with open(config_file, "w") as fh:
        json.dump({"api_token": "old-token", "port": 1234}, fh)
    cfg = load_config()
    saved = read(config_file)
    assert saved["api_token"] == "old-token" and saved["port"] == 1234
    assert saved["admin_password_hash"].startswith("pbkdf2_sha256$")
    assert cfg["upload_root"] == "uploads"  # defaults filled in


def test_no_admin_password_when_admin_page_is_off(config_file):
    os.makedirs(os.path.dirname(config_file))
    with open(config_file, "w") as fh:
        json.dump({"api_token": "t", "admin_path": ""}, fh)
    load_config()
    assert "admin_password_hash" not in read(config_file)  # file left untouched


# --------------------------------------------------------------------------
# file-dropbox token / admin-password
# --------------------------------------------------------------------------


def test_token_commands(config_file, capsys):
    load_config()
    capsys.readouterr()

    assert cli.main(["token", "set", "my-token"]) == 0
    assert read(config_file)["api_token"] == "my-token"
    assert mode(config_file) == 0o600
    capsys.readouterr()

    assert cli.main(["token", "show"]) == 0
    assert capsys.readouterr().out.strip() == "my-token"

    assert cli.main(["token", "rotate"]) == 0
    new = read(config_file)["api_token"]
    assert new != "my-token" and new in capsys.readouterr().out


def test_commands_explain_a_missing_config(config_file, capsys):
    assert cli.main(["token", "show"]) == 1
    assert "Start the server once" in capsys.readouterr().err


def test_admin_password_is_hashed(config_file, monkeypatch):
    load_config()
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "a-long-enough-password")
    assert cli.main(["admin-password"]) == 0
    assert verify_password("a-long-enough-password", read(config_file)["admin_password_hash"])


def test_admin_password_can_be_generated(config_file, monkeypatch, capsys):
    load_config()
    capsys.readouterr()
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
    assert cli.main(["admin-password"]) == 0
    generated = capsys.readouterr().out.split("safe):\n")[1].split("\n")[0].strip()
    assert verify_password(generated, read(config_file)["admin_password_hash"])


@pytest.mark.parametrize("answers, message", [
    (["short"], "at least 12 characters"),
    (["a-long-enough-password", "something-else-entirely"], "don't match"),
])
def test_bad_admin_passwords_change_nothing(config_file, monkeypatch, capsys, answers, message):
    load_config()
    before = read(config_file)["admin_password_hash"]
    replies = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(replies))
    assert cli.main(["admin-password"]) == 1
    assert message in capsys.readouterr().err
    assert read(config_file)["admin_password_hash"] == before


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"file-dropbox {__version__}"
