"""
Tests for the config file and the ``file-dropbox`` command (pytest).

Each test points FILE_DROPBOX_CONFIG at a config file in a temp folder.

Run:  pytest -v
"""

import json
import os
import re
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

    # The username is printed and kept; the password is printed once and only its hash is kept.
    saved = read(config_file)
    username = re.search(r"username: (\S+)", out).group(1)
    password = re.search(r"password: (\S+)\s+\(shown only this once\)", out).group(1)
    assert username == saved["admin_username"] and username.startswith("owner-")
    assert password not in json.dumps(saved)
    assert verify_password(password, saved["admin_password_hash"])


def test_upgrade_adds_admin_password_and_keeps_settings(config_file):
    os.makedirs(os.path.dirname(config_file))
    with open(config_file, "w") as fh:
        json.dump({"api_token": "old-token", "port": 1234}, fh)
    cfg = load_config()
    saved = read(config_file)
    assert saved["api_token"] == "old-token" and saved["port"] == 1234
    assert saved["admin_password_hash"].startswith("pbkdf2_sha256$")
    assert saved["admin_username"].startswith("owner-")
    assert cfg["upload_root"] == "uploads"  # defaults filled in


def test_upgrade_keeps_the_password_and_adds_a_username(config_file, capsys):
    os.makedirs(os.path.dirname(config_file))
    with open(config_file, "w") as fh:
        json.dump({"api_token": "t", "admin_password_hash": "pbkdf2_sha256$1$YQ==$YQ=="}, fh)
    load_config()
    saved = read(config_file)
    assert saved["admin_password_hash"] == "pbkdf2_sha256$1$YQ==$YQ=="
    out = capsys.readouterr().out
    assert f"username: {saved['admin_username']}" in out
    assert "password: unchanged" in out


def test_no_admin_password_when_admin_page_is_off(config_file):
    os.makedirs(os.path.dirname(config_file))
    with open(config_file, "w") as fh:
        json.dump({"api_token": "t", "admin_path": ""}, fh)
    load_config()
    saved = read(config_file)
    assert "admin_password_hash" not in saved and "admin_username" not in saved  # untouched


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


@pytest.mark.parametrize("command", ["admin", "admin-password"])  # old name still works
def test_admin_command_sets_username_and_password(config_file, monkeypatch, command):
    load_config()
    monkeypatch.setattr("builtins.input", lambda prompt="": "me@home")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "a-long-enough-password")
    assert cli.main([command]) == 0
    saved = read(config_file)
    assert saved["admin_username"] == "me@home"
    assert verify_password("a-long-enough-password", saved["admin_password_hash"])


def test_admin_command_keeps_username_and_can_generate_password(config_file, monkeypatch, capsys):
    load_config()
    username = read(config_file)["admin_username"]
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
    assert cli.main(["admin"]) == 0
    generated = capsys.readouterr().out.split("safe):\n")[1].split("\n")[0].strip()
    saved = read(config_file)
    assert saved["admin_username"] == username
    assert verify_password(generated, saved["admin_password_hash"])


@pytest.mark.parametrize("username, passwords, message", [
    ("", ["short"], "at least 12 characters"),
    ("", ["a-long-enough-password", "something-else-entirely"], "don't match"),
    ("x", ["a-long-enough-password"] * 2, "3 to 64"),
    ("has space", ["a-long-enough-password"] * 2, "3 to 64"),
])
def test_bad_admin_input_changes_nothing(config_file, monkeypatch, capsys, username, passwords, message):
    load_config()
    before = read(config_file)
    replies = iter(passwords)
    monkeypatch.setattr("builtins.input", lambda prompt="": username)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(replies))
    assert cli.main(["admin"]) == 1
    assert message in capsys.readouterr().err
    assert read(config_file) == before


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"file-dropbox {__version__}"
