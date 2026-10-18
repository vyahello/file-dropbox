#!/usr/bin/env python3
"""
Manage the secrets in config.json: the shared upload token and the admin password.

Usage:
  python3 manage_token.py show            # print the current upload token
  python3 manage_token.py rotate          # new upload token (old one stops working)
  python3 manage_token.py set TOKEN       # set a specific upload token
  python3 manage_token.py admin-password  # set a new admin password (prompts)

Restart the server after any change.
"""

import getpass
import json
import os
import secrets
import sys
from typing import Any
from typing import Dict

from security import hash_password

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("FILE_DROPBOX_CONFIG") or os.path.join(HERE, "config.json")
MIN_PASSWORD_LENGTH = 12


def load() -> Dict[str, Any]:
    """Read config.json, exiting with a hint if it doesn't exist yet."""
    if not os.path.exists(CONFIG_PATH):
        print(f"{CONFIG_PATH} not found. Run server.py once to create it.")
        sys.exit(1)
    with open(CONFIG_PATH) as fh:
        return json.load(fh)


def save(cfg: Dict[str, Any]) -> None:
    """Write ``cfg`` back to config.json, readable by its owner only."""
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def ask_admin_password() -> str:
    """Prompt for a new admin password; an empty answer generates a random one."""
    password = getpass.getpass("New admin password (leave empty to generate one): ")
    if not password:
        password = secrets.token_urlsafe(18)
        print("Generated admin password (store it somewhere safe):")
        print(f"  {password}")
        return password
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
        sys.exit(1)
    if getpass.getpass("Repeat it: ") != password:
        print("The passwords don't match. Nothing was changed.")
        sys.exit(1)
    return password


def main() -> None:
    """Dispatch the ``show`` / ``rotate`` / ``set`` / ``admin-password`` sub-commands."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    cfg = load()

    if cmd == "show":
        print(cfg.get("api_token") or "(no token set)")

    elif cmd == "rotate":
        cfg["api_token"] = secrets.token_urlsafe(32)
        save(cfg)
        print("New token (restart the server, then re-distribute it):")
        print(f"  {cfg['api_token']}")

    elif cmd == "set" and len(sys.argv) == 3:
        cfg["api_token"] = sys.argv[2]
        save(cfg)
        print("Token set. Restart the server.")

    elif cmd == "admin-password":
        cfg["admin_password_hash"] = hash_password(ask_admin_password())
        save(cfg)
        print("Admin password updated. Restart the server to use it.")

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
