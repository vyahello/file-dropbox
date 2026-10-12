#!/usr/bin/env python3
"""
Manage the single shared API token in config.json.

Usage:
  python3 manage_token.py show      # print the current token
  python3 manage_token.py rotate    # generate a new token (old one stops working)
  python3 manage_token.py set TOKEN # set a specific token
"""

import json
import os
import secrets
import sys
from typing import Any
from typing import Dict

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")


def load() -> Dict[str, Any]:
    """Read config.json, exiting with a hint if it doesn't exist yet."""
    if not os.path.exists(CONFIG_PATH):
        print("config.json not found. Run server.py once to create it.")
        sys.exit(1)
    with open(CONFIG_PATH) as fh:
        return json.load(fh)


def save(cfg: Dict[str, Any]) -> None:
    """Write ``cfg`` back to config.json."""
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)


def main() -> None:
    """Dispatch the ``show`` / ``rotate`` / ``set`` sub-commands."""
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

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
