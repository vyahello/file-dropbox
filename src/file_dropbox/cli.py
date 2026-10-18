"""
The ``file-dropbox`` command (also ``python -m file_dropbox``).

Usage:
  file-dropbox                    run the server (same as ``file-dropbox serve``)
  file-dropbox token show         print the current upload token
  file-dropbox token rotate       new random upload token (old one stops working)
  file-dropbox token set TOKEN    set a specific upload token
  file-dropbox admin              set the admin username and password

Restart the server after changing a secret.
"""

import argparse
import getpass
import re
import sys
from typing import List
from typing import Optional

from file_dropbox import __version__
from file_dropbox.config import ConfigError
from file_dropbox.config import load_config
from file_dropbox.config import new_password
from file_dropbox.config import new_token
from file_dropbox.config import read_config
from file_dropbox.config import save_config
from file_dropbox.security import hash_password
from file_dropbox.server import serve

MIN_PASSWORD_LENGTH = 12
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for ``file-dropbox``."""
    parser = argparse.ArgumentParser(
        prog="file-dropbox",
        description="A tiny authenticated file-drop server for your LAN.",
        epilog="Settings live in ./config.json, or wherever FILE_DROPBOX_CONFIG points.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.add_parser("serve", help="run the server (the default)")

    token = commands.add_parser("token", help="show or change the upload token")
    actions = token.add_subparsers(dest="action", metavar="ACTION")
    actions.required = True
    actions.add_parser("show", help="print the current upload token")
    actions.add_parser("rotate", help="replace it with a new random token")
    set_token = actions.add_parser("set", help="set a specific token")
    set_token.add_argument("value", metavar="TOKEN")

    # "admin-password" is the name older versions used.
    commands.add_parser("admin", aliases=["admin-password"], help="set the admin username and password")
    return parser


def token_command(action: str, value: Optional[str] = None) -> None:
    """Show, rotate or set the upload token in config.json."""
    cfg = read_config()
    if action == "show":
        print(cfg.get("api_token") or "(no token set)")
        return
    cfg["api_token"] = new_token() if action == "rotate" else value
    save_config(cfg)
    if action == "rotate":
        print("New upload token (restart the server, then give it to your clients):")
        print(f"  {cfg['api_token']}")
    else:
        print("Upload token set. Restart the server.")


def ask_admin_username(current: str) -> str:
    """Prompt for the admin username; an empty answer keeps ``current``.

    Raises:
        ConfigError: if the username isn't 3-64 letters, digits or ``. _ @ -``.
    """
    prompt = f"Admin username [{current}]: " if current else "Admin username: "
    username = input(prompt).strip() or current
    if not USERNAME_RE.match(username):
        raise ConfigError("Use 3 to 64 letters, digits or . _ @ - for the username. Nothing was changed.")
    return username


def ask_admin_password() -> str:
    """Prompt for a new admin password; an empty answer generates a random one.

    Raises:
        ConfigError: if the password is too short or the two entries differ.
    """
    password = getpass.getpass("New admin password (leave empty to generate one): ")
    if not password:
        password = new_password()
        print("Generated admin password (store it somewhere safe):")
        print(f"  {password}")
        return password
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ConfigError(f"Use at least {MIN_PASSWORD_LENGTH} characters. Nothing was changed.")
    if getpass.getpass("Repeat it: ") != password:
        raise ConfigError("The passwords don't match. Nothing was changed.")
    return password


def admin_command() -> None:
    """Store a new admin username and password hash in config.json."""
    cfg = read_config()
    username = ask_admin_username(cfg.get("admin_username", ""))
    cfg["admin_password_hash"] = hash_password(ask_admin_password())
    cfg["admin_username"] = username
    save_config(cfg)
    print(f"Admin sign-in updated for {username}. Restart the server to use it.")


def main(argv: Optional[List[str]] = None) -> int:
    """Run ``file-dropbox`` with ``argv`` (default: the real command line).

    Returns:
        The process exit code.
    """
    args = build_parser().parse_args(argv)
    try:
        if args.command in (None, "serve"):
            serve(load_config())
        elif args.command == "token":
            token_command(args.action, getattr(args, "value", None))
        elif args.command in ("admin", "admin-password"):
            admin_command()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0
