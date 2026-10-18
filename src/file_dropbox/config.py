"""
Loading and saving config.json.

The config file is ``./config.json`` in the directory the server is started
from, unless the ``FILE_DROPBOX_CONFIG`` environment variable points somewhere
else (Docker keeps it in a mounted folder that way). Relative paths inside it,
such as ``upload_root``, are relative to the current directory as well.
"""

import json
import os
import secrets
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from file_dropbox.security import hash_password

Config = Dict[str, Any]

CONFIG_ENV = "FILE_DROPBOX_CONFIG"

DEFAULT_CONFIG: Config = {
    "host": "0.0.0.0",          # bind on all interfaces; see README for locking down
    "port": 47921,              # non-standard port (not 80/8080/21/etc.)
    "upload_root": "uploads",   # relative to the current directory, or absolute
    "max_upload_bytes": 1073741824,  # 1 GiB hard cap per request
    "api_token": "",            # single shared bearer token; generated on first run
    "admin_path": "/admin",     # owner's web UI; "" turns it off
    "admin_username": "",       # generated on first run; kept in plain text
    "admin_password_hash": "",  # PBKDF2 hash; generated on first run
    "session_minutes": 30,      # admin is signed out after this much idle time
    "secure_cookies": False,    # set true when served over HTTPS (reverse proxy)
    "max_failed_logins": 5,     # wrong tokens/passwords before an address is locked out
    "lockout_minutes": 15,      # ...and for how long
}


class ConfigError(Exception):
    """The config file is missing or can't be written. The message says how to fix it."""


def config_path() -> str:
    """Absolute path of the config file in use."""
    return os.path.abspath(os.environ.get(CONFIG_ENV) or "config.json")


def new_token() -> str:
    """A fresh random upload token."""
    return secrets.token_urlsafe(32)


def new_password() -> str:
    """A fresh random admin password."""
    return secrets.token_urlsafe(18)


def new_username() -> str:
    """A fresh admin username that isn't the guessable ``admin``."""
    return f"owner-{secrets.token_hex(3)}"


def permission_message(action: str, path: str) -> str:
    """Explain a permission error, naming the user the server runs as."""
    who = f"uid {os.getuid()}, gid {os.getgid()}" if hasattr(os, "getuid") else "this user"
    return (
        f"Can't {action} {path}: permission denied. It must belong to the user "
        f"running the server ({who}). Fix the owner with chown, or with Docker "
        "set DROPBOX_UID and DROPBOX_GID in .env to the folder's owner (see README)."
    )


def read_config(path: Optional[str] = None) -> Config:
    """Read an existing config file as-is.

    Raises:
        ConfigError: if the file doesn't exist yet, isn't readable or isn't valid JSON.
    """
    path = path or config_path()
    if not os.path.exists(path):
        raise ConfigError(f"{path} not found. Start the server once to create it.")
    try:
        with open(path) as fh:
            return json.load(fh)
    except PermissionError:
        raise ConfigError(permission_message("read", path)) from None
    except ValueError as exc:
        raise ConfigError(f"{path} isn't valid JSON: {exc}") from None


def save_config(cfg: Config, path: Optional[str] = None) -> None:
    """Write the config, readable by its owner only, since it holds secrets.

    Raises:
        ConfigError: if the file or its folder isn't writable.
    """
    path = path or config_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(cfg, fh, indent=2)
        os.chmod(path, 0o600)
    except PermissionError:
        raise ConfigError(permission_message("write", path)) from None


def load_config(path: Optional[str] = None) -> Config:
    """Load the config for the server, creating or completing it as needed.

    On first run this creates the file with a fresh upload token. Whenever the
    admin UI is on but has no username or password yet (first run, or an
    upgrade from an older version), it generates what's missing and prints it.
    The password is shown only once, since only its hash is stored; the
    username stays readable in the file. Missing keys are filled in from
    :data:`DEFAULT_CONFIG`.
    """
    path = path or config_path()
    created = not os.path.exists(path)
    if created:
        cfg = dict(DEFAULT_CONFIG)
        cfg["api_token"] = new_token()
    else:
        cfg = read_config(path)
        for key, val in DEFAULT_CONFIG.items():
            cfg.setdefault(key, val)

    notes: List[str] = []
    if created:
        notes += [
            f"No config found -> created {path} with a fresh upload token.",
            "Upload token (give it only to trusted clients, keep it secret):",
            f"  {cfg['api_token']}",
        ]
    if cfg["admin_path"] and not (cfg["admin_username"] and cfg["admin_password_hash"]):
        added_username = not cfg["admin_username"]
        if added_username:
            cfg["admin_username"] = new_username()
        username_line = f"  username: {cfg['admin_username']}"
        if added_username and cfg["admin_password_hash"]:
            username_line += "   (new: sign-in now asks for a username too)"
        if cfg["admin_password_hash"]:
            # Upgrade from a version without usernames. The password stays, but
            # only its hash is stored, so say that instead of printing nothing useful.
            password_lines = [
                "  password: the same admin password as before",
                "            (only its hash is stored, so it can't be shown here)",
                "Forgot the password? Set a new one with: file-dropbox admin",
            ]
        else:
            password = new_password()
            cfg["admin_password_hash"] = hash_password(password)
            password_lines = [
                f"  password: {password}   (shown only this once)",
                "Change them any time with: file-dropbox admin",
            ]
        notes += [
            f"Admin sign-in for the web UI at {cfg['admin_path']}:",
            username_line,
            *password_lines,
        ]
    if notes:
        save_config(cfg, path)
        print("=" * 70)
        print("\n".join(notes))
        print("=" * 70)
    return cfg
