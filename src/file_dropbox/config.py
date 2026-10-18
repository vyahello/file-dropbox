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


def read_config(path: Optional[str] = None) -> Config:
    """Read an existing config file as-is.

    Raises:
        ConfigError: if the file doesn't exist yet.
    """
    path = path or config_path()
    if not os.path.exists(path):
        raise ConfigError(f"{path} not found. Start the server once to create it.")
    with open(path) as fh:
        return json.load(fh)


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
        raise ConfigError(
            f"Can't write {path}: permission denied. "
            "Make sure that folder belongs to the user running the server."
        ) from None


def load_config(path: Optional[str] = None) -> Config:
    """Load the config for the server, creating or completing it as needed.

    On first run this creates the file with a fresh upload token. Whenever the
    admin UI is on but has no password yet (first run, or an upgrade from an
    older version), it generates one, stores only its hash and prints the
    password once. Missing keys are filled in from :data:`DEFAULT_CONFIG`.
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
    if cfg["admin_path"] and not cfg["admin_password_hash"]:
        password = new_password()
        cfg["admin_password_hash"] = hash_password(password)
        notes += [
            f"Admin password for the web UI at {cfg['admin_path']} (shown only this once):",
            f"  {password}",
            "Change it any time with: file-dropbox admin-password",
        ]
    if notes:
        save_config(cfg, path)
        print("=" * 70)
        print("\n".join(notes))
        print("=" * 70)
    return cfg
