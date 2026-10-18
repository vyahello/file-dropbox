"""
file-dropbox: a tiny authenticated file-drop server for your LAN.

Clients POST files with a shared token; the owner browses them in a
password-protected admin page. Standard library only.

Modules
-------
- :mod:`file_dropbox.cli`      command line: ``file-dropbox`` / ``python -m file_dropbox``
- :mod:`file_dropbox.config`   loading and saving config.json
- :mod:`file_dropbox.server`   the HTTP server and upload endpoint
- :mod:`file_dropbox.admin`    the owner's admin web UI
- :mod:`file_dropbox.storage`  how uploads are laid out on disk
- :mod:`file_dropbox.security` password hashing, lockout, sessions
"""

__version__ = "1.0.0"
