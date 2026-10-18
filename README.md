# 📮 file-dropbox

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](compose.yaml)
[![Tested with pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC?logo=pytest&logoColor=white)](tests)
[![Last commit](https://img.shields.io/github/last-commit/vyahello/file-dropbox)](https://github.com/vyahello/file-dropbox/commits)

> A tiny, grumpy mailbox for your LAN. It takes files and doesn't chat.

`file-dropbox` is a small Python HTTP server that **accepts uploads and
nothing else**. Clients `POST` files with a shared token. The server sorts them
into a folder per client and writes down who sent what, when, and from where.

Knock with `GET` and you get a blank `404`, as if nobody lives here. Knock
without the token and you get turned away. Knock too many times with the wrong
token and the door stays shut for a while. Knock with the right token and your
file goes in the pile.

The owner gets a key to the back door: a password-protected admin page to see
everything that arrived, on a laptop or a phone.

- 🚪 **POST only.** `GET`, `PUT`, `DELETE` and friends all get a plain `404`.
  The server never tells anyone which methods it actually accepts.
- 🔑 **One shared token.** No token → `401`, wrong token → `403`.
- 🧱 **Brute-force lockout.** 5 wrong tokens or passwords in 15 minutes and
  that address is locked out for 15 minutes (`429`).
- 🔐 **Admin page for the owner.** Browse clients, read text files, view
  images, download anything, watch recent activity.
- 🗂️ **A folder per client.** Named after `X-Client-Id`, or the sender's IP if
  they didn't introduce themselves.
- 📝 **Records everything.** Time, IP, User-Agent, filename, size and content
  type, all in one JSONL index per client.
- 🛡️ **Path traversal won't work.** `../../etc/passwd` gets saved as a file
  called `passwd`.
- 🐳 **Runs in Docker** with uploads and config kept on your machine.
- 🪶 **Standard library only.** Python 3.8+, nothing to `pip install`.

---

## 🚀 Quick start

Pick one.

**With Python:**

```bash
git clone https://github.com/vyahello/file-dropbox.git
cd file-dropbox
python3 -m venv .venv
source .venv/bin/activate
pip install .
file-dropbox
```

There are no dependencies to download: `pip install .` only installs
file-dropbox itself and gives you the `file-dropbox` command. Rather not
install anything? `PYTHONPATH=src python3 -m file_dropbox` runs it straight
from the checkout.

**With Docker:**

```bash
git clone https://github.com/vyahello/file-dropbox.git
cd file-dropbox
mkdir -p uploads config
docker compose up -d
docker compose logs   # shows the token and admin password, see below
```

The first run creates `config.json` with a fresh upload token and admin
password, and prints both:

```
======================================================================
No config found -> created config.json with a fresh upload token.
Upload token (give it only to trusted clients, keep it secret):
  pX3...your-token...9Qk
Admin password for the web UI at /admin (shown only this once):
  Fq7...your-password...2wE
Change it any time with: file-dropbox admin-password
======================================================================
File-drop server listening on http://0.0.0.0:47921
```

Save the admin password somewhere safe. Only its hash is stored, so it won't
be printed again (you can always set a new one).

To send your first file from another machine:

```bash
curl -X POST http://SERVER_IP:47921/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Client-Id: alice-laptop" \
  -H "X-Filename: cat.jpg" \
  --data-binary @cat.jpg
```

```json
{
  "status": "stored",
  "client": "alice-laptop",
  "files": [ { "original_filename": "cat.jpg", "size": 48213, "...": "..." } ]
}
```

🎉 It's saved as `uploads/alice-laptop/<today>/cat.jpg`. Open
`http://SERVER_IP:47921/admin/` to see it.

---

## 📤 Sending files

You need the token on every request. Pick whichever header you like:

```
Authorization: Bearer YOUR_TOKEN
X-API-Key: YOUR_TOKEN
```

**Raw body.** The simplest option, one file per request:

```bash
curl -X POST http://SERVER_IP:47921/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Client-Id: alice-laptop" \
  -H "X-Filename: report.pdf" \
  --data-binary @report.pdf
```

**Multipart form.** Works with ordinary upload tooling, and you can send
several files at once:

```bash
curl -X POST http://SERVER_IP:47921/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Client-Id: alice-laptop" \
  -F "file=@report.pdf" \
  -F "file=@slides.pptx"
```

**From Python:**

```python
import urllib.request

with open("report.pdf", "rb") as fh:
    req = urllib.request.Request(
        "http://SERVER_IP:47921/upload",
        data=fh.read(),
        headers={
            "Authorization": "Bearer YOUR_TOKEN",
            "X-Client-Id": "alice-laptop",
            "X-Filename": "report.pdf",
        },
    )
print(urllib.request.urlopen(req).read().decode())
```

### Optional headers

| Header          | What it does                                            |
|-----------------|---------------------------------------------------------|
| `X-Client-Id`   | Names your folder. Defaults to `ip-<your-ip>`.          |
| `X-Client-Host` | Records your hostname in the metadata.                  |
| `X-Filename`    | Filename for raw-body uploads. Defaults to `upload.bin`. |

### What the server can answer

| Code  | Meaning                                                    |
|-------|------------------------------------------------------------|
| `201` | Stored. 🎉                                                 |
| `400` | Empty body, broken multipart, or no file found             |
| `401` | No token                                                   |
| `403` | Wrong token                                                |
| `404` | Wrong method or wrong path                                 |
| `413` | Over `max_upload_bytes`                                    |
| `429` | Too many wrong tokens from your address. See `Retry-After` |
| `503` | The server has no token configured                         |

---

## 🔐 The admin page

Open `http://SERVER_IP:47921/admin/` and sign in with the admin password.

- **Mailbox:** every client as a pigeonhole (file count, total size, last
  delivery) and the latest server activity: deliveries, wrong tokens,
  blocked addresses, sign-ins.
- **A client:** its files grouped by day, newest first, with a filename filter.
- **A file:** when it arrived, who sent it (IP, port, User-Agent, claimed
  hostname), and a preview. Text files are shown with line numbers, images are
  displayed, anything else can be downloaded.

It works on phones too, and follows your system's light or dark theme.

**Why a separate password and not the upload token?** Every client has the
upload token. If it also opened the admin page, any client could read every
other client's files. The admin password stays with the owner.

**How it's protected:**

- The password is stored only as a salted PBKDF2-SHA256 hash (600,000 rounds).
- 5 wrong passwords in 15 minutes locks your address out for 15 minutes. Wrong
  upload tokens count towards the same limit.
- Sessions use an `HttpOnly`, `SameSite=Strict` cookie and end after 30
  minutes of inactivity. Restarting the server signs everyone out.
- Forms from other sites are refused, and signing out needs a CSRF token.
- Pages carry a strict Content-Security-Policy (no scripts at all), can't be
  framed, and are never cached.
- Uploaded files are never rendered as web pages. Text is escaped, only
  raster images are shown inline, and everything else downloads as a file.
  This keeps a malicious upload (say, an HTML file with a script) from
  running in your browser.
- Only files inside `uploads/` are reachable. Symlinks and the `_logs` folder
  are off limits.

Forgot the password, or want your own?

```bash
file-dropbox admin-password
docker compose exec file-dropbox file-dropbox admin-password   # with Docker
```

Type a new one (at least 12 characters) or press Enter to generate one, then
restart the server.

Don't want an admin page at all? Set `"admin_path": ""` and every `GET` is a
`404` again.

---

## 🐳 Running with Docker

`compose.yaml` builds a small image and mounts two folders from the directory
you start it in:

| On your machine | In the container | What's in it                                   |
|-----------------|------------------|------------------------------------------------|
| `./uploads`     | `/app/uploads`   | Every uploaded file, the index and the logs    |
| `./config`      | `/app/config`    | `config.json` with the token and password hash |

Uploads land straight in `./uploads`, so they're on your disk and survive
rebuilds, restarts and `docker compose down`.

```bash
mkdir -p uploads config          # create them first so they belong to you, not root
docker compose up -d             # build and start in the background
docker compose logs -f           # watch requests come in
docker compose restart           # after changing config.json
docker compose down              # stop
```

Good to know:

- **Your user id.** The container runs as uid/gid `1000`, so the files it
  writes belong to you. If `id -u` prints something else, create a `.env`
  file next to `compose.yaml`:

  ```
  DROPBOX_UID=1001
  DROPBOX_GID=1001
  ```

- **Already running without Docker?** Move your config into the mounted
  folder to keep the same token: `mkdir -p config && mv config.json config/`.
  Your existing `uploads/` folder is picked up as it is.
- **Changing the port.** Change both `port` in `config/config.json` and the
  `ports:` line in `compose.yaml`. Leave `host` as `0.0.0.0` inside the container.
- **Hardened by default.** The container runs as a non-root user with a
  read-only filesystem, no Linux capabilities and `no-new-privileges`. The
  only writable places are the two mounts.
- **Secrets stay out of the image.** `.dockerignore` keeps `config/`,
  `uploads/` and `.env` out of the build.

---

## ⚙️ Configuration

Everything lives in `config.json` in the folder you start the server from (or
in `./config/` with Docker). Set `FILE_DROPBOX_CONFIG` to keep it somewhere else.

```json
{
  "host": "0.0.0.0",
  "port": 47921,
  "upload_root": "uploads",
  "max_upload_bytes": 1073741824,
  "api_token": "<the shared token>",
  "admin_path": "/admin",
  "admin_password_hash": "pbkdf2_sha256$600000$...",
  "session_minutes": 30,
  "secure_cookies": false,
  "max_failed_logins": 5,
  "lockout_minutes": 15
}
```

| Key                   | Default   | Notes                                                                          |
|-----------------------|-----------|--------------------------------------------------------------------------------|
| `host`                | `0.0.0.0` | All interfaces. Use one LAN IP to restrict it, or `127.0.0.1` for local only.  |
| `port`                | `47921`   | Deliberately not 80 or 8080.                                                   |
| `upload_root`         | `uploads` | Relative to the folder you start the server from, or an absolute path.         |
| `max_upload_bytes`    | 1 GiB     | Hard cap per request.                                                          |
| `api_token`           | random    | If empty, every upload is refused with `503`.                                  |
| `admin_path`          | `/admin`  | Where the admin page lives. Pick something less guessable if you like. `""` turns it off. |
| `admin_password_hash` | generated | Set it with `file-dropbox admin-password`, never by hand.                      |
| `session_minutes`     | `30`      | Idle time before the admin is signed out.                                      |
| `secure_cookies`      | `false`   | Set `true` when the server is behind HTTPS, so the cookie is never sent over plain HTTP. |
| `max_failed_logins`   | `5`       | Wrong tokens or passwords allowed per address...                              |
| `lockout_minutes`     | `15`      | ...within this window, and how long the lockout lasts.                         |

The server writes `config.json` with `0600` permissions, since it holds
secrets. It's in `.gitignore`, so keep it out of git.

### 🔑 Managing secrets

```bash
file-dropbox token show          # print the current upload token
file-dropbox token rotate        # new random upload token; the old one stops working
file-dropbox token set MYTOKEN   # set a specific upload token
file-dropbox admin-password      # set or generate a new admin password
file-dropbox --help              # everything else
```

Restart the server after any change. With Docker, prefix the command with
`docker compose exec file-dropbox`.

---

## 🗄️ What gets stored

One folder per client, one subfolder per day, and the files keep their real
names:

```
uploads/
├── _logs/
│   └── access.log              # every request: time, event, IP, client, status
└── alice-laptop/
    ├── uploads.jsonl           # the index: one metadata line per file
    ├── 2026-10-14/
    │   └── report.pdf
    └── 2026-10-15/
        ├── LICENSE.txt
        ├── LICENSE-1.txt       # same name sent twice? it gets a suffix, nothing is overwritten
        └── cat.jpg
```

Each line in `uploads.jsonl` describes one file. `path` is relative to the
client folder:

```json
{
  "client": "alice-laptop",
  "path": "2026-10-15/LICENSE-1.txt",
  "original_filename": "LICENSE.txt",
  "size": 1071,
  "content_type": "text/plain",
  "received_at": "2026-10-15T16:30:03.424931+03:00",
  "source_ip": "192.168.1.42",
  "source_port": 51514,
  "user_agent": "curl/8.5.0",
  "hostname_claimed": "alice-pc"
}
```

The index is easy to query. For example, everything Alice sent today:

```bash
grep "$(date +%F)" uploads/alice-laptop/uploads.jsonl
```

---

## 🧭 Project layout

```
file-dropbox/
├── src/file_dropbox/      the package
│   ├── cli.py             the file-dropbox command
│   ├── config.py          loading and saving config.json
│   ├── server.py          HTTP server and the upload endpoint
│   ├── admin.py           the admin page: routes and HTML
│   ├── storage.py         how uploads are laid out on disk
│   ├── security.py        password hashing, lockout, sessions
│   └── static/            admin stylesheet and icon
├── tests/                 pytest suite
├── pyproject.toml         package metadata, the file-dropbox command, pytest settings
├── Dockerfile
└── compose.yaml
```

### Upgrading from the single-file version

Older versions were run as `python3 server.py` from the repository root.
Your `config.json` and `uploads/` stay exactly where they are. Only the
commands change:

| Before                                  | Now                           |
|-----------------------------------------|-------------------------------|
| `python3 server.py`                     | `file-dropbox`                |
| `python3 manage_token.py show`          | `file-dropbox token show`     |
| `python3 manage_token.py rotate`        | `file-dropbox token rotate`   |
| `python3 manage_token.py set TOKEN`     | `file-dropbox token set TOKEN` |
| `python3 manage_token.py admin-password` | `file-dropbox admin-password` |

Run them from the folder that holds `config.json` and `uploads/`, since
relative paths are resolved from where you start the command.

---

## 🧪 Running the tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

| File                     | Covers                                                                 |
|--------------------------|------------------------------------------------------------------------|
| `tests/test_server.py`   | Uploads: auth, lockout, method rejection, both upload styles, folders, size limits, logging |
| `tests/test_admin.py`    | Admin page: sign-in, lockout, cookies, CSRF and origin checks, browsing, previews, downloads, path traversal |
| `tests/test_storage.py`  | File names, writing without overwriting, listing and resolving stored files |
| `tests/test_cli.py`      | First-run config, upgrades, `0600` permissions, the token and admin-password commands |
| `tests/test_security.py` | Password hashing, the lockout limiter and sessions, with a fake clock  |

The server and admin tests start a real server on a random port.

---

## ⚠️ Before you trust it

- **It's plain HTTP.** Fine on a home LAN you trust. If the server is reachable
  from the internet, put it behind an HTTPS reverse proxy (Caddy, nginx) or a
  VPN. Otherwise the upload token *and the admin password* travel in
  cleartext. Behind HTTPS, set `"secure_cookies": true`.
- **Behind a reverse proxy, every request comes from the proxy's address.**
  The lockout then applies to everyone at once, because `X-Forwarded-For` is
  deliberately not trusted (anyone could fake it). Make the proxy pass the
  original `Host` header, or the admin forms will be refused as cross-site.
- **Everyone shares one token.** Anyone who has it can upload under any
  `X-Client-Id`. `source_ip` comes from the real socket; `X-Client-Id`,
  `X-Client-Host` and `user_agent` are whatever the client says. Treat them as
  labels, not proof.
- **Bodies are held in memory** up to `max_upload_bytes`. Lower the cap on
  small machines.

---

Made for moving files around the house without emailing them to yourself. 📬
