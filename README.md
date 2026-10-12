# 📮 file-dropbox

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tested with pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC?logo=pytest&logoColor=white)](test_server.py)
[![Last commit](https://img.shields.io/github/last-commit/vyahello/file-dropbox)](https://github.com/vyahello/file-dropbox/commits)

> A tiny, grumpy mailbox for your LAN. It takes files and doesn't chat.

`file-dropbox` is a single-file Python HTTP server that **accepts uploads and
nothing else**. Clients `POST` files with a shared token. The server sorts them
into a folder per client and writes down who sent what, when, and from where.

Knock with `GET` and you get a blank `404`, as if nobody lives here. Knock
without the token and you get turned away. Knock with the token and your file
goes in the pile.

- 🚪 **POST only.** `GET`, `PUT`, `DELETE` and friends all get a plain `404`.
  The server never tells anyone which methods it actually accepts.
- 🔑 **One shared token.** No token → `401`, wrong token → `403`.
- 🗂️ **A folder per client.** Named after `X-Client-Id`, or the sender's IP if
  they didn't introduce themselves.
- 📝 **Records everything.** Date, time, IP, OS, User-Agent, filename, size,
  content type.
- 🛡️ **Path traversal won't work.** `../../etc/passwd` gets saved as a file
  called `passwd`.
- 🪶 **Standard library only.** Python 3.8+, nothing to `pip install`.

---

## 🚀 Quick start

```bash
git clone https://github.com/vyahello/file-dropbox.git
cd file-dropbox
python3 server.py
```

The first run creates `config.json` with a fresh random token and prints it:

```
======================================================================
No config.json found -> created one with a fresh API token.
Shared bearer token (give it only to trusted clients, keep it secret):
  pX3...your-token...9Qk
======================================================================
File-drop server listening on http://0.0.0.0:47921
```

Copy the token and you're running. To send your first file from another
machine:

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

🎉 It's saved in `uploads/alice-laptop/`.

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

The OS is guessed from `User-Agent`. Browsers report it; `curl` doesn't, so it
shows up as `Unknown`.

### What the server can answer

| Code  | Meaning                                       |
|-------|-----------------------------------------------|
| `201` | Stored. 🎉                                    |
| `400` | Empty body, broken multipart, or no file found |
| `401` | No token                                      |
| `403` | Wrong token                                   |
| `404` | Wrong method or wrong path                    |
| `413` | Over `max_upload_bytes`                       |
| `503` | The server has no token configured            |

---

## ⚙️ Configuration

Everything lives in `config.json`, next to `server.py`:

```json
{
  "host": "0.0.0.0",
  "port": 47921,
  "upload_root": "uploads",
  "max_upload_bytes": 1073741824,
  "api_token": "<the shared token>"
}
```

| Key                | Default     | Notes                                                                  |
|--------------------|-------------|------------------------------------------------------------------------|
| `host`             | `0.0.0.0`   | All interfaces. Use one LAN IP to restrict it, or `127.0.0.1` for local only. |
| `port`             | `47921`     | Deliberately not 80 or 8080.                                           |
| `upload_root`      | `uploads`   | Relative to `server.py`, or an absolute path.                          |
| `max_upload_bytes` | 1 GiB       | Hard cap per request.                                                  |
| `api_token`        | random      | If empty, every upload is refused with `503`.                          |

### 🔑 Managing the token

```bash
python3 manage_token.py show        # print the current token
python3 manage_token.py rotate      # new random token; the old one stops working
python3 manage_token.py set MYTOKEN # set a specific token
```

Restart the server after changing the token.

---

## 🗄️ What gets stored

```
uploads/
├── _logs/
│   └── access.log                               # every request: time, event, IP, client, status
└── alice-laptop/
    ├── 20261010-153001-123456__report.pdf       # the file, timestamp-prefixed so nothing gets overwritten
    ├── 20261010-153001-123456__report.pdf.meta.json
    └── _uploads.jsonl                           # one metadata line per upload
```

Each `.meta.json` file (and each line in `_uploads.jsonl`) looks like this:

```json
{
  "client": "alice-laptop",
  "stored_name": "20261010-153001-123456__report.pdf",
  "original_filename": "report.pdf",
  "size": 20481,
  "content_type": "application/pdf",
  "received_at": "2026-10-10T15:30:01+00:00",
  "date": "2026-10-10",
  "time": "15:30:01 UTC",
  "source_ip": "192.168.1.42",
  "source_port": 51514,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "hostname_claimed": "alice-pc"
}
```

---

## 🧪 Running the tests

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/python -m pytest -v
```

The suite starts a real server on a random port. It covers auth, method
rejection, both upload styles, per-client folders, filename sanitizing, size
limits, logging and metadata.

---

## ⚠️ Before you trust it

- **It's plain HTTP.** Fine on a home LAN you trust. For anything sensitive,
  put it behind an HTTPS reverse proxy (Caddy, nginx) or a VPN, because the
  token travels in cleartext.
- **Everyone shares one token.** Anyone who has it can upload under any
  `X-Client-Id`. `source_ip` comes from the real socket; `X-Client-Id`,
  `X-Client-Host` and `os` are whatever the client says. Treat them as labels,
  not proof.
- **Bodies are held in memory** up to `max_upload_bytes`. Lower the cap on
  small machines.

---

Made for moving files around the house without emailing them to yourself. 📬
