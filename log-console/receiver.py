#!/usr/bin/env python3
"""Central console receiver (runs on the Mac).

Accepts batches of JSON-lines events from senders over HTTP(S), checks the
auth token and the SHA-256 of each batch, detects duplicate/missing batches,
and stores events in SQLite plus an append-only events.jsonl for the pipeline.

Standard library only.

Usage:
    export CONSOLE_TOKEN='long-random-string'
    python3 receiver.py --bind 0.0.0.0 --port 8443 --cert cert.pem --key key.pem
    (omit --cert/--key for plain HTTP on a trusted lab network only)
"""
import argparse
import gzip
import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 5 * 1024 * 1024  # 5 MB per batch (compressed)
LOCK = threading.Lock()


def load_env_file(path):
    """KEY=VALUE lines; real environment variables win."""
    if not path or not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def init_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute(
        "CREATE TABLE IF NOT EXISTS batches("
        "host TEXT, seq INTEGER, sha256 TEXT, received REAL, n_events INTEGER,"
        "PRIMARY KEY(host, seq))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS events("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, seq INTEGER,"
        "received REAL, event TEXT)"
    )
    db.commit()
    return db


class Handler(BaseHTTPRequestHandler):
    server_version = "LabConsole/1.0"

    def _reply(self, code, msg):
        body = json.dumps({"status": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[{time.strftime('%H:%M:%S')}] {self.client_address[0]} {fmt % args}")

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, "ok")
        else:
            self._reply(404, "not found")

    def do_POST(self):
        if self.path != "/ingest":
            return self._reply(404, "not found")

        # 1. Authenticate
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.server.token
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return self._reply(401, "unauthorized")

        # 2. Read body with a size cap
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._reply(400, "bad length")
        if length <= 0 or length > MAX_BODY:
            return self._reply(413, "bad or too-large body")
        raw = self.rfile.read(length)

        # 3. Decompress
        try:
            if self.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
        except Exception:
            return self._reply(400, "bad gzip")

        # 4. Integrity: SHA-256 of the decompressed batch must match header
        digest = hashlib.sha256(raw).hexdigest()
        if digest != self.headers.get("X-Batch-SHA256", ""):
            return self._reply(400, "hash mismatch")

        host = self.headers.get("X-Host", "")[:64]
        try:
            seq = int(self.headers.get("X-Batch-Seq", ""))
        except ValueError:
            return self._reply(400, "bad seq")
        if not host:
            return self._reply(400, "missing host")

        # 5. Parse events (one JSON object per line)
        events = []
        for line in raw.decode("utf-8-sig").splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                return self._reply(400, "bad json line")

        db = self.server.db
        now = time.time()
        with LOCK:
            # Duplicate batch (sender retried after a lost reply): accept, store nothing
            if db.execute(
                "SELECT 1 FROM batches WHERE host=? AND seq=?", (host, seq)
            ).fetchone():
                return self._reply(200, "duplicate")

            last = db.execute(
                "SELECT MAX(seq) FROM batches WHERE host=?", (host,)
            ).fetchone()[0]
            if last is not None and seq != last + 1:
                print(f"WARNING: {host} sequence gap: last={last}, got={seq}")

            db.execute(
                "INSERT INTO batches VALUES (?,?,?,?,?)",
                (host, seq, digest, now, len(events)),
            )
            db.executemany(
                "INSERT INTO events(host, seq, received, event) VALUES (?,?,?,?)",
                [(host, seq, now, json.dumps(e)) for e in events],
            )
            db.commit()

            with open(self.server.jsonl_path, "a", encoding="utf-8") as f:
                for e in events:
                    e.setdefault("_host", host)
                    f.write(json.dumps(e) + "\n")

        print(f"stored {len(events)} events from {host} (batch {seq})")
        self._reply(200, "stored")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1",
                    help="address to listen on (use your LAN/VM-facing IP, not 0.0.0.0 if avoidable)")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--db", default=os.path.join(HERE, "console.db"))
    ap.add_argument("--jsonl", default=os.path.join(HERE, "events_received.jsonl"))
    ap.add_argument("--env-file", default=os.path.join(HERE, "config.env"))
    args = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # logs appear at once when stdout is a file (launchd)

    load_env_file(args.env_file)
    token = os.environ.get("CONSOLE_TOKEN")
    if not token or len(token) < 16:
        raise SystemExit("Set CONSOLE_TOKEN (16+ characters) in the environment.")

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.token = token
    srv.db = init_db(args.db)
    srv.jsonl_path = args.jsonl

    scheme = "http"
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    else:
        print("WARNING: no TLS. Use only on an isolated lab network.")

    print(f"Console listening on {scheme}://{args.bind}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
