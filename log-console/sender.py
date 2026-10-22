#!/usr/bin/env python3
"""Log sender (runs on each machine / the Windows VM).

Reads events from a file, groups them into batches, gzips them and POSTs them to
the central console with:
  - Bearer token authentication
  - SHA-256 of each batch (integrity)
  - per-host sequence numbers (detect lost/duplicate batches)
Batches that fail because of the network are kept in a local spool folder and
retried in order. Batches the console rejects as malformed (HTTP 400) are moved
to spool/rejected so they can never block later batches.

Two modes
  --mode append    (default) the file only grows (JSON Lines). Progress is remembered
                   per file as a byte offset.
  --mode snapshot  the file is REPLACED every cycle (e.g. latest_batch.json written
                   every 5 minutes, possibly overlapping the previous one). Every event
                   is fingerprinted; only events not sent before are sent.

Accepted input formats: JSON Lines, a JSON array, or one pretty-printed JSON object;
UTF-8 BOM, CRLF and UTF-16 are handled. The file is validated BEFORE anything is sent.

Settings may come from an env file (default: sender.env next to this script) with
lines KEY=VALUE, e.g. CONSOLE_TOKEN=... (real environment variables win).
Standard library only.

Usage (PowerShell):
    python sender.py --url https://192.168.64.1:8443 --file C:\\SecurityTools\\latest_batch.json ^
        --host VM-WIN11 --cafile cert.pem --mode snapshot
"""
import argparse
import gzip
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

BATCH_MAX_EVENTS = 500
SEEN_MAX = 50000


class SendError(Exception):
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


def load_env_file(path):
    if not path or not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


# ---------- state ----------
def load_state(path):
    try:
        with open(path) as f:
            s = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        s = {}
    s.setdefault("seq", 0)
    s.setdefault("offsets", {})
    s.setdefault("seen", [])
    return s


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


# ---------- input handling ----------
def read_normalized(path):
    """Whole file as UTF-8 bytes (UTF-16 and BOM handled)."""
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16").encode("utf-8")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:]
    return data


def extract_lines(data, offset):
    """Return (list_of_json_line_bytes, new_offset). Raises ValueError on bad input."""
    body = data[offset:]
    if offset == 0 and body.strip():
        try:
            doc = json.loads(body.decode("utf-8"))
        except ValueError:
            doc = None
        if isinstance(doc, list):
            return [json.dumps(e, separators=(",", ":")).encode() for e in doc], len(data)
        if isinstance(doc, dict):
            return [json.dumps(doc, separators=(",", ":")).encode()], len(data)

    end = body.rfind(b"\n")
    if end == -1:
        return [], offset  # no complete line yet
    chunk = body[: end + 1]
    first_line_no = data[:offset].count(b"\n") + 1
    out = []
    for i, line in enumerate(chunk.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line.decode("utf-8"))
        except ValueError:
            preview = line[:70].decode("utf-8", "replace")
            raise ValueError(
                f"line {first_line_no + i} is not valid JSON: {preview!r}\n"
                "Each line must be ONE complete JSON object. Nothing was sent."
            )
        out.append(line)
    return out, offset + len(chunk)


def event_key(line):
    obj = json.loads(line.decode("utf-8"))
    return hashlib.sha1(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------- network ----------
def post_batch(url, token, host, seq, raw, ctx):
    digest = hashlib.sha256(raw).hexdigest()
    req = urllib.request.Request(
        url.rstrip("/") + "/ingest",
        data=gzip.compress(raw),
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Encoding": "gzip",
            "Content-Type": "application/x-ndjson",
            "X-Host": host,
            "X-Batch-Seq": str(seq),
            "X-Batch-SHA256": digest,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        reason = e.read().decode("utf-8", "replace")[:200]
        raise SendError(f"HTTP {e.code}: {reason}", e.code) from None
    except (urllib.error.URLError, OSError) as e:
        raise SendError(str(e)) from None


def reject(spool, path, why):
    rejected = os.path.join(spool, "rejected")
    os.makedirs(rejected, exist_ok=True)
    os.replace(path, os.path.join(rejected, os.path.basename(path)))
    print(f"  console rejected this batch ({why}); moved to {rejected}")


def flush_spool(spool, url, token, host, ctx):
    for name in sorted(os.listdir(spool)):
        path = os.path.join(spool, name)
        if not os.path.isfile(path):
            continue
        seq = int(name.split(".")[0])
        with open(path, "rb") as f:
            raw = f.read()
        try:
            post_batch(url, token, host, seq, raw, ctx)
        except SendError as e:
            if e.code == 400:
                reject(spool, path, str(e))
                continue
            print(f"spool retry failed ({e}); will try later")
            return False
        os.remove(path)
        print(f"resent spooled batch {seq}")
    return True


def send_lines(args, state, spool, token, ctx, lines):
    for i in range(0, len(lines), BATCH_MAX_EVENTS):
        batch = lines[i : i + BATCH_MAX_EVENTS]
        raw = b"\n".join(batch) + b"\n"
        state["seq"] += 1
        seq = state["seq"]
        spool_path = os.path.join(spool, f"{seq:010d}.ndjson")
        with open(spool_path, "wb") as f:  # spool first: a crash can't lose it
            f.write(raw)
        try:
            post_batch(args.url, token, args.host, seq, raw, ctx)
            os.remove(spool_path)
            print(f"sent batch {seq} ({len(batch)} events)")
        except SendError as e:
            if e.code == 400:
                reject(spool, spool_path, str(e))
            else:
                print(f"send failed ({e}); batch {seq} kept in spool")


def send_append(args, state, spool, token, ctx):
    data = read_normalized(args.file)
    key = os.path.abspath(args.file)
    offset = state["offsets"].get(key, 0)
    if offset > len(data):  # file was replaced by a shorter one
        offset = 0
    lines, new_offset = extract_lines(data, offset)  # may raise ValueError
    send_lines(args, state, spool, token, ctx, lines)
    state["offsets"][key] = new_offset
    save_state(args.state, state)
    return len(lines)


def send_snapshot(args, state, spool, token, ctx):
    data = read_normalized(args.file)
    if not data.strip():
        return 0
    if not data.endswith(b"\n"):
        data += b"\n"
    lines, _ = extract_lines(data, 0)  # may raise ValueError
    seen = state["seen"]
    seen_set = set(seen)
    fresh, keys = [], []
    for line in lines:
        k = event_key(line)
        if k not in seen_set:
            seen_set.add(k)
            fresh.append(line)
            keys.append(k)
    send_lines(args, state, spool, token, ctx, fresh)
    seen.extend(keys)
    del seen[:-SEEN_MAX]
    save_state(args.state, state)
    return len(fresh)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="e.g. https://192.168.64.1:8443")
    ap.add_argument("--file", required=True, help="events file to send")
    ap.add_argument("--host", required=True, help="name of this machine")
    ap.add_argument("--cafile", help="receiver cert (for self-signed TLS)")
    ap.add_argument("--mode", choices=["append", "snapshot"], default="append")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--interval", type=int, default=10, help="seconds between polls")
    ap.add_argument("--state", default=os.path.join(here, "sender_state.json"))
    ap.add_argument("--spool", default=os.path.join(here, "spool"))
    ap.add_argument("--env-file", default=os.path.join(here, "sender.env"))
    args = ap.parse_args()

    load_env_file(args.env_file)
    token = os.environ.get("CONSOLE_TOKEN")
    if not token:
        sys.exit("Set CONSOLE_TOKEN in the environment or in sender.env.")
    ctx = ssl.create_default_context(cafile=args.cafile) if args.url.startswith("https") else None
    os.makedirs(args.spool, exist_ok=True)
    state = load_state(args.state)
    send = send_snapshot if args.mode == "snapshot" else send_append

    while True:
        flush_spool(args.spool, args.url, token, args.host, ctx)
        try:
            n = send(args, state, args.spool, token, ctx)
            if n == 0 and not args.follow:
                print("nothing new to send")
        except ValueError as e:
            print(f"ERROR in {args.file}: {e}")
            if not args.follow:
                sys.exit(2)
        except FileNotFoundError:
            print(f"ERROR: {args.file} does not exist")
            if not args.follow:
                sys.exit(2)
        if not args.follow:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
