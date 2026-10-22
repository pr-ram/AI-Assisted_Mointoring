#!/usr/bin/env python3
"""Mask events on the Mac BEFORE anything is sent to Claude.  Standard library only.

    python3 mask_events.py --in events_received.jsonl --out masked_events.jsonl --map mask_map.json

What it does
  * Real names become stable tokens: USER_1, DEVICE_1, DOMAIN_1, EMAIL_1, TERM_1,
    INTERNAL_IP_1, GUID_1 ... The token <-> real-value table lives ONLY in mask_map.json
    (never send it, never commit it). The same real value always gets the same token,
    across runs, so USER_1 keeps meaning the same person.
  * Replaced everywhere inside every text field (paths, command lines, ...), including
    inside Base64 blobs (e.g. PowerShell -EncodedCommand), which are decoded, masked and
    re-encoded.
  * Private IPs -> INTERNAL_IP_n.  URLs lose user:password@, query strings and fragments;
    the path is kept / reduced to its extension / dropped (--url-paths).
  * Secrets in command lines (password=..., --token ..., Bearer ...) -> <REDACTED>.
  * System accounts (SYSTEM, LOCAL SERVICE, NT AUTHORITY\\...) are kept: they are not
    personal and matter for analysis.
  * Empty fields are dropped (smaller prompts = lower cost). Adds event_id and time (UTC).
  * Duplicates are removed and repeats of the same behaviour are merged into ONE event carrying
    count and last_time (so 40 identical DNS lookups become one event with count=40).
  * A leak check runs before writing. If any real value is still present, NOTHING is written.

Restore real names in Claude's answer (for the e-mail step):
    python3 mask_events.py --unmask-file alert.txt --map mask_map.json
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

SYSTEM_ACCOUNTS = {"system", "local service", "network service", "localservice",
                   "networkservice", "anonymous logon"}
SYSTEM_DOMAINS = {"nt authority", "nt service", "window manager", "font driver host",
                  "nt virtual machine"}
ENTITY_KINDS = {"USER", "DEVICE", "DOMAIN", "TERM"}
ALL_KINDS = "USER|DEVICE|DOMAIN|EMAIL|TERM|INTERNAL_IP|PUBLIC_IP|GUID"
SHORT = 5  # values shorter than this are matched as whole words only

DROP = {"Timestamp", "UtcTime", "RecordId", "Computer", "_host", "EventID", "event_id"}
GUID_FIELDS = {"ProcessGuid", "ParentProcessGuid"}
BLOB_FIELDS = {"CommandLine", "ParentCommandLine", "Base64Blob", "Details"}
EVENT_TYPES = {1: "process_create", 3: "network_connect", 5: "process_terminate",
               7: "image_load", 11: "file_create", 12: "registry_object",
               13: "registry_value_set", 14: "registry_rename", 22: "dns_query",
               23: "file_delete"}

TOKEN_SPLIT = re.compile(rf"((?:{ALL_KINDS})_\d+|<[A-Z_]+>)")
UNMASK_RE = re.compile(rf"\b(?:{ALL_KINDS})_\d+\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
USERPATH_RE = re.compile(r"(?i)([\\/]Users[\\/])([^\\/\s\"']+)")
SAFE_PROFILES = {"public", "default", "default user", "all users", "defaultuser0"}
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
SECRET_WORD = r"[A-Za-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)"
SECRET_KV = re.compile(rf"(?i)\b({SECRET_WORD})\b(\s*[=:]\s*)(?!(?:bearer|basic)\b)(\"[^\"]*\"|'[^']*'|\S+)")
SECRET_FLAG = re.compile(rf"(?i)(\s--?(?:{SECRET_WORD}|key)\s+)(\"[^\"]*\"|'[^']*'|\S+)")
CRED_FLAG = re.compile(r"(?i)(\s(?:-u|--user|--proxy-user)(?:\s+|=))(\"[^\"]*:[^\"]*\"|'[^']*:[^']*'|[^\s:]+:\S+)")
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


# ---------------------------------------------------------------- mapping table
class Mapper:
    def __init__(self, path):
        self.path = path
        self.counters, self.forward, self.reverse = {}, {}, {}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            self.counters = d.get("counters", {})
            self.forward = d.get("forward", {})
            self.reverse = d.get("reverse", {})

    def token(self, kind, real):
        key = f"{kind}|{real.lower()}"
        if key in self.forward:
            return self.forward[key]
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        tok = f"{kind}_{n}"
        self.forward[key] = tok
        self.reverse[tok] = real
        return tok

    def save(self):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # owner-only
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"counters": self.counters, "forward": self.forward,
                       "reverse": self.reverse}, f, indent=1)
        os.replace(tmp, self.path)


def unmask_text(text, mapper):
    return UNMASK_RE.sub(lambda m: mapper.reverse.get(m.group(0), m.group(0)), text)


# ---------------------------------------------------------------- masker
class Masker:
    def __init__(self, mapper, public_ips="keep", url_paths="ext", filenames="keep"):
        self.m = mapper
        self.public_ips, self.url_paths, self.filenames = public_ips, url_paths, filenames
        self.entity_re, self.entity_lookup = None, {}
        self.time_mismatch, self.mismatch_example = 0, None
        self.refresh()

    # ---- entities
    def refresh(self):
        self.entity_lookup = {}
        for tok, real in self.m.reverse.items():
            if tok.rsplit("_", 1)[0] in ENTITY_KINDS:
                self.entity_lookup[real.lower()] = tok
        parts = []
        for real in sorted(self.entity_lookup, key=len, reverse=True):
            p = re.escape(real)
            if len(real) < SHORT:
                p = rf"(?<![A-Za-z0-9]){p}(?![A-Za-z0-9])"
            parts.append(p)
        self.entity_re = re.compile("|".join(parts), re.I) if parts else None

    def collect(self, rec):
        """Pass 1: register every user / device / domain name found in a record."""
        comp = rec.get("Computer")
        for dev in (comp, rec.get("_host")):
            if isinstance(dev, str) and dev.strip():
                self.m.token("DEVICE", dev.strip())
        user = rec.get("User")
        if isinstance(user, str) and user.strip():
            dom, _, name = user.rpartition("\\")
            if dom.lower() in SYSTEM_DOMAINS or name.lower() in SYSTEM_ACCOUNTS:
                return
            if name.endswith("$"):
                self.m.token("DEVICE", name[:-1])
            elif name:
                self.m.token("USER", name)
            if dom and not (isinstance(comp, str) and dom.lower() == comp.lower()):
                self.m.token("DOMAIN", dom)

    # ---- string steps
    def _secrets(self, s):
        s = BEARER.sub(lambda m: f"{m.group(1)} <REDACTED>", s)  # before the key=value rule
        s = SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}<REDACTED>", s)
        s = SECRET_FLAG.sub(lambda m: f"{m.group(1)}<REDACTED>", s)
        return CRED_FLAG.sub(lambda m: f"{m.group(1)}<REDACTED>", s)

    def _urls(self, s):
        def fix(m):
            url, trail = m.group(0), ""
            while url and url[-1] in ".,;)]}":
                trail, url = url[-1] + trail, url[:-1]
            sp = urlsplit(url)
            netloc = sp.netloc.rsplit("@", 1)[-1]  # drop user:password@
            path = sp.path
            if path not in ("", "/"):
                if self.url_paths == "drop":
                    path = "/<PATH>"
                elif self.url_paths == "ext":
                    ext = os.path.splitext(path.rsplit("/", 1)[-1])[1]
                    path = "/<PATH>" + (ext if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", ext) else "")
            query = "?<QUERY>" if sp.query else ""
            return f"{sp.scheme}://{netloc}{path}{query}{trail}"
        return URL_RE.sub(fix, s)

    def _entities(self, s):
        if not self.entity_re:
            return s
        parts = TOKEN_SPLIT.split(s)  # never touch tokens/placeholders already inserted
        for i in range(0, len(parts), 2):
            parts[i] = self.entity_re.sub(lambda m: self.entity_lookup[m.group(0).lower()], parts[i])
        return "".join(parts)

    def _userpath(self, m):
        name = m.group(2)
        if re.fullmatch(rf"(?:{ALL_KINDS})_\d+", name) or name.lower() in SAFE_PROFILES:
            return m.group(0)
        return m.group(1) + self.m.token("USER", name)

    def _ip(self, m):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) == "255.255.255.255":
            return m.group(0)
        if ip.is_private or ip.is_link_local:
            return self.m.token("INTERNAL_IP", str(ip))
        if self.public_ips == "mask":
            return self.m.token("PUBLIC_IP", str(ip))
        return m.group(0)

    def mask_string(self, s):
        s = self._entities(s)  # first, on the untouched original text
        s = self._urls(s)      # drops user:password@ and ?query before the secret rules run
        s = self._secrets(s)
        s = EMAIL_RE.sub(lambda m: self.m.token("EMAIL", m.group(0)), s)
        s = USERPATH_RE.sub(self._userpath, s)
        return IPV4_RE.sub(self._ip, s)

    def mask_blobs(self, s):
        def fix(m):
            b = m.group(0)
            core = b.rstrip("=")
            try:
                raw = base64.b64decode(core + "=" * (-len(core) % 4), validate=True)
            except Exception:
                return b
            for enc in ("utf-16-le", "utf-8"):
                try:
                    txt = raw.decode(enc)
                except UnicodeDecodeError:
                    continue
                if txt and sum(c.isprintable() or c in "\r\n\t" for c in txt) / len(txt) >= 0.95:
                    new_raw = (self.mask_string(txt)).encode(enc)
                    new_raw = self.mask_bytes(new_raw)   # also catches names at another byte alignment
                    return base64.b64encode(new_raw).decode() if new_raw != raw else b
            # Not readable text: a binary container with text inside (e.g. the /SESSION: argument
            # Windows 11 Notepad passes to itself, which holds the full path of the open file).
            # Replace the known names inside the raw bytes instead.
            new_raw = self.mask_bytes(raw)
            return base64.b64encode(new_raw).decode() if new_raw != raw else b
        return B64_RE.sub(fix, s)

    def mask_bytes(self, raw):
        """Replace known user/device/domain names inside binary data (UTF-16LE and UTF-8 forms).
        Names shorter than SHORT characters are skipped here (too easy to hit by chance);
        the leak check still looks for them."""
        for enc in ("utf-16-le", "utf-8"):
            reals = [r for r in self.entity_lookup if len(r) >= SHORT]
            if not reals:
                break
            reals.sort(key=len, reverse=True)
            pat = re.compile(b"|".join(re.escape(r.encode(enc)) for r in reals), re.I)
            def sub(m, enc=enc):
                real = m.group(0).decode(enc).lower()
                return self.entity_lookup[real].encode(enc)
            raw = pat.sub(sub, raw)
        return raw

    # ---- record
    def _time(self, rec):
        ts, ut = rec.get("Timestamp"), rec.get("UtcTime")
        if not isinstance(ts, str):
            return None
        try:
            t = datetime.fromisoformat(ts).astimezone(timezone.utc)
        except ValueError:
            return None
        if isinstance(ut, str):
            try:
                u = datetime.fromisoformat(ut).replace(tzinfo=timezone.utc)
                if abs((u - t).total_seconds()) > 120:
                    self.time_mismatch += 1
                    self.mismatch_example = self.mismatch_example or (rec.get("RecordId"), ts, ut)
            except ValueError:
                pass
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def mask_record(self, rec):
        dev_real = rec.get("Computer") or rec.get("_host")
        device = self.m.token("DEVICE", dev_real.strip()) if isinstance(dev_real, str) and dev_real.strip() else None
        if rec.get("event_id") not in (None, ""):
            eid = str(rec["event_id"])
        elif rec.get("RecordId") is not None and device:
            eid = f"{device}-{rec['RecordId']}"
        else:
            eid = None
        out = {}
        if eid:
            out["event_id"] = eid
        t = self._time(rec)
        if t:
            out["time"] = t
        if device:
            out["device"] = device
        sid = rec.get("EventID")
        if isinstance(sid, int) or (isinstance(sid, str) and sid.isdigit()):
            sid = int(sid)
            out["event_type"] = EVENT_TYPES.get(sid, f"sysmon_{sid}")
            out["sysmon_event_id"] = sid
        for k, v in rec.items():
            if k in DROP or v is None or v == "" or v == "-":
                continue
            if isinstance(v, str):
                if k in GUID_FIELDS:
                    v = self.m.token("GUID", v)
                elif k != "Hashes":
                    v = self.mask_string(v)
                    if k in BLOB_FIELDS:
                        v = self.mask_blobs(v)
                    if k == "TargetFilename" and self.filenames == "ext":
                        head, _, last = v.rpartition("\\")
                        ext = os.path.splitext(last)[1]
                        v = f"{head}\\<FILE>{ext}" if head else f"<FILE>{ext}"
            out[k] = v
        return out


# ---------------------------------------------------------------- leak check
def leak_check(out_text, mapper, public_ips):
    scan = out_text
    raws = []
    for m in B64_RE.finditer(out_text):  # look inside Base64 blobs too
        core = m.group(0).rstrip("=")
        try:
            raw = base64.b64decode(core + "=" * (-len(core) % 4), validate=True)
        except Exception:
            continue
        raws.append(raw)
        for enc in ("utf-16-le", "utf-8"):
            try:
                scan += "\n" + raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
    kinds = ENTITY_KINDS | {"EMAIL", "INTERNAL_IP"} | ({"PUBLIC_IP"} if public_ips == "mask" else set())
    found = []
    for tok, real in mapper.reverse.items():
        if tok.rsplit("_", 1)[0] not in kinds or len(real) < 3:
            continue
        p = re.escape(real)
        if len(real) < SHORT:
            p = rf"(?<![A-Za-z0-9]){p}(?![A-Za-z0-9])"
        if re.search(p, scan, re.I):
            found.append(tok)
            continue
        # raw bytes of binary blobs, at any alignment (the text decode above can miss odd offsets)
        for raw in raws:
            if (len(real) >= 3 and re.search(re.escape(real.encode("utf-16-le")), raw, re.I)) or \
               (len(real) >= SHORT and re.search(re.escape(real.encode("utf-8")), raw, re.I)):
                found.append(tok)
                break
    return found


# ---------------------------------------------------------------- main
# Fields that differ on every occurrence of the same behaviour; ignored when deciding "same event"
VOLATILE = {"event_id", "time", "last_time", "count", "ProcessId", "ParentProcessId", "ProcessGuid",
            "ParentProcessGuid", "LogonId", "LogonGuid", "SourcePort", "QueryResults", "CreationUtcTime"}


def consolidate(masked):
    """1) drop exact duplicates (same event_id seen twice: resent batch, overlapping collection window)
       2) merge repeats of the same behaviour (same masked content apart from VOLATILE fields) into ONE event
          that keeps the first occurrence and adds  count  and  last_time.
    Returns (unique_events, {"exact_dups": n, "merged": n})."""
    seen_ids, groups, order, exact = set(), {}, [], 0
    for e in masked:
        eid = e.get("event_id")
        if eid and eid in seen_ids:
            exact += 1
            continue
        if eid:
            seen_ids.add(eid)
        key = json.dumps({k: v for k, v in e.items() if k not in VOLATILE}, sort_keys=True, ensure_ascii=False)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"event": dict(e), "count": 1, "first": e.get("time"), "last": e.get("time")}
            order.append(key)
        else:
            g["count"] += 1
            t = e.get("time")
            if t and (not g["first"] or t < g["first"]):
                g["first"] = t
            if t and (not g["last"] or t > g["last"]):
                g["last"] = t
    out, merged = [], 0
    for key in order:
        g = groups[key]
        ev = g["event"]
        if g["first"]:
            ev["time"] = g["first"]
        if g["count"] > 1:
            ev["count"] = g["count"]
            ev["last_time"] = g["last"]
            merged += g["count"] - 1
        out.append(ev)
    return out, {"exact_dups": exact, "merged": merged}


def mask_batch(records, mapper, public_ips="keep", url_paths="ext", filenames="keep", terms=(), unique=True):
    """Mask a list of event dicts. Returns (masked_dicts, stats). Raises LeakError if a real value survives."""
    mk = Masker(mapper, public_ips, url_paths, filenames)
    for term in terms:
        if term.strip():
            mapper.token("TERM", term.strip())
    for rec in records:
        mk.collect(rec)
    mk.refresh()
    masked = [mk.mask_record(rec) for rec in records]
    mk.refresh()
    if unique:
        out, cst = consolidate(masked)
    else:
        out, cst = masked, {"exact_dups": 0, "merged": 0}
    text = "\n".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in out)
    leaks = leak_check(text, mapper, public_ips)
    if leaks:
        raise LeakError(leaks)
    return out, {"in": len(records), "out": len(out), "dups": cst["exact_dups"], "merged": cst["merged"], "time_mismatch": mk.time_mismatch, "mismatch_example": mk.mismatch_example}


class LeakError(Exception):
    def __init__(self, leaks):
        super().__init__("real values still present: " + ", ".join(leaks))
        self.leaks = leaks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", help="events_received.jsonl")
    ap.add_argument("--out", help="masked output: .json = one JSON array of unique events, .jsonl = one per line")
    ap.add_argument("--map", default="mask_map.json", help="token table (keep private)")
    ap.add_argument("--sensitive", nargs="*", default=[], metavar="TEXT",
                    help="extra words to hide everywhere (names, school, street ...)")
    ap.add_argument("--public-ips", choices=["keep", "mask"], default="keep")
    ap.add_argument("--url-paths", choices=["keep", "ext", "drop"], default="ext",
                    help="keep the URL path, keep only its file extension (default), or drop it")
    ap.add_argument("--filenames", choices=["keep", "ext"], default="keep",
                    help="ext: hide the base name of TargetFilename, keep folder and extension")
    ap.add_argument("--no-consolidate", action="store_true",
                    help="keep every event (default: drop duplicates and merge repeats into one event with a count)")
    ap.add_argument("--unmask-file", help="restore real names in this text file ('-' = stdin)")
    args = ap.parse_args()

    mapper = Mapper(args.map)
    if args.unmask_file:
        text = sys.stdin.read() if args.unmask_file == "-" else open(args.unmask_file, encoding="utf-8").read()
        sys.stdout.write(unmask_text(text, mapper))
        return 0
    if not args.inp or not args.out:
        ap.error("--in and --out are required")

    records, bad = [], 0
    with open(args.inp, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8-sig", "replace").strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                bad += 1
    try:
        out, st = mask_batch(records, mapper, args.public_ips, args.url_paths, args.filenames,
                             args.sensitive, unique=not args.no_consolidate)
    except LeakError as e:
        print(f"STOP: {len(e.leaks)} real value(s) still present in the output: {', '.join(e.leaks)}.\n"
              "Nothing was written. Add them with --sensitive, or report the case.", file=sys.stderr)
        return 3

    if args.out.lower().endswith(".jsonl"):
        out_text = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in out)
    else:  # .json (default): one JSON array of the final unique events
        out_text = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(out_text)
    os.replace(tmp, args.out)
    mapper.save()

    kinds = {}
    for tok in mapper.reverse:
        k = tok.rsplit("_", 1)[0]
        kinds[k] = kinds.get(k, 0) + 1
    print(f"read {st['in']} events -> wrote {st['out']} unique masked events to {args.out}")
    print(f"removed: {st['dups']} exact duplicates (same event id), {st['merged']} repeats merged "
          f"(same behaviour; kept once with count and last_time); {bad} unreadable lines skipped")
    print("tokens in map: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"leak check passed. Rough size: {len(out_text)//4:,} tokens "
          f"(estimate: 4 characters per token)")
    if st["time_mismatch"]:
        rid, ts, ut = st["mismatch_example"]
        print(f"NOTE: {st['time_mismatch']} events have a Sysmon UtcTime that differs from the event-log "
              f"Timestamp by more than 2 minutes (e.g. RecordId {rid}: Timestamp {ts}, UtcTime {ut}). "
              f"'time' uses the event-log Timestamp.")
    print(f"Keep {args.map} private: it can reverse the masking.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
