#!/usr/bin/env python3
"""Grounding check: are the details in Claude's explanation present in the events it cited?

pipeline.verify() already proves that every cited event id EXISTS. This module goes one step
further and checks the CONTENT of each finding (its title and its "why" text):

  * every domain / file name, IP address, port number and clock time mentioned must appear in the
    events the finding cites (details that appear only elsewhere in the batch are noted separately);
  * a repeat count ("count 48", "5 times") must equal the real `count` of a cited event;
  * the ATT&CK technique, if given, must look like T#### or T####.###.

It does NOT judge whether Claude's reasoning is right. It catches invented or misquoted details.
It works on the MASKED events (so tokens such as USER_1 match what Claude saw). Standard library only.

    import grounding
    g = grounding.check_finding(finding, by_id)    # by_id: {event_id: masked event}
    g["ok"], g["missing"], g["elsewhere"], g["count_mismatch"], g["technique_ok"], g["checked"]
"""
import json
import re

TOKEN = re.compile(r"\b(?:USER|DEVICE|DOMAIN|EMAIL|TERM|INTERNAL_IP|PUBLIC_IP|GUID)_\d+\b")
NAME = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.I)   # domains and file names
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PORT = re.compile(r"\bport\s+(\d{1,5})\b", re.I)
CLOCK = re.compile(r"\b\d{2}:\d{2}:\d{2}\b")
COUNT = [re.compile(r"\bcount(?:\s+of)?\s+(\d+)\b", re.I), re.compile(r"\b(\d+)\s+times\b", re.I)]
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _blob(events):
    return "\n".join(json.dumps(e, ensure_ascii=False).lower() for e in events)


def _claims(text):
    """Return a list of (kind, value) details found in a piece of explanation text."""
    text = TOKEN.sub(" ", text or "")
    out = []
    for m in NAME.finditer(text):
        out.append(("name", m.group(0).lower().rstrip(".")))
    for m in IPV4.finditer(text):
        out.append(("ip", m.group(0)))
    for m in PORT.finditer(text):
        out.append(("port", m.group(1)))
    for m in CLOCK.finditer(text):
        out.append(("time", m.group(0)))
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def check_finding(finding, by_id):
    """Check one verified finding. `by_id` maps event_id -> masked event (the whole batch)."""
    cited = [by_id[e] for e in finding.get("evidence", []) if e in by_id]
    cited_text, batch_text = _blob(cited), _blob(by_id.values())
    text = f"{finding.get('title', '')} {finding.get('why', '')}"

    missing, elsewhere = [], []
    claims = _claims(text)
    for kind, val in claims:
        if val in cited_text:
            continue
        (elsewhere if val in batch_text else missing).append(f"{kind} '{val}'")

    count_mismatch = []
    real_counts = {int(e.get("count", 1)) for e in cited if str(e.get("count", 1)).isdigit()}
    if real_counts:
        real_counts.add(sum(real_counts))
    claimed = []
    for rx in COUNT:
        for m in rx.finditer(text):
            n = int(m.group(1))
            if n not in claimed:
                claimed.append(n)
    for n in claimed:
        if n not in real_counts:
            count_mismatch.append(f"count {n} (events show {sorted(real_counts)})")

    tech = (finding.get("attack_technique") or "").strip()
    technique_ok = (not tech) or bool(TECHNIQUE.search(tech))

    checked = len(claims) + len(claimed) + (1 if tech else 0)
    return {"ok": not missing and not count_mismatch and technique_ok,
            "checked": checked, "missing": missing, "elsewhere": elsewhere,
            "count_mismatch": count_mismatch, "technique_ok": technique_ok}
