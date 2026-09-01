#!/usr/bin/env python3
"""Tests for the verdict logic in testbed-server.py.

This logic decides whether the phone check passed, so it must not be the untested part.
The dangerous case is the last one: an iOS build that ignored the name constraints has to
read as FAIL, never as a quiet success.

Run: python3 scripts/testbed-server-test.py
"""

import contextlib
import importlib.util
import io
import pathlib
import sys

MODULE = pathlib.Path(__file__).with_name("testbed-server.py")
spec = importlib.util.spec_from_file_location("testbed_server", MODULE)
tb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tb)

MANIFEST = {"cases": [
    {"name": "ok", "serverName": "ok.host", "url": "u1",
     "expectation": "valid", "sendsFullChain": False},
    {"name": "bad", "serverName": "bad.host", "url": "u2",
     "expectation": "invalid", "sendsFullChain": False},
    {"name": "ip", "serverName": "", "url": "u3",
     "expectation": "invalid", "sendsFullChain": False},
]}

# Mirrors the real r6 layout: two ways of building the path, side by side.
MIXED = {"cases": [
    {"name": "ok", "serverName": "ok.host", "url": "u1",
     "expectation": "valid", "sendsFullChain": False},
    {"name": "okfull", "serverName": "okfull.host", "url": "u2",
     "expectation": "valid", "sendsFullChain": True},
    {"name": "badfull", "serverName": "badfull.host", "url": "u3",
     "expectation": "invalid", "sendsFullChain": True},
    {"name": "bad", "serverName": "bad.host", "url": "u4",
     "expectation": "invalid", "sendsFullChain": False},
]}
PHONE = "INTERNAL_IP_05"
MAC = "192.168.1.4"
REJECTED = "handshake rejected by client"

failures = []


def verdicts_for(events, manifest=MANIFEST):
    observer = tb.Observer({MAC, "127.0.0.1"})
    with contextlib.redirect_stdout(io.StringIO()):      # record() also prints
        for client, sni, outcome in events:
            observer.record(client, sni, outcome)
    return {row["case"]: row["verdict"] for row in tb.verdicts(manifest, observer)}


def check(label, events, expected, manifest=MANIFEST):
    got = verdicts_for(events, manifest)
    status = "ok  " if got == expected else "FAIL"
    if got != expected:
        failures.append(f"{label}: expected {expected}, got {got}")
    print(f"  {status} {label}")


check("phone trusts the permitted host and rejects the others",
      [(PHONE, "ok.host", "served"),
       (PHONE, "bad.host", REJECTED),
       (PHONE, None, REJECTED)],
      {"ok": "PASS", "bad": "PASS", "ip": "PASS"})

# Safari offers "visit this website anyway". A click-through arrives as a completed
# handshake, so without ordering it is indistinguishable from trust — and every case
# below would read as a pass on a phone that trusts nothing.
check("warning on every case means the anchor is not trusted, not a bypass",
      [(PHONE, "ok.host", REJECTED), (PHONE, "ok.host", "served"),
       (PHONE, "bad.host", REJECTED), (PHONE, "bad.host", "served"),
       (PHONE, None, REJECTED), (PHONE, None, "served")],
      {"ok": "FAIL", "bad": "INVALID", "ip": "INVALID"})

check("override on a forbidden host does not spoil a valid run",
      [(PHONE, "ok.host", "served"),
       (PHONE, "bad.host", REJECTED), (PHONE, "bad.host", "served"),
       (PHONE, None, REJECTED)],
      {"ok": "PASS", "bad": "PASS", "ip": "PASS"})

check("iOS accepting an out-of-list certificate is a FAIL",
      [(PHONE, "ok.host", "served"),
       (PHONE, "bad.host", "served"),
       (PHONE, None, "served")],
      {"ok": "PASS", "bad": "FAIL", "ip": "FAIL"})

check("rejecting the permitted host is a FAIL, not a pass",
      [(PHONE, "ok.host", REJECTED)],
      {"ok": "FAIL", "bad": "NOT TESTED", "ip": "NOT TESTED"})

check("a rejection is INVALID, not PASS, when the control never passed",
      [(PHONE, "ok.host", REJECTED),
       (PHONE, "bad.host", REJECTED)],
      {"ok": "FAIL", "bad": "INVALID", "ip": "NOT TESTED"})

check("probes from the Mac itself prove nothing about the phone",
      [(MAC, "ok.host", "served"),
       (MAC, "bad.host", REJECTED)],
      {"ok": "NOT TESTED", "bad": "NOT TESTED", "ip": "NOT TESTED"})

check("no traffic at all is NOT TESTED, never PASS",
      [],
      {"ok": "NOT TESTED", "bad": "NOT TESTED", "ip": "NOT TESTED"})

check("a forbidden case is judged against a control that builds its path the same way",
      [(PHONE, "ok.host", REJECTED),
       (PHONE, "okfull.host", "served"),
       (PHONE, "badfull.host", REJECTED),
       (PHONE, "bad.host", REJECTED)],
      {"ok": "FAIL", "okfull": "PASS", "badfull": "PASS", "bad": "INVALID"},
      MIXED)

if failures:
    print("\n" + "\n".join(failures))
    sys.exit(1)
print("\nall verdict cases pass")
