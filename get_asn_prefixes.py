#!/usr/bin/env python3
"""
get_asn_prefixes.py – pull live *and/or* historic IPv4/IPv6 prefixes for
one or more ASNs and guess who is announcing silent address space today.

Features
========
• Historic-fallback – even if an ASN is dark, its old space (RIPEstat lod=2)
  is returned so you can still build block-lists or geofences.
• Successor lookup
    1. RIPE DB `origin:` heuristic
    2. Per-prefix origin (RIPEstat ➜ BGPView ➜ IPinfo) with tunable sample
       size (`--sample 0` = check *all* historic prefixes).
• CSV / JSON export or stdout.
• Robust CLI parsing – commas, spaces, NBSP/NNBSP all work.

2025-06-22  v2.1  –  single file, Python 3.8+, deps: `requests`, `tqdm`
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
import unicodedata
from itertools import chain, islice
from pathlib import Path
from typing import Dict, Iterable, List, Set

import requests
from tqdm import tqdm

###############################################################################
# End-user tuneables
###############################################################################
TIMEOUT = 15         # seconds for every HTTP call
DEFAULT_SAMPLE = 40  # historic prefixes checked per ASN (0 = all)

###############################################################################
# Constant API endpoints
###############################################################################
RIPE_ANNOUNCED = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
)
PREFIX_OVERVIEW = (
    "https://stat.ripe.net/data/prefix-overview/data.json?resource={prefix}"
)
BGPVIEW_ASN = "https://api.bgpview.io/asn/{asn}/prefixes"
BGPVIEW_PREF = "https://api.bgpview.io/prefix/{prefix}"
IPINFO_ASN = "https://ipinfo.io/AS{asn}?token={token}"
IPINFO_PREF = "https://ipinfo.io/{prefix}?token={token}"
RIPE_DB_SEARCH = (
    "https://rest.db.ripe.net/search"
    "?type=inetnum&flags=no-referenced&query-string={asn}"
)

# split on ASCII/Unicode whitespace or commas
_SPLIT = re.compile(r"[\s,\u00A0\u202F]+", re.UNICODE)

###############################################################################
# General helpers
###############################################################################
def clean_asn_list(raw: Iterable[str]) -> List[str]:
    """Return distinct ['AS123', ...] list, tolerant of odd whitespace."""
    seen: Set[str] = set()
    out: List[str] = []
    for token in raw:
        token = unicodedata.normalize("NFKC", token)
        for part in _SPLIT.split(token.strip()):
            if not part:
                continue
            asn = part.upper() if part.lower().startswith("as") else f"AS{part}"
            if asn not in seen:
                seen.add(asn)
                out.append(asn)
    return out


###############################################################################
# Data fetchers
###############################################################################
def fetch_ripe_announced(asn: str, *, history: bool) -> Set[str]:
    url = RIPE_ANNOUNCED.format(asn=asn[2:]) + ("&lod=2" if history else "&lod=1")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            item.get("prefix") or item.get("resource")
            for item in data.get("prefixes", [])
        }
    except Exception:
        return set()


def fetch_bgpview(asn: str) -> Set[str]:
    try:
        r = requests.get(BGPVIEW_ASN.format(asn=asn[2:]), timeout=TIMEOUT)
        if r.ok and r.json().get("status") == "ok":
            d = r.json()["data"]
            return {
                p["prefix"]
                for p in chain(d.get("ipv4_prefixes", []), d.get("ipv6_prefixes", []))
            }
    except Exception:
        pass
    return set()


def fetch_ipinfo_asn(asn: str, token: str | None) -> Set[str]:
    if not token:
        return set()
    try:
        r = requests.get(IPINFO_ASN.format(asn=asn[2:], token=token), timeout=TIMEOUT)
        if r.ok:
            return set(r.json().get("prefixes", []))
    except Exception:
        pass
    return set()


###############################################################################
# Per-prefix origin helpers
###############################################################################
def origin_ripe(prefix: str) -> str | None:
    try:
        r = requests.get(PREFIX_OVERVIEW.format(prefix=prefix), timeout=TIMEOUT)
        if r.ok:
            asns = r.json().get("data", {}).get("asns", [])
            if asns:
                return f"AS{asns[0]['asn']}"
    except Exception:
        pass
    return None


def origin_bgpview(prefix: str) -> str | None:
    try:
        r = requests.get(BGPVIEW_PREF.format(prefix=prefix), timeout=TIMEOUT)
        if r.ok and r.json().get("status") == "ok":
            asn = r.json()["data"].get("origin_asn", {}).get("asn")
            if asn:
                return f"AS{asn}"
    except Exception:
        pass
    return None


def origin_ipinfo(prefix: str, token: str | None) -> str | None:
    if not token:
        return None
    try:
        r = requests.get(IPINFO_PREF.format(prefix=prefix, token=token), timeout=TIMEOUT)
        if r.ok and (org := r.json().get("org", "")).startswith("AS"):
            return org.split()[0]
    except Exception:
        pass
    return None


def prefix_origin(prefix: str, token: str | None) -> str | None:
    for fn in (origin_ripe, origin_bgpview, lambda p: origin_ipinfo(p, token)):
        o = fn(prefix)
        if o:
            return o
    return None


###############################################################################
# Successor detection
###############################################################################
def successor_from_ripe_db(asn: str) -> str | None:
    try:
        r = requests.get(
            RIPE_DB_SEARCH.format(asn=asn),
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.ok:
            origins = {
                a["value"].upper()
                for obj in r.json().get("objects", {}).get("object", [])
                for a in obj.get("attributes", {}).get("attribute", [])
                if a["name"].lower() == "origin" and a["value"].upper() != asn
            }
            return sorted(origins)[0] if origins else None
    except Exception:
        pass
    return None


def deep_successor(
    asn: str, *, token: str | None, sample: int, debug: bool
) -> str | None:
    hist = fetch_ripe_announced(asn, history=True)
    if not hist:
        return None
    iterable = islice(hist, sample) if sample > 0 else hist
    counter: collections.Counter[str] = collections.Counter()
    if debug:
        iterable = tqdm(list(iterable), desc=f"{asn} prefixes", leave=False)
    for pfx in iterable:
        o = prefix_origin(pfx, token)
        if debug:
            print(f"    [dbg] {pfx:<18} → {o}")
        if o and o != asn:
            counter[o] += 1
    return counter.most_common(1)[0][0] if counter else None


###############################################################################
# Core logic
###############################################################################
def collect_prefixes(asn: str, *, history: bool, token: str | None) -> Set[str]:
    """Return live prefixes if any, otherwise historic set."""
    for fn in (
        lambda a: fetch_ripe_announced(a, history=history),
        fetch_bgpview,
        lambda a: fetch_ipinfo_asn(a, token),
    ):
        pfx = fn(asn)
        if pfx:
            return pfx
    # final fallback → historic
    return fetch_ripe_announced(asn, history=True)


###############################################################################
# Output helpers
###############################################################################
def write_csv(rows: List[Dict[str, str]], path: Path):
    with path.open("w", newline="") as fh:
        csv.DictWriter(fh, fieldnames=["asn", "prefix"]).writerows(rows)


def write_json(rows: List[Dict[str, str]], path: Path):
    with path.open("w") as fh:
        json.dump(rows, fh, indent=2)


###############################################################################
# Main
###############################################################################
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fetch live or historic prefixes for ASNs, with successor detection."
    )
    ap.add_argument("asns", nargs="+", help="Comma/space list of ASNs (with or without 'AS').")
    ap.add_argument("--csv", help="Write CSV file")
    ap.add_argument("--json", help="Write JSON file")
    ap.add_argument("--token", help="IPinfo token")
    ap.add_argument("--history", action="store_true", help="Include historic prefixes")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress bars")
    ap.add_argument("--deep-successor", action="store_true", default=True, help="Enable deep successor hunt")
    ap.add_argument("--sample", type=int, default=DEFAULT_SAMPLE, help="Historic prefixes to sample (0 = all)")
    ap.add_argument("--debug", action="store_true", help="Verbose successor hunt")
    args = ap.parse_args()

    asn_list = clean_asn_list(args.asns)
    if not asn_list:
        sys.exit("[!] No valid ASNs supplied.")

    rows: List[Dict[str, str]] = []
    iterator = tqdm(asn_list, desc="ASNs") if not args.no_progress else asn_list

    for asn in iterator:
        prefixes = collect_prefixes(asn, history=args.history, token=args.token)
        if not prefixes:
            # completely silent ASN
            successor = successor_from_ripe_db(asn)
            if not successor and args.deep_successor:
                successor = deep_successor(
                    asn,
                    token=args.token,
                    sample=args.sample,
                    debug=args.debug,
                )
            if successor:
                print(f"[!] {asn} is silent; its space likely announced by {successor}")
            else:
                # don't suggest flags if they're already on
                print(f"[!] {asn} is silent; successor undetermined")
            continue

        for pfx in prefixes:
            rows.append({"asn": asn, "prefix": pfx})
            if args.no_progress:
                print(f"{asn},{pfx}")

    if not rows:
        sys.exit("[!] No prefixes found for any supplied ASN.")

    if args.csv:
        write_csv(rows, Path(args.csv))
        print(f"[+] CSV written → {args.csv}")
    if args.json:
        write_json(rows, Path(args.json))
        print(f"[+] JSON written → {args.json}")
    if not args.csv and not args.json and not args.no_progress:
        for row in rows:
            print(f"{row['asn']},{row['prefix']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)
