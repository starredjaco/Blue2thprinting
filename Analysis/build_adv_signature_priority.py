#!/usr/bin/env python3
"""
Build the BLE advertisement signature -> deprioritization CSV that
central_app_launcher.py consumes when deciding whether a newly-discovered
device is a duplicate of one we already have full GATT data for.

Pipeline:
  1. Walk every .pcap under --pcap-dir, run tshark to dump per-packet AD
     entries, and aggregate per-bdaddr the set of "stable" advertisement
     fields (UUIDs, MSD company IDs, Service Data UUIDs, flags, etc.).
     Volatile / device-unique fields (names, target addresses, MSD payload
     bytes, etc.) are intentionally excluded — see SIGNATURE_DESIGN below.
  2. Normalise each bdaddr's component-set into a deterministic signature
     string and count how many distinct bdaddrs produce each signature.
  3. For the top --top-n signatures, look up the bdaddrs in the local bt2
     database and mark the signature as deprioritised iff at least one of
     the bdaddrs already has full GATT data
     (device_has_GATT_values()).
  4. Emit a CSV `<signature>,<0|1>` that CAL can mmap.

SIGNATURE_DESIGN
================
Per bdaddr, the signature is the union of these AD-derived fields across
every advertisement and scan-response we ever saw the bdaddr emit. Field
keys map cleanly onto BlueZ Device1 properties so CAL can recompute the
same signature at runtime from `org.bluez.Device1` props alone.

  fl=<flags_byte_hex>          AdvertisingFlags                  (AD 0x01)
  u16=<sorted_uuid16+...>      UUIDs filtered to UUID16          (AD 0x02/0x03)
  u32=<sorted_uuid32+...>      UUIDs filtered to UUID32          (AD 0x04/0x05)
  u128=<sorted_uuid128+...>    UUIDs filtered to UUID128         (AD 0x06/0x07)
  sd16=<sorted_uuid16+...>     ServiceData keys (UUID16)         (AD 0x16)
  sd32=<sorted_uuid32+...>     ServiceData keys (UUID32)         (AD 0x20)
  sd128=<sorted_uuid128+...>   ServiceData keys (UUID128)        (AD 0x21)
  mfr=<sorted_cid+...>         ManufacturerData keys             (AD 0xFF)
  ap=<appearance_hex>          Appearance                        (AD 0x19)
  tx=<txpower>                 TxPower (signed dBm)              (AD 0x0A)

Excluded as device-unique or volatile:
  Local Names (0x08, 0x09)                — strings, often per-instance
  Target Addresses (0x17, 0x18, 0x1B)     — bdaddr-specific
  Hash C / Randomizer R (0x0E, 0x0F)      — random
  LE Secure Connections (0x22, 0x23)      — random
  URI (0x24)                              — often instance-specific
  Resolvable Set Identifier (0x2E)        — resolvable-set-specific
  MSD payload bytes (only the company ID is kept)
  Service Data payload bytes (only the UUID is kept)

Why not include Service Solicitation, Adv Interval, Conn Interval, LE Role:
  BlueZ does not expose these via Device1 properties, so CAL cannot
  reconstruct them at runtime — including them would only inflate the pcap
  signature space and prevent matching. We deliberately stay within the
  intersection of what tshark sees and what BlueZ surfaces.

Format:
  field separator = '|'
  key=value separator = '='
  list separator = '+'  (so the signature itself is comma-safe for CSV)
  hex is lowercase, fixed width per type
  empty fields are omitted entirely
  fields are emitted sorted by key
"""

# Activate venv before any other imports — matches the convention used by
# Tell_Me_Everything.py and friends, so mysql.connector is on sys.path.
import os
import sys
from pathlib import Path
from handle_venv import activate_venv  # noqa: E402
activate_venv()

import argparse
import csv
import multiprocessing as mp
import pickle
import subprocess
import time
from collections import Counter, defaultdict
from glob import glob

# tshark fields, in the exact order parse_packet() unpacks them.
TSHARK_FIELDS = [
    "btle.advertising_address",
    "btle.advertising_header.pdu_type",
    "btcommon.eir_ad.entry.type",
    "btcommon.eir_ad.entry.length",
    "btcommon.eir_ad.entry.uuid_16",
    "btcommon.eir_ad.entry.uuid_32",
    "btcommon.eir_ad.entry.uuid_128",
    "btcommon.eir_ad.entry.custom_uuid_32",
    "btcommon.eir_ad.entry.custom_uuid_128",
    "btcommon.eir_ad.entry.appearance",
    "btcommon.eir_ad.entry.power_level",
    "btcommon.eir_ad.entry.company_id",
    "btcommon.eir_ad.entry.flags.le_general_discoverable_mode",
    "btcommon.eir_ad.entry.flags.le_limited_discoverable_mode",
    "btcommon.eir_ad.entry.flags.bredr_not_supported",
    "btcommon.eir_ad.entry.flags.le_bredr_support_controller",
    "btcommon.eir_ad.entry.flags.le_bredr_support_host",
]
NUM_FIELDS = len(TSHARK_FIELDS)

# Empty-component template used when starting a new bdaddr.
COMPONENT_KEYS = ("fl", "u16", "u32", "u128", "sd16", "sd32", "sd128", "mfr", "ap", "tx")

# Legacy advertising PDU types we extract data from. We only emit signatures
# for bdaddrs that emitted at least one ADV_IND, because the goal of this
# CSV is to deprioritize *connectable* devices we already have GATT data
# for — non-connectable advertisers (NONCONN_IND, SCAN_IND) and directed
# adverts (DIRECT_IND, which carries no AdvData anyway) cannot be GATT-
# enumerated, so deprioritizing them is meaningless.
#
# SCAN_RSP (0x4) is included because BlueZ's active-scan path merges
# SCAN_RSP AD data into the same Device1 props that ADV_IND populates —
# so to match CAL's runtime view we must aggregate both. SCAN_RSP without
# a matching ADV_IND from the same bdaddr is dropped at the bdaddr level
# below (a SCAN_RSP could in principle answer an ADV_SCAN_IND from a
# scannable-but-not-connectable advertiser).
ADV_IND_PDU_TYPE = 0x0
SCAN_RSP_PDU_TYPE = 0x4
DATA_BEARING_PDU_TYPES = {ADV_IND_PDU_TYPE, SCAN_RSP_PDU_TYPE}


def _empty_components():
    return {k: set() for k in COMPONENT_KEYS}


def _csv_to_list(s):
    if not s:
        return []
    return s.split(",")


def _hex_or_dec(s):
    """tshark emits some integer fields as 0xNN and others as plain decimal."""
    if not s:
        return None
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def parse_packet(cols):
    """Walk one packet's AD entries and return (bdaddr, components, pdu_type).

    Returns (None, None, None) if the packet has no AD entries we care about
    or if the PDU type isn't ADV_IND / SCAN_RSP. We skip ADV_DIRECT_IND
    (carries no AdvData), ADV_NONCONN_IND, ADV_SCAN_IND, and ADV_EXT_IND
    here — we only want connectable advertisers in the signature CSV.
    """
    if len(cols) < NUM_FIELDS:
        return None, None, None
    bdaddr = cols[0].strip().lower()
    if not bdaddr:
        return None, None, None

    pdu_type_str = cols[1].strip()
    try:
        pdu_type = int(pdu_type_str, 16) if pdu_type_str else -1
    except ValueError:
        return None, None, None
    if pdu_type not in DATA_BEARING_PDU_TYPES:
        return None, None, None

    types_csv = cols[2]
    lengths_csv = cols[3]
    if not types_csv:
        return None, None, None

    try:
        types = [int(t, 16) for t in types_csv.split(",") if t]
        lengths = [int(l) for l in lengths_csv.split(",") if l]
    except ValueError:
        return None, None, None
    if not types or len(types) != len(lengths):
        return None, None, None

    uuid_16 = _csv_to_list(cols[4])
    uuid_32 = _csv_to_list(cols[5])
    uuid_128 = _csv_to_list(cols[6])
    custom_uuid_32 = _csv_to_list(cols[7])
    custom_uuid_128 = _csv_to_list(cols[8])
    appearances = _csv_to_list(cols[9])
    powers = _csv_to_list(cols[10])
    company_ids = _csv_to_list(cols[11])
    flags_gen = _csv_to_list(cols[12])
    flags_lim = _csv_to_list(cols[13])
    flags_brn = _csv_to_list(cols[14])
    flags_brc = _csv_to_list(cols[15])
    flags_brh = _csv_to_list(cols[16])

    # tshark splits "known" UUIDs from "custom"/unknown ones into separate
    # field lists. We don't have a reliable way to interleave them in wire
    # order (tshark doesn't expose entry-level offsets via -T fields), so
    # we concatenate known-then-custom and consume in that order. For the
    # vast majority of packets only one of the two lists is populated, so
    # the imprecision is theoretical, not practical.
    all_32 = uuid_32 + custom_uuid_32
    all_128 = uuid_128 + custom_uuid_128

    components = _empty_components()
    u16_idx = u32_idx = u128_idx = 0
    cid_idx = app_idx = pwr_idx = fl_idx = 0

    for adt, adlen in zip(types, lengths):
        # adlen counts the type byte + the data bytes (matches the on-wire
        # AD-structure length field). data_len is the data after the type.
        data_len = adlen - 1
        if data_len < 0:
            continue

        if adt == 0x01:  # Flags
            if fl_idx < min(len(flags_lim), len(flags_gen), len(flags_brn),
                            len(flags_brc), len(flags_brh)):
                try:
                    lim = int(flags_lim[fl_idx], 16)
                    gen = int(flags_gen[fl_idx], 16)
                    brn = int(flags_brn[fl_idx], 16)
                    brc = int(flags_brc[fl_idx], 16)
                    brh = int(flags_brh[fl_idx], 16)
                    flags_byte = (brh << 4) | (brc << 3) | (brn << 2) | (gen << 1) | lim
                    components["fl"].add(f"{flags_byte:02x}")
                except ValueError:
                    pass
                fl_idx += 1

        elif adt in (0x02, 0x03):  # Complete/Incomplete UUID16 list
            n = data_len // 2
            for u in uuid_16[u16_idx:u16_idx + n]:
                v = _hex_or_dec(u)
                if v is not None:
                    components["u16"].add(f"{v:04x}")
            u16_idx += n

        elif adt in (0x04, 0x05):  # Complete/Incomplete UUID32 list
            n = data_len // 4
            for u in all_32[u32_idx:u32_idx + n]:
                v = _hex_or_dec(u)
                if v is not None:
                    components["u32"].add(f"{v:08x}")
            u32_idx += n

        elif adt in (0x06, 0x07):  # Complete/Incomplete UUID128 list
            n = data_len // 16
            for u in all_128[u128_idx:u128_idx + n]:
                clean = u.replace("-", "").lower().zfill(32)
                components["u128"].add(clean)
            u128_idx += n

        elif adt == 0x14:  # Service Solicit UUID16 — consumed but not signal-bearing
            n = data_len // 2
            u16_idx += n

        elif adt == 0x15:  # Service Solicit UUID128 — consumed but not signal-bearing
            n = data_len // 16
            u128_idx += n

        elif adt == 0x1F:  # Service Solicit UUID32 — consumed but not signal-bearing
            n = data_len // 4
            u32_idx += n

        elif adt == 0x16:  # Service Data UUID16 — keep UUID, drop payload
            if u16_idx < len(uuid_16):
                v = _hex_or_dec(uuid_16[u16_idx])
                if v is not None:
                    components["sd16"].add(f"{v:04x}")
                u16_idx += 1

        elif adt == 0x20:  # Service Data UUID32 — keep UUID, drop payload
            if u32_idx < len(all_32):
                v = _hex_or_dec(all_32[u32_idx])
                if v is not None:
                    components["sd32"].add(f"{v:08x}")
                u32_idx += 1

        elif adt == 0x21:  # Service Data UUID128 — keep UUID, drop payload
            if u128_idx < len(all_128):
                clean = all_128[u128_idx].replace("-", "").lower().zfill(32)
                components["sd128"].add(clean)
                u128_idx += 1

        elif adt == 0x0A:  # TxPower
            if pwr_idx < len(powers):
                try:
                    p = int(powers[pwr_idx])
                    components["tx"].add(str(p))
                except ValueError:
                    pass
                pwr_idx += 1

        elif adt == 0x19:  # Appearance
            if app_idx < len(appearances):
                v = _hex_or_dec(appearances[app_idx])
                if v is not None:
                    components["ap"].add(f"{v:04x}")
                app_idx += 1

        elif adt == 0xFF:  # Manufacturer Specific Data — keep CID, drop payload
            if cid_idx < len(company_ids):
                v = _hex_or_dec(company_ids[cid_idx])
                if v is not None:
                    components["mfr"].add(f"{v:04x}")
                cid_idx += 1
        # All other AD types: deliberately not consumed; their subfields
        # aren't in TSHARK_FIELDS so there's nothing to skip past.

    return bdaddr, components, pdu_type


def process_pcap(pcap_path):
    """Run tshark on one pcap, returning the per-bdaddr signature components
    plus the set of bdaddrs proven connectable by an observed ADV_IND.

    Returned shape:
      {"components": {bdaddr: {key: sorted list of values, ...}, ...},
       "connectable": [bdaddr, ...]}
    """
    # Push the PDU-type filter down into tshark so we don't pay for parsing
    # ADV_NONCONN_IND / ADV_SCAN_IND / ADV_DIRECT_IND lines we'd just drop.
    pdu_filter = " or ".join(
        f"btle.advertising_header.pdu_type == {t:#x}"
        for t in sorted(DATA_BEARING_PDU_TYPES)
    )
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", f"btcommon.eir_ad.entry.type and ({pdu_filter})",
        "-T", "fields",
    ]
    for f in TSHARK_FIELDS:
        cmd.extend(["-e", f])
    cmd.extend([
        "-E", "separator=|",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
    ])

    bdaddr_components = defaultdict(_empty_components)
    connectable_bdaddrs = set()

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True,
                                bufsize=1024 * 1024)
    except FileNotFoundError:
        print("ERROR: tshark not on PATH", file=sys.stderr)
        return {"components": {}, "connectable": []}

    try:
        for line in proc.stdout:
            cols = line.rstrip("\n").split("|")
            bdaddr, comps, pdu_type = parse_packet(cols)
            if bdaddr is None:
                continue
            if pdu_type == ADV_IND_PDU_TYPE:
                connectable_bdaddrs.add(bdaddr)
            dst = bdaddr_components[bdaddr]
            for k in COMPONENT_KEYS:
                if comps[k]:
                    dst[k].update(comps[k])
    finally:
        proc.stdout.close()
        proc.wait()

    return {
        "components": {bd: {k: sorted(v) for k, v in comps.items() if v}
                       for bd, comps in bdaddr_components.items()},
        "connectable": list(connectable_bdaddrs),
    }


def merge_into(global_components, global_connectable, pcap_result):
    """Union one pcap's per-bdaddr components into the global accumulator.

    Also unions the set of connectable bdaddrs (those for which an
    ADV_IND was seen, which is the only proof that GATT enumeration is
    even possible against that bdaddr).
    """
    for bdaddr, comps in pcap_result["components"].items():
        dst = global_components[bdaddr]
        for k, vs in comps.items():
            dst[k].update(vs)
    global_connectable.update(pcap_result["connectable"])


def build_signature(comps):
    """Render aggregated components as a deterministic signature string."""
    parts = []
    for k in sorted(comps.keys()):
        vs = comps[k]
        if not vs:
            continue
        parts.append(f"{k}={'+'.join(sorted(vs))}")
    return "|".join(parts)


def parse_signature(s):
    """Inverse of build_signature: 'k1=v1+v2|k2=v3' -> {'k1': frozenset(...)}.

    Used by the dedup logic and (mirrored in CAL) by the runtime subset
    matcher so a more-general deprio entry subsumes a more-specific device
    signature.
    """
    out = {}
    if not s:
        return out
    for part in s.split("|"):
        k, sep, v = part.partition("=")
        if not sep:
            continue
        out[k] = frozenset(v.split("+")) if v else frozenset()
    return out


def sig_is_subset(small, big):
    """True if dict-of-frozensets `small` is a (non-strict) subset of `big`.

    Subset semantics: every key in `small` must appear in `big`, and for
    each such key, every value in `small[k]` must also be in `big[k]`.
    """
    for k, vs in small.items():
        bv = big.get(k)
        if bv is None or not vs.issubset(bv):
            return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-dir", default=os.path.expanduser("~/Desktop/deleteme/sniffle_logs"),
                    help="Directory containing .pcap files (recursively scanned)")
    ap.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 1),
                    help="tshark worker processes")
    ap.add_argument("--top-n", type=int, default=1000,
                    help="Number of top signatures to write to the CSV")
    ap.add_argument("--output", default=str(Path(__file__).parent / "adv_signature_priority.csv"),
                    help="Output CSV path")
    ap.add_argument("--cache", default=None,
                    help="Optional pickle path to cache extracted per-bdaddr "
                         "components between runs. If the file exists and "
                         "--force-extract is not set, skip pcap extraction.")
    ap.add_argument("--force-extract", action="store_true",
                    help="Re-extract from pcaps even if --cache exists")
    ap.add_argument("--db-host", default="localhost")
    ap.add_argument("--db-user", default="user")
    ap.add_argument("--db-password", default="a")
    ap.add_argument("--db-name", default="bt2")
    args = ap.parse_args()

    global_components = defaultdict(_empty_components)
    global_connectable = set()

    cache_loaded = False
    if args.cache and os.path.exists(args.cache) and not args.force_extract:
        print(f"Loading cached components from {args.cache} ...", file=sys.stderr)
        with open(args.cache, "rb") as f:
            cached = pickle.load(f)
        # Cache schema v2: {"components": {bd: {k: list}}, "connectable": [bd, ...]}.
        # v1 (pre-PDU-filter) was just {bd: {k: list}}; reject it so we re-extract.
        if isinstance(cached, dict) and "components" in cached and "connectable" in cached:
            for bd, comps in cached["components"].items():
                dst = global_components[bd]
                for k, vs in comps.items():
                    dst[k].update(vs)
            global_connectable.update(cached["connectable"])
            cache_loaded = True
        else:
            print(f"  cache schema is v1 (no PDU-type filter); re-extracting",
                  file=sys.stderr)

    if not cache_loaded:
        pcap_paths = sorted(glob(os.path.join(args.pcap_dir, "*.pcap")))
        if not pcap_paths:
            print(f"No .pcap files found under {args.pcap_dir}", file=sys.stderr)
            sys.exit(1)
        # Skip empty files — tshark would error and they have no data anyway.
        pcap_paths = [p for p in pcap_paths if os.path.getsize(p) > 0]
        print(f"Extracting from {len(pcap_paths)} pcap(s) using {args.workers} worker(s) ...",
              file=sys.stderr)

        start = time.monotonic()
        done = 0
        with mp.Pool(args.workers) as pool:
            for result in pool.imap_unordered(process_pcap, pcap_paths, chunksize=1):
                merge_into(global_components, global_connectable, result)
                done += 1
                if done % 25 == 0 or done == len(pcap_paths):
                    elapsed = time.monotonic() - start
                    rate = done / elapsed if elapsed > 0 else 0.0
                    eta = (len(pcap_paths) - done) / rate if rate > 0 else 0.0
                    print(f"  [{done}/{len(pcap_paths)}] "
                          f"bdaddrs={len(global_components)} "
                          f"connectable={len(global_connectable)} "
                          f"elapsed={elapsed:0.1f}s "
                          f"eta={eta:0.1f}s",
                          file=sys.stderr)

        if args.cache:
            print(f"Saving cache to {args.cache} ...", file=sys.stderr)
            serialisable = {
                "components": {bd: {k: sorted(v) for k, v in comps.items() if v}
                               for bd, comps in global_components.items()},
                "connectable": sorted(global_connectable),
            }
            with open(args.cache, "wb") as f:
                pickle.dump(serialisable, f, protocol=pickle.HIGHEST_PROTOCOL)

    print(f"Total bdaddrs with extracted components: {len(global_components)} "
          f"(connectable: {len(global_connectable)})",
          file=sys.stderr)

    # Build per-bdaddr signature strings and a reverse map sig -> [bdaddrs].
    # Skip bdaddrs we never observed an ADV_IND from — even if they emitted
    # data in SCAN_RSP, we have no proof they're connectable.
    sig_to_bdaddrs = defaultdict(list)
    skipped_nonconnectable = 0
    for bd, comps in global_components.items():
        if bd not in global_connectable:
            skipped_nonconnectable += 1
            continue
        sig = build_signature(comps)
        if not sig:
            continue
        sig_to_bdaddrs[sig].append(bd)
    print(f"Dropped {skipped_nonconnectable} non-connectable bdaddrs (no ADV_IND seen)",
          file=sys.stderr)

    print(f"Distinct connectable signatures: {len(sig_to_bdaddrs)}",
          file=sys.stderr)

    # ------------------------------------------------------------------
    # Determine deprio status for every signature, then prune redundancy.
    #
    # CAL's runtime lookup uses *subset* matching: a device signature D is
    # deprioritized iff some entry E in the CSV has E as a subset of D.
    # Under that rule, an entry whose signature is a strict superset of
    # another deprio entry is redundant — the shorter entry would already
    # match the same device. We therefore keep only the minimal deprio
    # signatures, and drop any "novel" (deprio=0) entries that would be
    # subsumed by a minimal deprio anchor (those aren't novel either, CAL
    # would deprioritize them via subset match).
    # ------------------------------------------------------------------
    import mysql.connector
    conn = mysql.connector.connect(
        host=args.db_host, user=args.db_user, password=args.db_password,
        database=args.db_name, charset="utf8mb4",
        collation="utf8mb4_unicode_ci", auth_plugin="mysql_native_password",
    )
    cursor = conn.cursor()

    # Pre-load the set of bdaddrs with full GATT data so we don't issue a
    # query per (sig, bdaddr) pair — for the most-common signatures the
    # bdaddr list is six-figure and that gets pathological otherwise.
    cursor.execute("SELECT DISTINCT bdaddr FROM GATT_characteristics_values")
    bdaddrs_with_gatt = {row[0] for row in cursor.fetchall()}
    cursor.close()
    conn.close()
    print(f"DB has full GATT data for {len(bdaddrs_with_gatt)} distinct bdaddrs",
          file=sys.stderr)

    sigs_meta = []  # (sig, deprio, count, parsed_dict)
    for sig, bdaddrs in sig_to_bdaddrs.items():
        deprio = 1 if any(bd in bdaddrs_with_gatt for bd in bdaddrs) else 0
        sigs_meta.append((sig, deprio, len(bdaddrs), parse_signature(sig)))

    def _parsed_complexity(parsed):
        return (len(parsed), sum(len(v) for v in parsed.values()))

    # Find minimal deprio anchors. Process in (complexity asc, count desc) so
    # the shorter, more-general signatures become anchors and the longer
    # ones get recognised as subsumed.
    deprio_meta = sorted(
        (m for m in sigs_meta if m[1] == 1),
        key=lambda m: (_parsed_complexity(m[3]), -m[2]),
    )
    minimal_parsed = []
    minimal_sigs = set()
    for sig, _d, _c, parsed in deprio_meta:
        if any(sig_is_subset(m, parsed) for m in minimal_parsed):
            continue
        minimal_parsed.append(parsed)
        minimal_sigs.add(sig)

    print(f"Pruned deprio anchors: {len(minimal_sigs)} kept, "
          f"{len(deprio_meta) - len(minimal_sigs)} subsumed", file=sys.stderr)

    # Filter the full set: keep only minimal-deprio + truly-novel.
    filtered = []
    novel_subsumed = 0
    for sig, deprio, count, parsed in sigs_meta:
        if deprio == 1:
            if sig in minimal_sigs:
                filtered.append((sig, 1, count))
            # else: redundant deprio, drop silently
        else:
            if any(sig_is_subset(m, parsed) for m in minimal_parsed):
                novel_subsumed += 1
                continue
            filtered.append((sig, 0, count))
    print(f"Filtered novels subsumed by minimal-deprio: {novel_subsumed}",
          file=sys.stderr)

    # Top-N by bdaddr count. After dedup the CSV may be shorter than top_n;
    # that's the user's intent (no padding with redundant rows).
    filtered.sort(key=lambda r: -r[2])
    top = filtered[: args.top_n]

    deprio_count = sum(1 for _s, d, _c in top if d == 1)
    with open(args.output, "w", newline="") as f:
        # CAL strips lines starting with '#'.
        f.write("# signature,deprioritized,bdaddr_count\n")
        f.write("# Subset semantics: a device with a signature S is deprioritized\n")
        f.write("# iff at least one row in this file has deprioritized=1 and that\n")
        f.write("# row's signature is a subset of S (every key=value present in\n")
        f.write("# the row's signature is also present in S). Redundant supersets\n")
        f.write("# of any deprio=1 row are pruned from this CSV.\n")
        writer = csv.writer(f)
        for row in top:
            writer.writerow(row)

    print(f"Wrote {len(top)} rows to {args.output} "
          f"({deprio_count} deprioritized anchors, "
          f"{len(top) - deprio_count} truly-novel)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
