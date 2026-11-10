#!/usr/bin/env python3
"""Reconcile BTIDES/SQL address types against HCI and over-the-air evidence.

Default mode is read-only. --apply backs up bt2 and changed BTIDES exports,
writes a complete reimportable mirror, then corrects matching bt2 rows and
source BTIDES exports. HCI/pcap captures are never edited. An address seen
with both types in capture evidence is ambiguous and is not changed.
"""

from handle_venv import activate_venv
activate_venv()

import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from decimal import Decimal
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

import ijson
import mysql.connector
from mysql.connector import IntegrityError


ADDRESS = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cfa", ".btsnoop", ".log"}
CAPTURE_MAGIC = {
    b"btsnoop\x00", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
}
TSHARK_FIELDS = (
    "frame.time_epoch", "bthci_evt.bd_addr", "bthci_evt.le_address_type",
    "bthci_evt.le_peer_address_type", "btle.advertising_address",
    "btle.advertising_header.randomized_tx",
    "btle.advertising_header.randomized_rx", "btle.advertising_header.pdu_type",
)
DISPLAY_FILTER = (
    "(bthci_evt.bd_addr && (bthci_evt.le_address_type || "
    "bthci_evt.le_peer_address_type)) || "
    "(btle.advertising_address && !btle.crc.incorrect)"
)


def evidence_connection(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS capture_files (
            path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
            status TEXT NOT NULL, error TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            path TEXT NOT NULL, address TEXT NOT NULL, address_type INTEGER NOT NULL,
            source TEXT NOT NULL, count INTEGER NOT NULL,
            first_s INTEGER NOT NULL, last_s INTEGER NOT NULL,
            PRIMARY KEY (path, address, address_type, source)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS observations_address ON observations(address)")
    return conn


def capture_paths(root, explicit):
    if explicit:
        paths = [Path(p).expanduser().resolve() for p in explicit]
    else:
        paths = (p for p in root.rglob("*") if p.suffix.lower() in CAPTURE_SUFFIXES)
    for path in paths:
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            head = stream.read(8)
        if any(head.startswith(magic) for magic in CAPTURE_MAGIC):
            yield path


def split_values(value):
    return value.split("|") if value else []


def parsed_type(value):
    try:
        raw = int(value, 0)
    except ValueError:
        return None
    return raw & 1 if raw in (0, 1, 2, 3) else None


def pairs(addresses, types):
    if len(addresses) != len(types):
        return
    for raw_address, raw_type in zip(addresses, types):
        address = raw_address.lower()
        address_type = parsed_type(raw_type)
        if ADDRESS.fullmatch(address) and address_type is not None:
            yield address, address_type


def parse_tshark_line(line):
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) != len(TSHARK_FIELDS):
        return
    try:
        timestamp = int(float(fields[0]))
    except ValueError:
        return
    if not 946684800 <= timestamp <= 4102444800:
        return
    hci_addresses = split_values(fields[1])
    hci_types = split_values(fields[2]) or split_values(fields[3])
    for address, address_type in pairs(hci_addresses, hci_types):
        yield address, address_type, "hci", timestamp
    air_addresses = split_values(fields[4])
    pdu_types = split_values(fields[7])
    # In SCAN_REQ and CONNECT_IND the advertising address is the second
    # address, described by RxAdd. Other PDUs use the first address/TxAdd.
    raw_types = split_values(fields[6] if pdu_types and
                             all(pdu in ("0x03", "0x05") for pdu in pdu_types)
                             else fields[5])
    air_types = [{"True": "1", "False": "0", "1": "1", "0": "0"}.get(x, "")
                 for x in raw_types]
    for address, address_type in pairs(air_addresses, air_types):
        yield address, address_type, "air", timestamp


def extract_capture(path, candidates):
    command = [
        "tshark", "-n", "-r", str(path), "-Y", DISPLAY_FILTER,
        "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
    ]
    for field in TSHARK_FIELDS:
        command += ["-e", field]
    # Aggregate per file to keep the evidence database small even for dense captures.
    observed = {}
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                   text=True, errors="replace")
        for line in process.stdout:
            for address, address_type, source, timestamp in parse_tshark_line(line):
                if address not in candidates:
                    continue
                key = address, address_type, source
                if key not in observed:
                    observed[key] = [1, timestamp, timestamp]
                else:
                    row = observed[key]
                    row[0] += 1
                    row[1] = min(row[1], timestamp)
                    row[2] = max(row[2], timestamp)
        status = process.wait()
        if status:
            errors.seek(0)
            return None, errors.read().decode("utf-8", "replace")[:500]
    return observed, None


def is_fast_capture(path):
    with path.open("rb") as stream:
        header = stream.read(24)
    if len(header) != 24:
        return False
    if header.startswith(b"btsnoop\x00"):
        return True
    if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        return struct.unpack_from("<I", header, 20)[0] == 256
    if header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return struct.unpack_from(">I", header, 20)[0] == 256
    return False


def scan_fast_captures(conn, pending, candidates, output_root):
    source = Path(__file__).with_name("address_type_evidence.rs")
    binary = output_root / "address_type_evidence"
    if not binary.exists() or binary.stat().st_mtime_ns < source.stat().st_mtime_ns:
        subprocess.run(["rustc", "--edition", "2021", "-O", str(source),
                        "-o", str(binary)], check=True)
    candidate_file = output_root / "btides-addresses.txt"
    address_index = output_root / "btides-addresses.txt.gz"
    if not candidate_file.exists() or candidate_file.stat().st_mtime_ns < address_index.stat().st_mtime_ns:
        candidate_file.write_text("\n".join(sorted(candidates)) + "\n")
    paths_file = output_root / "pending-pcaps.txt"
    paths_file.write_text("\n".join(str(path) for path, _, _ in pending) + "\n")
    metadata = {str(path): (size, mtime) for path, size, mtime in pending}
    observed = defaultdict(dict)
    done = 0
    errors = 0
    process = subprocess.Popen([str(binary), str(candidate_file), str(paths_file)],
                               stdout=subprocess.PIPE, text=True)
    try:
        for line in process.stdout:
            parts = line.rstrip("\n").split("\t")
            if parts[0] == "O" and len(parts) == 8:
                _, path, address, typ, source, count, first, last = parts
                observed[path][(address, int(typ), source)] = (
                    int(count), int(first), int(last))
            elif parts[0] == "F" and len(parts) == 3:
                _, path, status = parts
                rows = observed.pop(path, {})
                conn.execute("DELETE FROM observations WHERE path=?", (path,))
                if status == "ok":
                    conn.executemany("INSERT INTO observations VALUES (?,?,?,?,?,?,?)",
                                     ((path, address, typ, source, *values)
                                      for (address, typ, source), values in rows.items()))
                else:
                    errors += 1
                conn.execute("INSERT OR REPLACE INTO capture_files VALUES (?,?,?,?,?)",
                             (path, *metadata[path],
                              "rust_v2" if status == "ok" else "error", status))
                conn.commit()
                done += 1
                if done % 500 == 0 or done == len(pending):
                    print(f"Fast capture scan {done}/{len(pending)}; errors={errors}", flush=True)
        if process.wait():
            raise RuntimeError("Rust pcap evidence reader failed")
        if done != len(pending):
            raise RuntimeError(f"Rust pcap evidence reader stopped at {done}/{len(pending)}")
    finally:
        paths_file.unlink(missing_ok=True)


def scan_captures(root, cache_path, candidates, explicit=(), workers=4):
    conn = evidence_connection(cache_path)
    files = list(capture_paths(root, explicit))
    existing = {path: (size, mtime, status) for path, size, mtime, status
                in conn.execute("SELECT path,size,mtime_ns,status FROM capture_files")}
    pending = []
    for path in files:
        stat = path.stat()
        expected_status = "rust_v2" if is_fast_capture(path) else "ok"
        if existing.get(str(path)) == (stat.st_size, stat.st_mtime_ns, expected_status):
            continue
        pending.append((path, stat.st_size, stat.st_mtime_ns))
    print(f"Captures: {len(files)} supported; {len(pending)} new or changed", flush=True)
    fast = [item for item in pending if is_fast_capture(item[0])]
    slow = [item for item in pending if not is_fast_capture(item[0])]
    if fast:
        scan_fast_captures(conn, fast, candidates, cache_path.parent)
    failed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(extract_capture, path, candidates): (path, size, mtime)
                   for path, size, mtime in slow}
        for number, future in enumerate(as_completed(futures), 1):
            path, size, mtime = futures[future]
            try:
                observed, error = future.result()
            except Exception as exc:
                observed, error = None, str(exc)
            conn.execute("DELETE FROM observations WHERE path=?", (str(path),))
            if observed is not None:
                conn.executemany(
                    "INSERT INTO observations VALUES (?,?,?,?,?,?,?)",
                    ((str(path), address, typ, source, count, first_s, last_s)
                     for (address, typ, source), (count, first_s, last_s)
                     in observed.items()),
                )
            else:
                failed += 1
            conn.execute(
                "INSERT OR REPLACE INTO capture_files VALUES (?,?,?,?,?)",
                (str(path), size, mtime, "ok" if observed is not None else "error", error),
            )
            conn.commit()
            if number % 100 == 0 or number == len(slow):
                print(f"TShark scanned {number}/{len(slow)} captures; errors={failed}", flush=True)
    conn.close()


def decisions_from_evidence(cache_path):
    conn = evidence_connection(cache_path)
    rows = conn.execute("""
        SELECT address, address_type,
               SUM(CASE WHEN source='hci' THEN count ELSE 0 END),
               SUM(CASE WHEN source='air' THEN count ELSE 0 END),
               MIN(first_s), MAX(last_s)
        FROM observations GROUP BY address,address_type
    """)
    by_address = defaultdict(dict)
    for address, typ, hci, air, first_s, last_s in rows:
        by_address[address][typ] = dict(hci=hci, air=air, first_s=first_s, last_s=last_s)
    decisions = {}
    ambiguous = 0
    for address, types in by_address.items():
        if len(types) != 1:
            ambiguous += 1
            continue
        typ, evidence = next(iter(types.items()))
        if evidence["hci"] or evidence["air"] >= 2:
            decisions[address] = dict(expected=typ, **evidence)
            decisions[address]["windows"] = []
    for address, typ, first_s, last_s in conn.execute(
        "SELECT address,address_type,first_s,last_s FROM observations "
        "ORDER BY address,address_type,first_s"
    ):
        decision = decisions.get(address)
        if decision is None or decision["expected"] != typ:
            continue
        windows = decision["windows"]
        if windows and first_s <= windows[-1][1] + 1200:
            windows[-1][1] = max(windows[-1][1], last_s)
        else:
            windows.append([first_s, last_s])
    conn.close()
    print(f"Evidence: {len(decisions)} single-type addresses; {ambiguous} mixed-type addresses skipped",
          flush=True)
    return decisions


def btides_paths(root, explicit, output_root):
    paths = [Path(p).expanduser().resolve() for p in explicit] if explicit else root.rglob("*.btides")
    for path in paths:
        if path.is_file() and not path.is_relative_to(output_root):
            yield path


def index_btides_addresses(files, output_root):
    metadata = output_root / "btides-address-index.json"
    addresses_file = output_root / "btides-addresses.txt.gz"
    fingerprint = hashlib.sha256()
    for path in files:
        stat = path.stat()
        fingerprint.update(
            f"{path}\t{stat.st_size}\t{stat.st_mtime_ns}\n".encode("utf-8")
        )
    digest = fingerprint.hexdigest()
    if metadata.exists() and addresses_file.exists():
        if json.loads(metadata.read_text()).get("fingerprint") == digest:
            with gzip.open(addresses_file, "rt") as stream:
                addresses = set(stream.read().splitlines())
            print(f"BTIDES address index: {len(addresses)} cached addresses", flush=True)
            return addresses
    addresses = set()
    for number, path in enumerate(files, 1):
        with path.open("rb") as stream:
            for record in ijson.items(stream, "item"):
                if not isinstance(record, dict) or record.get("bdaddr_rand") not in (0, 1):
                    continue
                address = record.get("bdaddr")
                if isinstance(address, str) and ADDRESS.fullmatch(address.lower()):
                    addresses.add(address.lower())
        if number % 250 == 0 or number == len(files):
            print(f"Indexed {number}/{len(files)} BTIDES files; "
                  f"{len(addresses)} addresses", flush=True)
    with gzip.open(addresses_file, "wt") as stream:
        stream.write("\n".join(sorted(addresses)) + "\n")
    metadata.write_text(json.dumps({"fingerprint": digest, "files": len(files),
                                    "addresses": len(addresses)}, indent=2) + "\n")
    return addresses


def record_times(record):
    times = []
    for packet in record.get("AdvChanArray", []):
        time = packet.get("std_optional_fields", {}).get("time", {})
        value = time.get("unix_time_milli")
        if isinstance(value, (int, float, Decimal)):
            times.append(int(value // 1000))
        elif isinstance(time.get("unix_time"), (int, float, Decimal)):
            times.append(int(time["unix_time"]))
    return times


def supported_record(record, decision):
    address = record["bdaddr"].lower()
    expected = decision["expected"]
    old = record["bdaddr_rand"]
    if old == 1 and expected == 0 and (int(address[:2], 16) & 0xC0) == 0x80:
        return True, "reserved-random-prefix"
    times = record_times(record)
    if not times:
        return False, "no observation timestamp"
    # A type event must overlap every timed advertisement in an aggregate
    # BTIDES entry. Allow ten minutes for timestamp drift between capture tools.
    if all(any(first - 600 <= timestamp <= last + 600
               for first, last in decision["windows"]) for timestamp in times):
        return True, "time-overlap"
    return False, "outside evidence interval"


def inspect_btides(root, explicit, output_root, decisions):
    files = list(btides_paths(root, explicit, output_root))
    entries = defaultdict(lambda: dict(supported=0, unsupported=0, reasons=defaultdict(int)))
    by_file = defaultdict(dict)
    for number, path in enumerate(files, 1):
        with path.open("rb") as stream:
            for record in ijson.items(stream, "item"):
                if not isinstance(record, dict):
                    continue
                address = record.get("bdaddr")
                if not isinstance(address, str):
                    continue
                address = address.lower()
                decision = decisions.get(address)
                if decision is None or record.get("bdaddr_rand") not in (0, 1):
                    continue
                if record["bdaddr_rand"] == decision["expected"]:
                    continue
                supported, reason = supported_record(record, decision)
                entry = entries[address]
                entry["supported" if supported else "unsupported"] += 1
                entry["reasons"][reason] += 1
                by_file[str(path)][address] = by_file[str(path)].get(address, 0) + 1
        if number % 250 == 0 or number == len(files):
            print(f"Inspected {number}/{len(files)} BTIDES files", flush=True)
    # A corrected mirror should not contain an uncorrected occurrence of the
    # same address elsewhere, so only fully supported addresses are eligible.
    eligible = {address: decisions[address] for address, info in entries.items()
                if info["supported"] and not info["unsupported"]}
    skipped = {address: dict(info, reasons=dict(info["reasons"]))
               for address, info in entries.items() if address not in eligible}
    print(f"BTIDES: {len(eligible)} eligible addresses; {len(skipped)} skipped", flush=True)
    return files, eligible, skipped, by_file


def mysql_connection(args):
    return mysql.connector.connect(
        host=args.mysql_host, user=args.mysql_user, password=args.mysql_password,
        database=args.database, charset="utf8mb4", collation="utf8mb4_unicode_ci",
        auth_plugin="mysql_native_password", autocommit=False,
    )


def typed_tables(conn, database):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.TABLE_NAME
        FROM information_schema.COLUMNS AS c
        JOIN information_schema.TABLES AS t
          ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME
        WHERE c.TABLE_SCHEMA=%s AND c.COLUMN_NAME='bdaddr_random'
          AND t.ENGINE='InnoDB'
        ORDER BY c.TABLE_NAME
    """, (database,))
    tables = [row[0] for row in cursor]
    for table in tables:
        if not re.fullmatch(r"[A-Za-z0-9_]+", table):
            raise RuntimeError(f"Unsafe table name: {table}")
        cursor.execute("""
            SELECT COLUMN_NAME FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        """, (database, table))
        columns = {row[0] for row in cursor}
        if not {"id", "bdaddr", "bdaddr_random"}.issubset(columns):
            raise RuntimeError(f"{table} lacks required id/bdaddr/type columns")
    cursor.close()
    return tables


def database_counts(conn, tables, candidates):
    """Find wrong-type rows with indexed joins, including database-only cases."""
    cursor = conn.cursor()
    totals = defaultdict(int)
    by_address = defaultdict(dict)
    cursor.execute("CREATE TEMPORARY TABLE reconcile_types ("
                   "bdaddr CHAR(17) CHARACTER SET ascii COLLATE ascii_general_ci PRIMARY KEY, "
                   "expected TINYINT NOT NULL) ENGINE=InnoDB")
    addresses = list(candidates.items())
    for start in range(0, len(addresses), 5000):
        cursor.executemany("INSERT INTO reconcile_types VALUES (%s,%s)",
                           [(address, decision["expected"])
                            for address, decision in addresses[start:start + 5000]])
    print(f"Checking {len(addresses)} evidenced addresses against {len(tables)} SQL tables",
          flush=True)
    for number, table in enumerate(tables, 1):
        cursor.execute(
            f"SELECT r.bdaddr,COUNT(*) FROM reconcile_types r STRAIGHT_JOIN {table} t "
            "ON t.bdaddr=r.bdaddr AND t.bdaddr_random<>r.expected GROUP BY r.bdaddr"
        )
        for address, count in cursor:
            by_address[address.lower()][table] = count
            totals[table] += count
        if number % 10 == 0 or number == len(tables):
            print(f"Checked {number}/{len(tables)} SQL tables", flush=True)
    cursor.execute("DROP TEMPORARY TABLE reconcile_types")
    cursor.close()
    return dict(totals), dict(by_address)


def backup_database(args, run_dir):
    destination = run_dir / f"{args.database}-before.sql.gz"
    credentials = run_dir / ".mysql-backup.cnf"
    credentials.write_text(
        "[client]\n"
        f"host={args.mysql_host}\nuser={args.mysql_user}\n"
        f"password={args.mysql_password}\n"
    )
    credentials.chmod(0o600)
    command = [
        "mysqldump", f"--defaults-extra-file={credentials}",
        "--single-transaction", "--quick", "--hex-blob",
        "--column-statistics=0", "--set-gtid-purged=OFF",
        args.database,
    ]
    print(f"Backing up {args.database} to {destination}", flush=True)
    try:
        with tempfile.TemporaryFile() as errors, destination.open("wb") as file:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors)
            with gzip.GzipFile(fileobj=file, mode="wb", compresslevel=1) as zipped:
                shutil.copyfileobj(process.stdout, zipped, length=1024 * 1024)
            status = process.wait()
            if status:
                errors.seek(0)
                raise RuntimeError(
                    f"mysqldump failed ({status}): "
                    + errors.read().decode("utf-8", "replace")[:1000]
                )
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        credentials.unlink(missing_ok=True)
    with destination.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    print(f"Database backup: {destination.stat().st_size:,} bytes, sha256={digest}", flush=True)
    return destination, digest


def write_btides_mirror(root, run_dir, files, eligible, by_file):
    mirror = run_dir / "btides"
    changed = []
    linked = 0
    eligible_addresses = set(eligible)
    for number, source in enumerate(files, 1):
        relative = source.relative_to(root)
        destination = mirror / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        candidate_addresses = set(by_file.get(str(source), {})) & eligible_addresses
        if not candidate_addresses:
            os.link(source, destination)
            linked += 1
            continue
        output_count = 0
        with source.open("r", encoding="utf-8") as input_file:
            records = json.load(input_file)
        if not isinstance(records, list):
            raise ValueError(f"Expected a BTIDES array in {source}")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError(f"Non-object BTIDES entry in {source}")
            address = record.get("bdaddr", "").lower()
            if address in candidate_addresses and record.get("bdaddr_rand") in (0, 1):
                target = eligible[address]["expected"]
                if record["bdaddr_rand"] != target:
                    record["bdaddr_rand"] = target
                    output_count += 1
        if output_count:
            with destination.open("w", encoding="utf-8") as output_file:
                json.dump(records, output_file, ensure_ascii=False, separators=(",", ":"))
                output_file.write("\n")
            with source.open("rb") as stream:
                source_sha = hashlib.file_digest(stream, "sha256").hexdigest()
            with destination.open("rb") as stream:
                corrected_sha = hashlib.file_digest(stream, "sha256").hexdigest()
            changed.append(dict(source=str(source), corrected=str(destination),
                                changed_records=output_count,
                                source_sha256=source_sha,
                                corrected_sha256=corrected_sha))
        else:
            os.link(source, destination)
            linked += 1
        if number % 250 == 0 or number == len(files):
            print(f"Mirrored {number}/{len(files)} BTIDES files; changed={len(changed)}",
                  flush=True)
    return mirror, changed, linked


def replace_corrected_btides(root, run_dir, changed):
    """Keep an original hardlink, then atomically replace each derived export."""
    replaced = []
    backups = run_dir / "btides-originals"
    for item in changed:
        source = Path(item["source"])
        corrected = Path(item["corrected"])
        backup = backups / source.relative_to(root)
        backup.parent.mkdir(parents=True, exist_ok=True)
        os.link(source, backup)
        with tempfile.NamedTemporaryFile(dir=source.parent, prefix=".btides-corrected-",
                                         delete=False) as stream:
            temporary = Path(stream.name)
        try:
            shutil.copy2(corrected, temporary)
            os.replace(temporary, source)
        finally:
            temporary.unlink(missing_ok=True)
        replaced.append(dict(source=str(source), original_backup=str(backup),
                             corrected_sha256=item["corrected_sha256"]))
    return replaced


def correct_sql(conn, tables, eligible, wrong_by_address=None):
    cursor = conn.cursor(dictionary=True)
    corrected = {}
    unresolved = {}
    for number, (address, decision) in enumerate(eligible.items(), 1):
        old_type = 1 - decision["expected"]
        cursor.execute("SAVEPOINT address_type_fix")
        address_stats = defaultdict(lambda: defaultdict(int))
        reason = None
        for table in (wrong_by_address.get(address, {}) if wrong_by_address is not None
                      else tables):
            cursor.execute(
                f"SELECT * FROM {table} WHERE bdaddr=%s AND bdaddr_random=%s",
                (address, old_type),
            )
            rows = cursor.fetchall()
            for row in rows:
                try:
                    cursor.execute(
                        f"UPDATE {table} SET bdaddr_random=%s WHERE id=%s",
                        (decision["expected"], row["id"]),
                    )
                    address_stats[table]["updated"] += 1
                except IntegrityError as error:
                    if error.errno != 1062:
                        raise
                    # Delete only an exact duplicate of a row already present
                    # with the proven type. A conflicting payload is preserved.
                    columns = [key for key in row if key not in ("id", "bdaddr_random")]
                    where = " AND ".join(f"{column} <=> %s" for column in columns)
                    cursor.execute(
                        f"SELECT id FROM {table} WHERE bdaddr_random=%s AND {where} LIMIT 1",
                        (decision["expected"], *(row[column] for column in columns)),
                    )
                    if cursor.fetchone() is None:
                        reason = f"{table} id={row['id']}: duplicate key with different row data"
                        break
                    cursor.execute(f"DELETE FROM {table} WHERE id=%s", (row["id"],))
                    address_stats[table]["deduplicated"] += 1
            if reason:
                break
        if reason:
            cursor.execute("ROLLBACK TO SAVEPOINT address_type_fix")
            unresolved[address] = reason
        else:
            corrected[address] = {table: dict(counts) for table, counts in address_stats.items()}
        cursor.execute("RELEASE SAVEPOINT address_type_fix")
        if number % 100 == 0 or number == len(eligible):
            print(f"SQL {number}/{len(eligible)} addresses; conflicts={len(unresolved)}",
                  flush=True)
    # Verify before the single commit; any unexpected old-type row is a failure.
    for address, decision in corrected.items():
        for table in (wrong_by_address.get(address, {}) if wrong_by_address is not None
                      else tables):
            cursor.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE bdaddr=%s AND bdaddr_random=%s",
                (address, 1 - eligible[address]["expected"]),
            )
            if cursor.fetchone()["n"]:
                raise RuntimeError(f"Uncorrected SQL rows for {address} in {table}")
    conn.commit()
    cursor.close()
    return corrected, unresolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "Documents/sniffing")
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--capture", action="append", default=[],
                        help="Restrict evidence scan to this capture; repeatable")
    parser.add_argument("--btides", action="append", default=[],
                        help="Restrict BTIDES scan to this file; repeatable")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--no-scan", action="store_true",
                        help="Use the existing evidence cache without scanning captures")
    parser.add_argument("--scan-only", action="store_true",
                        help="Update the evidence cache and stop before planning corrections")
    parser.add_argument("--apply", action="store_true",
                        help="Back up SQL, write corrected BTIDES mirror, then correct SQL")
    parser.add_argument("--database", default="bt2")
    parser.add_argument("--mysql-host", default="localhost")
    parser.add_argument("--mysql-user", default=os.environ.get("BT2_MYSQL_USER", "user"))
    parser.add_argument("--mysql-password",
                        default=os.environ.get("BT2_MYSQL_PASSWORD", "a"))
    args = parser.parse_args()
    args.root = args.root.expanduser().resolve()
    # Keep the full BTIDES mirror outside the scan tree: recursively importing
    # the source tree must not see a second copy of every export.
    args.output_root = (args.output_root or args.root.with_name(
        args.root.name + "-address-type-reconciliation")).resolve()
    if not args.root.is_dir():
        parser.error(f"Root directory does not exist: {args.root}")
    if args.output_root.is_relative_to(args.root):
        parser.error("--output-root must be outside --root to avoid duplicate BTIDES imports")
    if args.workers < 1:
        parser.error("--workers must be positive")
    args.output_root.mkdir(parents=True, exist_ok=True)
    cache_path = args.output_root / "evidence.sqlite3"
    if not args.no_scan:
        btides_files = list(btides_paths(args.root, args.btides, args.output_root))
        candidates = index_btides_addresses(btides_files, args.output_root)
        scan_captures(args.root, cache_path, candidates, args.capture, args.workers)
    elif not cache_path.exists():
        parser.error("--no-scan requires an existing evidence cache")
    if args.scan_only:
        return
    decisions = decisions_from_evidence(cache_path)
    files, btides_eligible, skipped, by_file = inspect_btides(
        args.root, args.btides, args.output_root, decisions,
    )
    db = mysql_connection(args)
    try:
        tables = typed_tables(db, args.database)
        safe_decisions = {address: decision for address, decision in decisions.items()
                          if address not in skipped}
        db_counts, wrong_by_address = database_counts(db, tables, safe_decisions)
        eligible = {address: safe_decisions[address]
                    for address in set(btides_eligible) | set(wrong_by_address)}
        db.rollback()
        plan = {
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "root": str(args.root), "database": args.database,
            "capture_scope": args.capture or "all supported captures under root",
            "btides_scope": args.btides or "all .btides files under root",
            "eligible_addresses": eligible, "skipped_addresses": skipped,
            "btides_eligible_addresses": len(btides_eligible),
            "sql_wrong_type_addresses": len(wrong_by_address),
            "btides_files": len(files),
            "database_wrong_type_rows_by_table": db_counts,
        }
        print(
            f"Plan: {len(eligible)} addresses, "
            f"{sum(db_counts.values())} wrong-type SQL rows in {len(db_counts)} tables",
            flush=True,
        )
        plan_path = args.output_root / "latest-plan.json"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n")
        print(f"Plan file: {plan_path}", flush=True)
        if not args.apply:
            print("Dry run: pass --apply to back up and write corrections", flush=True)
            return
        if not eligible:
            print("No eligible corrections; no backup or mirror created", flush=True)
            return
        run_dir = args.output_root / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir.mkdir()
        (run_dir / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        backup, backup_sha256 = backup_database(args, run_dir)
        mirror, changed, linked = write_btides_mirror(
            args.root, run_dir, files, eligible, by_file,
        )
        corrected, unresolved = correct_sql(db, tables, eligible, wrong_by_address)
        replaced = replace_corrected_btides(args.root, run_dir, changed)
        report = {
            "plan": str(run_dir / "plan.json"),
            "sql_backup": str(backup), "sql_backup_sha256": backup_sha256,
            "btides_mirror": str(mirror),
            "btides_changed_files": changed,
            "btides_replaced_sources": replaced,
            "btides_hardlinked_unchanged_files": linked,
            "sql_corrected_addresses": corrected,
            "sql_unresolved_addresses": unresolved,
        }
        (run_dir / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            f"Applied: {len(corrected)} SQL addresses; {len(unresolved)} SQL conflicts; "
            f"{len(changed)} corrected BTIDES files. Report: {run_dir / 'result.json'}",
            flush=True,
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
