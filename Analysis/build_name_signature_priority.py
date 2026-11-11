#!/usr/bin/env python3
"""
Build the device-name signature deprioritization CSV consumed by
Scripts/central_app_launcher.py and the XenoMetaRadar Android application.

A name is deprioritized when at least one BDADDR observed with that name also
has a row in GATT_characteristics_values.  bdaddr_count is the number of
distinct BDADDRs observed with the same normalized name across the local
database's LE advertising, BR/EDR inquiry, HCI/LMP remote-name, and GATT
Device Name (0x2A00) sources.

Name signatures are the lowercase hexadecimal UTF-8 encoding of the name
after Unicode NFKC normalization and removal of leading/trailing Unicode
whitespace and NUL characters.  The hex representation is deterministic,
comma-safe, and preserves case: Bluetooth names that differ only by case are
different signatures.

Default output contains only names that should be deprioritized.  Pass
--include-novel to include observed names without GATT-value coverage as
deprioritized=0 rows for auditing.
"""

import sys
from pathlib import Path

try:
    from handle_venv import activate_venv
except ModuleNotFoundError:
    # Allows `Analysis.build_name_signature_priority` imports when pytest is
    # launched from the repository root rather than from Analysis/.
    from Analysis.handle_venv import activate_venv

activate_venv()

import argparse
import csv
import unicodedata
from collections import defaultdict


def normalize_name(name):
    """Return the cross-platform canonical form used for matching."""
    if not isinstance(name, str):
        return ""
    normalized = unicodedata.normalize("NFKC", name)
    start = 0
    end = len(normalized)
    while start < end and (normalized[start].isspace() or normalized[start] == "\x00"):
        start += 1
    while end > start and (normalized[end - 1].isspace() or normalized[end - 1] == "\x00"):
        end -= 1
    return normalized[start:end]


def name_signature(name):
    """Return the comma-safe signature for a runtime/database device name."""
    normalized = normalize_name(name)
    return normalized.encode("utf-8").hex() if normalized else ""


def decode_hex_name(value):
    """Decode the DB's hexadecimal name columns like Android/BlueZ do."""
    if value is None:
        return ""
    try:
        return bytes.fromhex(str(value)).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def build_priority_rows(observations, bdaddrs_with_gatt, include_novel=False):
    """Aggregate (bdaddr, name) observations into deterministic CSV rows."""
    signature_to_bdaddrs = defaultdict(set)
    gatt = {str(bdaddr).strip().lower() for bdaddr in bdaddrs_with_gatt if bdaddr}

    for bdaddr, name in observations:
        if not bdaddr:
            continue
        signature = name_signature(name)
        if signature:
            signature_to_bdaddrs[signature].add(str(bdaddr).strip().lower())

    rows = []
    for signature, bdaddrs in signature_to_bdaddrs.items():
        deprioritized = int(not bdaddrs.isdisjoint(gatt))
        if deprioritized or include_novel:
            rows.append((signature, deprioritized, len(bdaddrs)))
    return sorted(rows, key=lambda row: (-row[2], row[0]))


def iter_database_names(cursor):
    """Yield every locally-observed remote device name as (bdaddr, text)."""
    hex_sources = (
        ("LE_bdaddr_to_name", "name_hex_str"),
        ("EIR_bdaddr_to_name", "name_hex_str"),
        ("HCI_bdaddr_to_name", "name_hex_str"),
    )
    for table, column in hex_sources:
        cursor.execute(f"SELECT bdaddr, {column} FROM {table}")
        for bdaddr, encoded_name in cursor:
            name = decode_hex_name(encoded_name)
            if name:
                yield bdaddr, name

    cursor.execute("SELECT bdaddr, device_name FROM LMP_NAME_RES_defragmented")
    for bdaddr, name in cursor:
        if name:
            yield bdaddr, name

    # Include names read from Generic Access Device Name (0x2A00).  This lets
    # a later advertiser using the same name benefit even when the first
    # device exposed its name only after connecting.
    cursor.execute(
        """
        SELECT c.bdaddr, v.byte_values
        FROM GATT_characteristics AS c
        JOIN GATT_characteristics_values AS v
          ON v.bdaddr = c.bdaddr
         AND v.bdaddr_random = c.bdaddr_random
         AND v.char_value_handle = c.char_value_handle
        WHERE LOWER(REPLACE(c.UUID, '-', '')) IN
              ('2a00', '00002a0000001000800000805f9b34fb')
        """
    )
    for bdaddr, raw_name in cursor:
        if raw_name is None:
            continue
        if isinstance(raw_name, str):
            name = raw_name
        else:
            name = bytes(raw_name).decode("utf-8", errors="replace")
        if name:
            yield bdaddr, name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent / "name_signature_priority.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--include-novel",
        action="store_true",
        help="Also emit names with no GATT-value coverage as deprioritized=0",
    )
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-user", default="user")
    parser.add_argument("--db-password", default="a")
    parser.add_argument("--db-name", default="bt2")
    args = parser.parse_args()

    import mysql.connector

    connection = mysql.connector.connect(
        host=args.db_host,
        user=args.db_user,
        password=args.db_password,
        database=args.db_name,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        auth_plugin="mysql_native_password",
    )
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT DISTINCT bdaddr FROM GATT_characteristics_values")
        bdaddrs_with_gatt = {row[0] for row in cursor}
        observations = list(iter_database_names(cursor))
    finally:
        cursor.close()
        connection.close()

    rows = build_priority_rows(
        observations,
        bdaddrs_with_gatt,
        include_novel=args.include_novel,
    )
    output = Path(args.output)
    with output.open("w", newline="", encoding="utf-8") as output_file:
        output_file.write("# name_signature,deprioritized,bdaddr_count\n")
        output_file.write("# name_signature is hex(UTF-8(NFKC(trim(name)))); matching is case-sensitive.\n")
        output_file.write("# bdaddr_count counts distinct BDADDRs observed with the normalized name.\n")
        output_file.write("# A row is deprioritized when any such BDADDR has GATT characteristic values.\n")
        writer = csv.writer(output_file, lineterminator="\n")
        writer.writerows(rows)

    deprioritized_count = sum(row[1] for row in rows)
    print(
        f"Wrote {len(rows)} rows to {output} "
        f"({deprioritized_count} deprioritized, "
        f"{len(rows) - deprioritized_count} novel; "
        f"{len(observations)} name observations, "
        f"{len(bdaddrs_with_gatt)} BDADDRs with GATT values)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
