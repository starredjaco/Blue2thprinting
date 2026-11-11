#!/usr/bin/env python3
"""
Build the exact GATT handle-to-UUID priority CSV used by Better Getter and
the XenoMetaRadar Android Connect All flow.

Each device's structural GATT fingerprint is the sorted set of every
``attribute_handle -> UUID`` row in GATT_attribute_handles. UUIDs use a
cross-platform canonical form: assigned UUID16/UUID32 values are shortened
and custom UUID128 values are lowercase hex without dashes.

A fingerprint is deprioritized only when at least ``--min-value-bdaddrs``
distinct BDADDRs with that exact mapping also have characteristic-value data.
The default threshold is three, so one prior sample is not treated as a
well-covered device family.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

try:
    from handle_venv import activate_venv
except ModuleNotFoundError:
    from Analysis.handle_venv import activate_venv

activate_venv()

BG_DIR = Path(__file__).resolve().parents[1] / "Scripts" / "BG"
if str(BG_DIR) not in sys.path:
    sys.path.insert(0, str(BG_DIR))

from gatt_handle_uuid_priority import handle_uuid_signature


def build_priority_rows(
    handle_maps,
    value_devices,
    min_value_bdaddrs=3,
    include_novel=False,
):
    """Aggregate ``(bdaddr, random, entries)`` observations into CSV rows."""
    if min_value_bdaddrs < 1:
        raise ValueError("min_value_bdaddrs must be at least 1")

    normalized_value_devices = {
        (str(bdaddr).strip().lower(), int(bdaddr_random))
        for bdaddr, bdaddr_random in value_devices
        if bdaddr
    }
    signature_to_bdaddrs = defaultdict(set)
    signature_to_value_bdaddrs = defaultdict(set)
    signature_to_handle_count = {}

    for bdaddr, bdaddr_random, entries in handle_maps:
        if not bdaddr:
            continue
        address = str(bdaddr).strip().lower()
        address_type = int(bdaddr_random)
        try:
            signature = handle_uuid_signature(entries)
        except ValueError:
            # A BDADDR can expose different databases over time (or imported
            # captures can disagree), leaving multiple UUIDs for one handle.
            # Such a row set is not one exact map and must not become an anchor.
            continue
        if not signature:
            continue
        signature_to_bdaddrs[signature].add(address)
        if (address, address_type) in normalized_value_devices:
            signature_to_value_bdaddrs[signature].add(address)
        signature_to_handle_count[signature] = signature.count("|") + 1

    rows = []
    for signature, bdaddrs in signature_to_bdaddrs.items():
        value_count = len(signature_to_value_bdaddrs[signature])
        deprioritized = int(value_count >= min_value_bdaddrs)
        if deprioritized or include_novel:
            rows.append(
                (
                    signature,
                    deprioritized,
                    len(bdaddrs),
                    value_count,
                    signature_to_handle_count[signature],
                )
            )
    return sorted(rows, key=lambda row: (-row[3], -row[2], row[0]))


def iter_database_handle_maps(cursor):
    """Yield one complete ordered handle map at a time without buffering the table."""
    cursor.execute(
        """
        SELECT bdaddr, bdaddr_random, attribute_handle, UUID
        FROM GATT_attribute_handles
        ORDER BY LOWER(bdaddr), bdaddr_random, attribute_handle
        """
    )
    current_key = None
    current_entries = []
    for bdaddr, bdaddr_random, handle, uuid in cursor:
        key = (str(bdaddr).strip().lower(), int(bdaddr_random))
        if current_key is not None and key != current_key:
            yield current_key[0], current_key[1], current_entries
            current_entries = []
        current_key = key
        current_entries.append((handle, uuid))
    if current_key is not None:
        yield current_key[0], current_key[1], current_entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent / "gatt_handle_uuid_priority.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--min-value-bdaddrs",
        type=int,
        default=3,
        help="Minimum exact-map BDADDRs with GATT values needed to deprioritize",
    )
    parser.add_argument(
        "--include-novel",
        action="store_true",
        help="Also emit insufficiently-covered maps as deprioritized=0",
    )
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-user", default="user")
    parser.add_argument("--db-password", default="a")
    parser.add_argument("--db-name", default="bt2")
    args = parser.parse_args()

    if args.min_value_bdaddrs < 1:
        parser.error("--min-value-bdaddrs must be at least 1")

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
        cursor.execute(
            "SELECT DISTINCT bdaddr, bdaddr_random "
            "FROM GATT_characteristics_values"
        )
        value_devices = set(cursor.fetchall())
        handle_maps = list(iter_database_handle_maps(cursor))
    finally:
        cursor.close()
        connection.close()

    rows = build_priority_rows(
        handle_maps,
        value_devices,
        min_value_bdaddrs=args.min_value_bdaddrs,
        include_novel=args.include_novel,
    )
    output = Path(args.output)
    with output.open("w", newline="", encoding="utf-8") as output_file:
        output_file.write(
            "# handle_uuid_signature,deprioritized,bdaddr_count,"
            "value_bdaddr_count,handle_count\n"
        )
        output_file.write(
            "# signature is sorted 4-hex-handle=canonical-UUID entries "
            "joined by |; matching is exact.\n"
        )
        output_file.write(
            "# bdaddr_count counts distinct BDADDRs with the exact map; "
            "value_bdaddr_count counts those with GATT values.\n"
        )
        output_file.write(
            f"# deprioritized requires value_bdaddr_count >= "
            f"{args.min_value_bdaddrs}.\n"
        )
        csv.writer(output_file, lineterminator="\n").writerows(rows)

    deprioritized_count = sum(row[1] for row in rows)
    print(
        f"Wrote {len(rows)} rows to {output} "
        f"({deprioritized_count} deprioritized; "
        f"{len(handle_maps)} device maps, "
        f"{len(value_devices)} devices with GATT values; "
        f"threshold={args.min_value_bdaddrs})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
