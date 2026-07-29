import csv
import subprocess
import sys
from pathlib import Path

from Analysis.build_gatt_handle_uuid_priority import build_priority_rows

BG_DIR = Path(__file__).resolve().parents[2] / "Scripts" / "BG"
if str(BG_DIR) not in sys.path:
    sys.path.insert(0, str(BG_DIR))

from gatt_handle_uuid_priority import (
    handle_uuid_signature,
    load_deprioritized_signatures,
    normalize_uuid,
)


def test_uuid_normalization_matches_database_air_and_android_forms():
    assert normalize_uuid("2800") == "2800"
    assert normalize_uuid("00002800-0000-1000-8000-00805F9B34FB") == "2800"
    assert normalize_uuid(b"\x00\x28") == "2800"
    assert normalize_uuid("12345678-1234-5678-1234-56789ABCDEF0") == (
        "1234567812345678123456789abcdef0"
    )


def test_signature_is_exact_and_handle_order_independent():
    base = handle_uuid_signature([(2, "2803"), (1, "2800"), (3, "2A00")])

    assert base == "0001=2800|0002=2803|0003=2a00"
    assert handle_uuid_signature([(1, "2800"), (2, "2803"), (4, "2A00")]) != base
    assert handle_uuid_signature([(1, "2800"), (2, "2803"), (3, "2A01")]) != base


def test_rows_require_many_value_covered_distinct_bdaddrs():
    common = [(1, "2800"), (2, "2803"), (3, "2A00")]
    maps = [
        ("AA:00:00:00:00:01", 0, common),
        ("aa:00:00:00:00:01", 0, common),
        ("AA:00:00:00:00:02", 0, common),
        ("AA:00:00:00:00:03", 1, common),
    ]
    rows = build_priority_rows(
        maps,
        value_devices={
            ("AA:00:00:00:00:01", 0),
            ("AA:00:00:00:00:02", 0),
            ("AA:00:00:00:00:03", 1),
        },
    )

    assert rows == [
        ("0001=2800|0002=2803|0003=2a00", 1, 3, 3, 3),
    ]


def test_ambiguous_database_maps_are_not_eligible_anchors():
    rows = build_priority_rows(
        [
            (
                "AA:00:00:00:00:01",
                0,
                [(1, "2800"), (2, "2A00"), (2, "2A01")],
            ),
        ],
        value_devices={("AA:00:00:00:00:01", 0)},
        min_value_bdaddrs=1,
        include_novel=True,
    )

    assert rows == []


def test_csv_loader_keeps_only_canonical_enabled_rows(tmp_path):
    csv_path = tmp_path / "priority.csv"
    csv_path.write_text(
        "# signature,deprioritized\n"
        "0001=2800|0002=2803,1,3,3,2\n"
        "0001=2800|0003=2a00,0,9,9,2\n"
        "not-a-map,1,9,9,1\n",
        encoding="utf-8",
    )

    assert load_deprioritized_signatures(csv_path) == {
        "0001=2800|0002=2803",
    }


def test_cli_rebuilds_from_seeded_local_database(db_clean, tmp_path):
    output = tmp_path / "gatt_handle_uuid_priority.csv"
    script = Path(__file__).resolve().parents[1] / (
        "build_gatt_handle_uuid_priority.py"
    )
    subprocess.run(
        [
            "mysql",
            "-u",
            "user",
            "-pa",
            "-D",
            "bttest",
            "-e",
            (
                "INSERT INTO GATT_attribute_handles "
                "(bdaddr,bdaddr_random,attribute_handle,UUID) VALUES "
                "('aa:bb:cc:11:22:02',1,1,'2800'),"
                "('aa:bb:cc:11:22:02',1,2,'2803'),"
                "('aa:bb:cc:11:22:02',1,3,'2a00')"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--db-name",
            "bttest",
            "--min-value-bdaddrs",
            "1",
            "--output",
            str(output),
        ],
        cwd=script.parent,
        capture_output=True,
        text=True,
        check=True,
    )
    with output.open(newline="", encoding="utf-8") as input_file:
        rows = [
            row
            for row in csv.reader(
                line for line in input_file if not line.startswith("#")
            )
        ]

    assert len(rows) == 1
    assert rows == [
        ["0001=2800|0002=2803|0003=2a00", "1", "1", "1", "3"],
    ]
    assert "1 deprioritized" in result.stderr
