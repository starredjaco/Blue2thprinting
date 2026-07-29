import csv
import subprocess
import sys
from pathlib import Path

from Analysis.build_name_signature_priority import (
    build_priority_rows,
    decode_hex_name,
    name_signature,
    normalize_name,
)


def test_name_signature_normalizes_nfkc_and_edge_whitespace():
    assert normalize_name("\x00  Ｃafé\t") == "Café"
    assert name_signature("\x00  Ｃafé\t") == "Café".encode().hex()


def test_name_signatures_remain_case_sensitive():
    assert name_signature("Sensor") != name_signature("sensor")


def test_decode_hex_name_matches_utf8_replacement_behavior():
    assert decode_hex_name("54657374") == "Test"
    assert decode_hex_name("ff") == "\ufffd"
    assert decode_hex_name("not hex") == ""


def test_rows_count_distinct_bdaddrs_and_deprioritize_on_any_gatt_match():
    observations = [
        ("AA:00:00:00:00:01", "Sensor"),
        ("aa:00:00:00:00:01", "Sensor"),
        ("AA:00:00:00:00:02", "Sensor"),
        ("AA:00:00:00:00:03", "Novel"),
    ]

    rows = build_priority_rows(
        observations,
        bdaddrs_with_gatt={"AA:00:00:00:00:02"},
    )

    assert rows == [(name_signature("Sensor"), 1, 2)]


def test_include_novel_preserves_zero_priority_rows():
    rows = build_priority_rows(
        [("AA:00:00:00:00:01", "Novel")],
        bdaddrs_with_gatt=set(),
        include_novel=True,
    )

    assert rows == [(name_signature("Novel"), 0, 1)]


def test_cli_rebuilds_from_seeded_local_database(test_db, tmp_path):
    output = tmp_path / "name_signature_priority.csv"
    script = Path(__file__).resolve().parents[1] / "build_name_signature_priority.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--db-name",
            "bttest",
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
            for row in csv.reader(line for line in input_file if not line.startswith("#"))
        ]

    assert rows == [[name_signature("TestGATT2"), "1", "1"]]
    assert "1 deprioritized" in result.stderr
