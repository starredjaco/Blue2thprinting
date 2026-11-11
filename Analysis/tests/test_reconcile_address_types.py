"""Focused checks for the address-type reconciliation safety boundaries."""

import json
from pathlib import Path
import shutil
import struct
import subprocess
from types import SimpleNamespace
import sys

import pytest

from conftest import ANALYSIS_DIR, TEST_DB, _mysql

sys.path.insert(0, str(ANALYSIS_DIR))
from reconcile_address_types import (
    correct_sql, database_counts, mysql_connection, parse_tshark_line, supported_record,
    typed_tables, write_btides_mirror, replace_corrected_btides,
)


ADDRESS = "a4:c1:38:23:26:9b"


def test_hci_and_air_evidence_parsing():
    hci = "1794291919.0\ta4:c1:38:23:26:9b\t\t0x00\t\t\t\t\n"
    air = "1794291919.0\t\t\t\ta4:c1:38:23:26:9b\tFalse\t\t0x00\n"
    assert list(parse_tshark_line(hci)) == [(ADDRESS, 0, "hci", 1794291919)]
    assert list(parse_tshark_line(air)) == [(ADDRESS, 0, "air", 1794291919)]
    scan_request = ("1794291919.0\t\t\t\ta4:c1:38:23:26:9b"
                    "\tTrue\tFalse\t0x03\n")
    assert list(parse_tshark_line(scan_request)) == [(ADDRESS, 0, "air", 1794291919)]


def test_rust_reader_extracts_typed_hci_and_air_addresses(tmp_path):
    if not shutil.which("rustc"):
        pytest.skip("rustc unavailable")
    source = ANALYSIS_DIR / "address_type_evidence.rs"
    binary = tmp_path / "evidence"
    subprocess.run(["rustc", "--edition", "2021", "-O", str(source),
                    "-o", str(binary)], check=True)
    candidates = tmp_path / "candidates.txt"
    candidates.write_text(ADDRESS + "\n")
    address_le = bytes.fromhex("9b262338c1a4")
    timestamp = 1794291919

    rf = bytes(8) + struct.pack("<H", 0x0c00)
    air_pdu = bytes.fromhex("d6be898e") + bytes([0, 6]) + address_le + bytes(3)
    packet = rf + air_pdu
    pcap = tmp_path / "air.pcap"
    pcap.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256)
                     + struct.pack("<IIII", timestamp, 0, len(packet), len(packet)) + packet)

    event = bytes([4, 0x3e, 12, 2, 1, 0, 0]) + address_le + bytes([0, 0])
    btsnoop = tmp_path / "hci.cfa"
    btsnoop.write_bytes(b"btsnoop\0" + struct.pack(">II", 1, 1002)
                        + struct.pack(">IIIIQ", len(event), len(event), 1, 0,
                                      0x00dcddb30f2f8000 + timestamp * 1_000_000) + event)
    paths = tmp_path / "paths.txt"
    paths.write_text(f"{pcap}\n{btsnoop}\n")
    output = subprocess.check_output([str(binary), str(candidates), str(paths)], text=True)
    assert f"O\t{pcap}\t{ADDRESS}\t0\tair\t1\t{timestamp}\t{timestamp}" in output
    assert f"O\t{btsnoop}\t{ADDRESS}\t0\thci\t1\t{timestamp}\t{timestamp}" in output


def test_temporal_evidence_does_not_cover_distant_record():
    decision = {"expected": 1, "windows": [[1794291900, 1794292000]]}
    record = {
        "bdaddr": "50:11:22:33:44:55", "bdaddr_rand": 0,
        "AdvChanArray": [{"std_optional_fields": {
            "time": {"unix_time_milli": 1794291950000}
        }}],
    }
    assert supported_record(record, decision)[0]
    record["AdvChanArray"][0]["std_optional_fields"]["time"]["unix_time_milli"] = 1794200000000
    assert not supported_record(record, decision)[0]


def test_corrected_btides_mirror_preserves_source(tmp_path):
    root = tmp_path / "sniffing"
    root.mkdir()
    source = root / "sample.btides"
    source.write_text(json.dumps([
        {"bdaddr": ADDRESS.upper(), "bdaddr_rand": 1, "AdvChanArray": []},
        {"bdaddr": "11:22:33:44:55:66", "bdaddr_rand": 0},
    ]))
    mirror, changed, linked = write_btides_mirror(
        root, tmp_path / "run", [source], {ADDRESS: {"expected": 0}},
        {str(source): {ADDRESS: 1}},
    )
    assert linked == 0
    assert len(changed) == 1
    assert json.loads(source.read_text())[0]["bdaddr_rand"] == 1
    assert json.loads((mirror / "sample.btides").read_text())[0]["bdaddr_rand"] == 0
    replaced = replace_corrected_btides(root, tmp_path / "run", changed)
    assert len(replaced) == 1
    assert json.loads(source.read_text())[0]["bdaddr_rand"] == 0
    assert json.loads((tmp_path / "run/btides-originals/sample.btides").read_text())[0]["bdaddr_rand"] == 1


def test_sql_correction_deduplicates_exact_rows(db_clean):
    _mysql(["-D", TEST_DB, "-e",
            "INSERT INTO LE_bdaddr_to_name "
            "(bdaddr,bdaddr_random,le_evt_type,device_name_type,name_hex_str) VALUES "
            "('a4:c1:38:23:26:9b',0,0,9,'54657374'),"
            "('a4:c1:38:23:26:9b',1,0,9,'54657374');"
            "INSERT INTO GATT_services "
            "(bdaddr,bdaddr_random,service_type,begin_handle,end_handle,UUID) VALUES "
            "('a4:c1:38:23:26:9b',1,0,1,5,'1800')"])
    args = SimpleNamespace(mysql_host="localhost", mysql_user="user",
                           mysql_password="a", database=TEST_DB)
    conn = mysql_connection(args)
    try:
        tables = typed_tables(conn, TEST_DB)
        counts, by_address = database_counts(
            conn, tables, {ADDRESS: {"expected": 0}},
        )
        assert counts["LE_bdaddr_to_name"] == 1
        assert counts["GATT_services"] == 1
        assert by_address[ADDRESS] == {"LE_bdaddr_to_name": 1, "GATT_services": 1}
        corrected, unresolved = correct_sql(
            conn, tables, {ADDRESS: {"expected": 0}}, by_address,
        )
        assert unresolved == {}
        assert corrected[ADDRESS]["LE_bdaddr_to_name"]["deduplicated"] == 1
        assert corrected[ADDRESS]["GATT_services"]["updated"] == 1
        cursor = conn.cursor()
        for table in ("LE_bdaddr_to_name", "GATT_services"):
            cursor.execute(
                f"SELECT bdaddr_random,COUNT(*) FROM {table} WHERE bdaddr=%s "
                "GROUP BY bdaddr_random", (ADDRESS,),
            )
            assert cursor.fetchall() == [(0, 1)]
        cursor.close()
    finally:
        conn.close()
