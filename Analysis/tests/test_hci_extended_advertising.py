"""Narrow HCI-to-BTIDES regressions backed by checked-in H4 BTSnoop records."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


ANALYSIS_DIR = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hci_extadv"


def _convert(tmp_path, fixture_name):
    target = tmp_path / f"{fixture_name}.btides"
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ANALYSIS_DIR / "scapy"), str(ANALYSIS_DIR), env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        [sys.executable, "HCI_to_BTIDES.py", "--input", str(FIXTURES / fixture_name),
         "--output", str(target), "--quiet-print"],
        cwd=ANALYSIS_DIR, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout[:1000] + result.stderr[:1000]
    return json.loads(target.read_text())


def _single_h4_frame(fixture_name):
    """Return the only H4 frame in a one-record BTSnoop fixture."""
    snoop = (FIXTURES / fixture_name).read_bytes()
    assert snoop[:8] == b"btsnoop\0"
    length = int.from_bytes(snoop[16:20], "big")
    frame = snoop[40:40 + length]
    assert len(snoop) == 40 + length
    return frame


def test_nonlegacy_report_keeps_raw_data_and_metadata(tmp_path):
    fixture = "p1_nonlegacy_nonconnectable_100b.snoop"
    btides = _convert(tmp_path, fixture)
    assert len(btides) == 1
    device, = btides
    assert device["bdaddr"] == "02:00:00:00:00:ed"
    assert "AdvChanArray" not in device  # HCI report cannot identify one OTA PDU.
    report, = device["HCIArray"]
    assert (report["event_code"], report["subevent_code"]) == (0x3e, 0x0d)
    assert (report["event_type"], report["data_status"]) == (0, 0)
    assert (report["primary_phy"], report["secondary_phy"], report["advertising_sid"]) == (1, 1, 7)
    assert report["std_optional_fields"]["time"] == {
        "unix_time": 946684800, "unix_time_milli": 946684800000,
    }
    assert report["data_length"] == 100
    assert (report["source_record_seq"], report["report_index"]) == (1, 0)
    raw = bytes.fromhex(report["advertising_data_hex_str"])
    assert raw == _single_h4_frame(fixture)[29:]
    assert hashlib.sha256(raw).hexdigest() == "32e8e267caade67b592a5a767e96fe3a942db1879cdd956667cfcb2024dfad5f"
    assert {ad["type"] for ad in report["AdvDataArray"]} == {1, 9, 255}


def test_connectable_nonlegacy_report_is_not_dropped(tmp_path):
    fixture = "p1_nonlegacy_connectable_84b.snoop"
    btides = _convert(tmp_path, fixture)
    assert len(btides) == 1
    device, = btides
    assert device["bdaddr"] == "02:00:00:00:00:01"
    assert "AdvChanArray" not in device
    report, = device["HCIArray"]
    assert report["event_type"] == 1  # Connectable, nonlegacy, not scannable.
    assert report["data_length"] == 84
    raw = bytes.fromhex(report["advertising_data_hex_str"])
    assert raw == _single_h4_frame(fixture)[29:]
    assert hashlib.sha256(raw).hexdigest() == "faa3871f81ee9e8c921a2d932438eaf7a643606065554c916d2f31710f4b8133"
    assert bytes.fromhex("072e010203040506") in raw  # RSI AD type 0x2e survives intact.
    assert 0x2e not in {ad["type"] for ad in report["AdvDataArray"]}  # Parser lacks RSI.
    assert any(ad.get("name_hex_str") == b"QA Extended Test".hex() for ad in report["AdvDataArray"])


def test_coalesced_legacy_reports_use_each_reports_address_and_data(tmp_path):
    btides = _convert(tmp_path, "synthetic_two_legacy_reports.snoop")
    devices = {entry["bdaddr"]: entry for entry in btides}
    assert set(devices) == {"02:00:00:00:00:01", "02:00:00:00:00:02"}
    for address, name_hex in (("02:00:00:00:00:01", "41"),
                              ("02:00:00:00:00:02", "42")):
        advertisement, = devices[address]["AdvChanArray"]
        assert advertisement["type"] == 2  # Legacy ADV_NONCONN_IND.
        name, = advertisement["AdvDataArray"]
        assert name["name_hex_str"] == name_hex


def test_repeated_identical_reports_in_one_millisecond_keep_source_sequence(tmp_path):
    btides = _convert(tmp_path, "synthetic_repeated_identical_report.snoop")
    assert len(btides) == 1
    reports = btides[0]["HCIArray"]
    assert len(reports) == 2
    assert reports[0]["advertising_data_hex_str"] == reports[1]["advertising_data_hex_str"]
    assert [r["std_optional_fields"]["time"]["unix_time_milli"] for r in reports] == [
        946684801000, 946684801000,
    ]
    assert [(r["source_record_seq"], r["report_index"]) for r in reports] == [(1, 0), (2, 0)]


def test_att_read_response_without_handle_validates_end_to_end(tmp_path):
    btides = _convert(tmp_path, "p1_att_read_req_rsp.snoop")
    assert len(btides) == 1
    connection, = btides
    assert connection["CONNECT_IND"]["peripheral_bdaddr"] == "02:00:00:00:00:eb"
    assert connection["ATTArray"] == [
        {"direction": 0, "opcode": 10, "handle": 3},
        {"direction": 1, "opcode": 11, "value_hex_str": b"QATEST-EB".hex()},
    ]


def test_sql_import_explicitly_warns_when_skipping_extended_reports(tmp_path):
    btides = _convert(tmp_path, "p1_nonlegacy_connectable_84b.snoop")
    script = """
import json, sys
import TME.TME_glob as glob
from BTIDES_to_SQL import btides_to_sql, btides_to_sql_args
glob.BTIDES_JSON = json.load(sys.stdin)
assert btides_to_sql(btides_to_sql_args(input=['SKIPME'], quiet_print=True))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ANALYSIS_DIR,
        input=json.dumps(btides), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "skipped 1 HCI LE Extended Advertising Reports" in result.stderr
    assert "raw data remains in BTIDES" in result.stderr
