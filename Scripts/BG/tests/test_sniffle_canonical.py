"""Check BG's real Sniffle import and connection request compatibility."""

from pathlib import Path
from struct import unpack_from

from sniffle import sniffle_hw


def test_bg_loads_canonical_sniffle():
    repo_root = Path(__file__).resolve().parents[3]
    expected = repo_root / "Sniffle" / "python_cli" / "sniffle" / "sniffle_hw.py"
    assert Path(sniffle_hw.__file__).resolve() == expected


def test_connection_timeout_is_encoded_in_request(monkeypatch):
    requests = []
    hw = object.__new__(sniffle_hw.SniffleHW)
    monkeypatch.setattr(hw, "cmd_connect", lambda *args: requests.append(args))

    hw.initiate_conn([1, 2, 3, 4, 5, 6], timeout=75)

    assert len(requests) == 1
    assert unpack_from("<H", requests[0][1], 14)[0] == 75
