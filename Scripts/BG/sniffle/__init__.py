"""Compatibility entry point for the canonical Sniffle package in this repo."""

from pathlib import Path

_canonical_package = Path(__file__).resolve().parents[3] / "Sniffle" / "python_cli" / "sniffle"
if not _canonical_package.is_dir():
    raise ImportError(f"Canonical Sniffle package is missing: {_canonical_package}")
__path__ = [str(_canonical_package)]

__all__ = [
    "constants",
    "crc_ble",
    "decoder_state",
    "errors",
    "hexdump",
    "measurements",
    "packet_decoder",
    "pcap",
    "sniffer_state",
    "sniffle_hw",
    "sdr_utils",
    "whitening_ble",
    "sniffle_sdr",
    "coding_ble",
    "channelizer",
    "resampler"
]
