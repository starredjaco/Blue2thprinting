#!/usr/bin/env python3
"""Canonical GATT handle/UUID signatures shared by Better Getter and the CSV builder."""

import csv


BT_BASE_SUFFIX = "00001000800000805f9b34fb"


def normalize_uuid(value):
    """Return UUID16/UUID32/custom-UUID128 in one lowercase canonical form."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 2:
            return f"{int.from_bytes(raw, 'little'):04x}"
        if len(raw) == 16:
            compact = raw[::-1].hex()
        else:
            raise ValueError(f"unsupported binary UUID length: {len(raw)}")
    else:
        compact = str(value).strip().lower()
        if compact.startswith("0x"):
            compact = compact[2:]
        compact = compact.replace("-", "")

    if not compact or any(ch not in "0123456789abcdef" for ch in compact):
        raise ValueError(f"invalid UUID: {value!r}")
    if len(compact) <= 4:
        return compact.zfill(4)
    if len(compact) == 8:
        return compact[4:] if compact.startswith("0000") else compact
    if len(compact) == 32:
        if compact[8:] == BT_BASE_SUFFIX:
            prefix = compact[:8]
            return prefix[4:] if prefix.startswith("0000") else prefix
        return compact
    raise ValueError(f"unsupported UUID width: {value!r}")


def handle_uuid_signature(entries):
    """Build ``0001=2800|0002=2803|...`` from an iterable or mapping."""
    items = entries.items() if hasattr(entries, "items") else entries
    canonical = {}
    for handle, uuid in items:
        numeric_handle = int(handle)
        if not 1 <= numeric_handle <= 0xFFFF:
            raise ValueError(f"invalid ATT handle: {handle!r}")
        normalized_uuid = normalize_uuid(uuid)
        previous = canonical.get(numeric_handle)
        if previous is not None and previous != normalized_uuid:
            raise ValueError(
                f"conflicting UUIDs for handle 0x{numeric_handle:04x}: "
                f"{previous} vs {normalized_uuid}"
            )
        canonical[numeric_handle] = normalized_uuid
    return "|".join(
        f"{handle:04x}={canonical[handle]}" for handle in sorted(canonical)
    )


def load_deprioritized_signatures(csv_path):
    """Load enabled canonical signatures from ``gatt_handle_uuid_priority.csv``."""
    signatures = set()
    with open(csv_path, "r", newline="", encoding="utf-8") as csv_file:
        rows = csv.reader(
            line for line in csv_file if not line.lstrip().startswith("#")
        )
        for row in rows:
            if len(row) < 2:
                continue
            signature = row[0].strip().lower()
            try:
                enabled = int(row[1])
                parsed = (
                    (int(part.split("=", 1)[0], 16), part.split("=", 1)[1])
                    for part in signature.split("|")
                )
                if handle_uuid_signature(parsed) != signature:
                    continue
            except (TypeError, ValueError, IndexError):
                continue
            if enabled and signature:
                signatures.add(signature)
    return signatures
