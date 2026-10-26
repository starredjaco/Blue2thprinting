########################################
# Created by Xeno Kovah
# Copyright(c) © Dark Mentor LLC 2023-2026
########################################

from copy import deepcopy


def company_subversion_key(company_id, subversion):
    """Return the canonical key used by LL/LMP controller metadata files."""
    return f"{company_id:04X}:{subversion:04X}"


def lookup_company_subversion_metadata(metadata, company_id, subversion):
    """Look up a vendor-defined sub-version without assuming a VersNr value."""
    match = metadata.get('company_subversion_matches', {}).get(
        company_subversion_key(company_id, subversion)
    )
    result = deepcopy(match) if match is not None else None

    # Realtek patch versions mined from official linux-firmware history are
    # kept in compact provenance-rich tables. A collision is still useful as
    # an explicitly ambiguous fingerprint: report every candidate rather than
    # suppressing the evidence or pretending it identifies one exact chip.
    history_root = metadata.get('realtek_linux_firmware_history', {})
    subversion_key = f"0x{subversion:04X}"
    if company_id == 0x005D:
        history = history_root.get('unique_patch_subversions', {}).get(
            subversion_key
        )
        collision = history_root.get(
            'cross_chip_collisions', {}
        ).get(subversion_key)
    else:
        history = None
        collision = None

    if history is None and collision is None:
        return result
    if result is not None:
        result['linux_firmware_history'] = deepcopy(history or collision)
        return result

    result = deepcopy(history or collision)
    result['vendor'] = 'Realtek'
    result['firmware_state'] = 'patched'
    result['patch_version'] = f"0x{subversion:04X}"
    result['sources'] = [history_root['source_repository']]
    if collision is not None:
        result['cross_chip_collision'] = True
        result['match_quality'] = (
            'cross-chip SubVersNr collision; exact chip unknown; '
            'VersNr not constrained'
        )
        result['notes'] = [
            f"SubVersNr 0x{subversion:04X} occurs in firmware for multiple "
            'unrelated Realtek chip families; all listed chips are candidates.'
        ]
    else:
        result['display_name'] = (
            f"{' or '.join(result['chips'])} "
            f"(running patch version 0x{subversion:04x})"
        )
    return result


def metadata_chip_display_name(match):
    """Preserve the legacy ChipPrint wording while storing chips as a list."""
    if match is None:
        return ''
    if match.get('display_name'):
        return match['display_name']
    return ' or '.join(match.get('chips', []))
