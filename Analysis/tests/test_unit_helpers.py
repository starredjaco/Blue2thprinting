########################################
# Created by Xeno Kovah
# Copyright(c) © Dark Mentor LLC 2023-2026
########################################

"""Pure-Python unit tests that don't need MySQL or subprocess invocation."""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ANALYSIS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ANALYSIS_DIR))

from Tell_Me_Everything import validate_bdaddr  # noqa: E402
from TME.TME_import import (  # noqa: E402
    import_LL_VERSION_IND_metadata,
    import_LMP_VERSION_metadata,
)
from TME.TME_LLCP import (  # noqa: E402
    lookup_LL_VERSION_IND_metadata,
    print_LL_VERSION_IND_metadata,
    print_LLCP_info,
)
from TME.TME_LMP import (  # noqa: E402
    lookup_LMP_VERSION_metadata,
    print_LMP_VERSION_metadata,
)
from TME.TME_metadata import (  # noqa: E402
    chip_by_sub_version,
    chipprint_by_LL_VERSION,
    chipprint_by_LMP_VERSION,
    chipprint_by_sub_version,
    print_ChipPrint,
)
import TME.TME_glob  # noqa: E402

# clues_io ships in the CLUES_Schema submodule and is the canonical
# loader for both single-file and 16-shard hex-split CLUES layouts.
# TME_import imports it the same way (via sys.path), so mirror that
# pattern here for the unit tests.
sys.path.insert(0, str(ANALYSIS_DIR / "CLUES_Schema" / "scripts"))
from clues_io import clues_exists, load_clues, save_clues  # noqa: E402


class TestValidateBdaddr:
    @pytest.mark.parametrize("bdaddr", [
        "AA:BB:CC:11:22:33",
        "aa:bb:cc:11:22:33",
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
        "12:34:56:78:9A:bC",
    ])
    def test_accepts_valid(self, bdaddr):
        assert validate_bdaddr(bdaddr) == bdaddr

    @pytest.mark.parametrize("bad", [
        "",
        "AA:BB:CC:11:22",                 # too short
        "AA:BB:CC:11:22:33:44",           # too long
        "AA-BB-CC-11-22-33",              # wrong separator
        "AABBCC112233",                    # no separators
        "ZZ:BB:CC:11:22:33",              # non-hex
        "AA:BB:CC:11:22:3",                # last octet 1 char
    ])
    def test_rejects_invalid(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_bdaddr(bad)


class TestLLVersionIndMetadata:
    @classmethod
    def setup_class(cls):
        import_LL_VERSION_IND_metadata()
        import_LMP_VERSION_metadata()

    def test_exact_legacy_softdevice_match(self):
        result = lookup_LL_VERSION_IND_metadata(0x0A, 0x0059, 0x0102)
        assert result['software'] == ['S113 7.2.0']
        assert 'nRF52833' in result['chips']
        assert 'nRF5 SDK 17.1.1' in result['sdk_versions']
        assert result['match_quality'].startswith('exact')

    @pytest.mark.parametrize(('versnr', 'subversion', 'softdevices'), [
        (0x08, 0x007E, ['ANT S332 0.6.0.alpha']),
        (0x08, 0x0082, ['ANT S332 0.9.1.alpha']),
        (0x08, 0x0085, ['ANT S332 1.0.2']),
        (0x08, 0x008E, ['ANT S332 2.0.0', 'ANT S332 2.0.1']),
        (0x08, 0x0094, [
            'ANT S332 4.0.2', 'ANT S332 4.0.2-2', 'ANT S332 4.0.5'
        ]),
        (0x08, 0x009F, ['S132 4.0.5']),
        (0x09, 0x009B, ['ANT S332 5.0.0']),
        (0x09, 0x00B9, ['ANT S340 6.1.1']),
        (0x09, 0x00BA, ['ANT S332 6.1.1']),
        (0x09, 0x00BB, ['ANT S312 6.1.1']),
        (0x0A, 0x00CE, ['ANT S340 7.0.1']),
        (0x0A, 0x00CF, ['ANT S332 7.0.1']),
        (0x0A, 0x00D0, ['ANT S313 7.0.1']),
        (0x0A, 0x00D1, ['ANT S312 7.0.1']),
    ])
    def test_new_nordic_softdevice_fwid_candidates(
        self, versnr, subversion, softdevices
    ):
        result = lookup_LL_VERSION_IND_metadata(
            versnr, 0x0059, subversion
        )
        assert result['software'] == softdevices
        assert result['chips']
        assert result['on_air_verified'] is False
        assert 'FWID-derived' in result['match_quality']
        assert not result.get('sdk_versions')

    def test_ant_only_s212_is_not_a_ble_controller_match(self):
        result = lookup_LL_VERSION_IND_metadata(0x0A, 0x0059, 0x00EE)
        assert result['match_quality'].startswith('vendor/version')
        assert not any('S212' in name for name in result['software'])

    def test_ant_s313_print_and_chipprint_retain_ambiguity(self, monkeypatch):
        import TME.TME_LLCP as llcp

        output = []
        monkeypatch.setattr(llcp, 'qprint', output.append)
        print_LL_VERSION_IND_metadata(0x0A, 0x0059, 0x00D0)
        rendered = '\n'.join(output)
        assert 'FWID-derived Nordic ANT+BLE candidate' in rendered
        assert 'Possible SoftDevice/controller: ANT S313 7.0.1' in rendered
        assert 'Possible chip(s): nRF52810, nRF52811, nRF52832, ' in rendered
        assert 'not verified from this image on air' in rendered

        chipprint_text, quality = chipprint_by_LL_VERSION(
            0x0A, 0x00D0, 0x0059
        )
        assert 'nRF52810, nRF52811, nRF52832, nRF52833, nRF52840' in chipprint_text
        assert 'FWID-derived' in quality

    def test_ncs_family_and_build_pattern_match(self):
        result = lookup_LL_VERSION_IND_metadata(0x0D, 0x0059, 0x218F)
        assert 'nRF53' in result['software'][0]
        assert result['chips'] == ['nRF5340']
        assert 'nRF Connect SDK 2.6.0' in result['sdk_versions']
        assert 'pattern' in result['match_quality']

    def test_pattern_rejects_family_build_pair_not_shipped_by_nordic(self):
        result = lookup_LL_VERSION_IND_metadata(0x0B, 0x0059, 0x3123)
        assert result['match_quality'].startswith('vendor/version')
        assert 'SoftDevice Controller' not in result['software'][0]

    def test_unknown_nordic_fwid_still_gets_conservative_hint(self):
        result = lookup_LL_VERSION_IND_metadata(0x09, 0x0059, 0xDEAD)
        assert result['software'] == ['Nordic controller firmware (exact release unknown)']
        assert any('nRF51 excluded' in note for note in result['notes'])
        assert result['match_quality'].startswith('vendor/version')

    def test_unknown_non_nordic_tuple_has_no_match(self):
        assert lookup_LL_VERSION_IND_metadata(0x09, 0x000D, 0xDEAD) is None

    def test_yichip_static_version_tuple(self):
        result = lookup_LL_VERSION_IND_metadata(0x08, 0x050E, 0x0003)
        assert result['chips'] == ['YiChip YC1121 family']
        assert 'YC1121 BLE controller' in result['software'][0]
        assert 'not field-observed' in result['match_quality']
        assert any('not verified from an on-air capture' in note
                   for note in result['notes'])

    def test_open_link_layer_defaults_do_not_claim_a_chip(self):
        nimble = lookup_LL_VERSION_IND_metadata(0x09, 0x0B65, 0x0000)
        zephyr = lookup_LL_VERSION_IND_metadata(0x0D, 0x05F1, 0xFFFF)
        assert nimble['software'] == ['Apache NimBLE controller default configuration']
        assert zephyr['software'] == ['Zephyr software Link Layer default configuration']
        assert 'software defaults' in nimble['match_quality']
        assert 'software defaults' in zephyr['match_quality']
        assert not nimble.get('chips')
        assert not zephyr.get('chips')

    def test_ll_company_subversion_chip_match(self):
        result = lookup_LL_VERSION_IND_metadata(0xFF, 0x000F, 0x420E)
        assert result['chips'] == [
            'Broadcom BCM4347B1',
            'Cypress CYW20739B1',
            'Broadcom BCM4349B1',
        ]
        assert 'VersNr not constrained' in result['match_quality']

    def test_ghidra_verified_ll_and_lmp_versions_are_separate(self):
        broadcom_ll = lookup_LL_VERSION_IND_metadata(0x07, 0x000F, 0x2209)
        broadcom_lmp = lookup_LMP_VERSION_metadata(0x06, 0x000F, 0x2209)
        assert broadcom_ll['chips'] == ['Broadcom BCM43430A1']
        assert broadcom_lmp['chips'] == ['Broadcom BCM43430A1']
        assert broadcom_ll['match_quality'].startswith('exact')
        assert broadcom_lmp['match_quality'].startswith('exact')
        assert broadcom_ll['sources'] == ['Broadcom_GPT5.6_renames_2026-07-26']
        assert broadcom_lmp['sources'] == broadcom_ll['sources']

        # A different LMP VersNr still gets the older, less precise match.
        broadcom_fallback = lookup_LMP_VERSION_metadata(0x07, 0x000F, 0x2209)
        assert 'VersNr not constrained' in broadcom_fallback['match_quality']

        realtek = lookup_LMP_VERSION_metadata(0x0A, 0x005D, 0xD922)
        assert realtek['firmware_state'] == 'patched'
        assert realtek['patch_version'] == '0xD922'
        assert realtek['linux_firmware_history']['chips'] == ['Realtek RTL8761B*']
        assert realtek['sources'] == ['user_rtl8761bu_opus4.7_rename_2026-04-30']
        realtek_ll = lookup_LL_VERSION_IND_metadata(0x0A, 0x005D, 0xD922)
        assert realtek_ll['linux_firmware_history'] == realtek['linux_firmware_history']
        rtl8821ce = lookup_LL_VERSION_IND_metadata(0x08, 0x005D, 0x8821)
        assert rtl8821ce['chips'] == ['Realtek RTL8821CE']
        assert rtl8821ce['sources'] == ['RTL8821CE_GPT5.6_renames_2026-07-26']
        rtl8821ce_lmp = lookup_LMP_VERSION_metadata(0x08, 0x005D, 0x8821)
        assert rtl8821ce_lmp['chips'] == rtl8821ce['chips']
        assert rtl8821ce_lmp['sources'] == rtl8821ce['sources']
        chip_text, quality = chipprint_by_LMP_VERSION(0x08, 0x8821, 0x005D)
        assert chip_text == 'Possible chip(s): Realtek RTL8821CE'
        assert quality.startswith('exact')

        asr = lookup_LL_VERSION_IND_metadata(0x0A, 0x0917, 0x0008)
        assert asr['chips'] == ['ASR Microelectronics ASR582x family']
        assert asr['sources'] == ['ASR582x_gpt6.0_sol_renames_2026-10-09']

    def test_lmp_metadata_contains_same_extracted_chip_matches(self):
        assert len(TME.TME_glob.ll_version_ind_metadata[
            'company_subversion_matches'
        ]) == 52
        assert (
            TME.TME_glob.ll_version_ind_metadata[
                'company_subversion_matches'
            ]
            == TME.TME_glob.lmp_version_metadata[
                'company_subversion_matches'
            ]
        )

        result = lookup_LMP_VERSION_metadata(0x0C, 0x005D, 0xD922)
        assert result['chips'] == ['Realtek RTL8761B*']
        assert result['patch_version'] == '0xD922'
        assert 'VersNr not constrained' in result['match_quality']

    def test_realtek_linux_firmware_history_and_collisions(self):
        ll_history = TME.TME_glob.ll_version_ind_metadata[
            'realtek_linux_firmware_history'
        ]
        lmp_history = TME.TME_glob.lmp_version_metadata[
            'realtek_linux_firmware_history'
        ]
        assert ll_history == lmp_history
        assert len(ll_history['unique_patch_subversions']) == 75
        assert set(ll_history['cross_chip_collisions']) == {
            '0x020A', '0x4380', '0x7644'
        }

        old_8761b = lookup_LMP_VERSION_metadata(0x0A, 0x005D, 0x8A6B)
        assert old_8761b['chips'] == ['Realtek RTL8761B*']
        assert old_8761b['firmware_images'] == {
            'rtl8761b_fw.bin': '0x0CA98A6B',
            'rtl8761bu_fw.bin': '0x09A98A6B',
        }

        rtbtcore = lookup_LL_VERSION_IND_metadata(0x0C, 0x005D, 0xD230)
        assert rtbtcore['chips'] == ['Realtek RTL8851B']
        assert rtbtcore['format'] == 'rtbtcore'

        # These values occur in unrelated chip families, so every candidate
        # must be retained and the ambiguity must be explicit.
        collision_020a = lookup_LMP_VERSION_metadata(
            0x08, 0x005D, 0x020A
        )
        assert collision_020a['chips'] == [
            'Realtek RTL8192EE',
            'Realtek RTL8192EU',
            'Realtek RTL8812AE',
        ]
        assert collision_020a['cross_chip_collision'] is True
        assert collision_020a['match_quality'].startswith('cross-chip')

        collision_4380 = lookup_LL_VERSION_IND_metadata(
            0x08, 0x005D, 0x4380
        )
        assert collision_4380['chips'] == [
            'Realtek RTL8723A', 'Realtek RTL8761A'
        ]
        assert collision_4380['cross_chip_collision'] is True

        collision_7644 = lookup_LMP_VERSION_metadata(
            0x08, 0x005D, 0x7644
        )
        assert collision_7644['chips'] == [
            'Realtek RTL8821C*', 'Realtek RTL8852A'
        ]
        assert collision_7644['cross_chip_collision'] is True

    def test_legacy_chip_helper_is_backed_by_loaded_metadata(self):
        assert chip_by_sub_version(0x6308, 0x000F) == 'Broadcom BCM4387C2'
        assert chip_by_sub_version(0x8762, 0x005D) == (
            'Realtek RTL8762 (running unpatched)'
        )
        assert chip_by_sub_version(0x8A6B, 0x005D) == (
            'Realtek RTL8761B* (running patch version 0x8a6b)'
        )
        assert chip_by_sub_version(0x020A, 0x005D) == (
            'Possible chip(s): Realtek RTL8192EE, Realtek RTL8192EU, '
            'Realtek RTL8812AE'
        )
        assert chip_by_sub_version(0xDEAD, 0x000F) == ''

    def test_chipprint_lists_every_realtek_collision_candidate(self):
        chip_text, quality = chipprint_by_sub_version(0x020A, 0x005D)
        assert chip_text == (
            'Possible chip(s): Realtek RTL8192EE, Realtek RTL8192EU, '
            'Realtek RTL8812AE'
        )
        assert quality == (
            'cross-chip SubVersNr collision; exact chip unknown; '
            'VersNr not constrained'
        )

    def test_chipprint_printer_labels_realtek_collision(self, monkeypatch):
        import TME.TME_metadata as metadata

        def fake_execute_query(query, _values):
            if 'FROM LL_VERSION_IND' in query:
                return [(0x08, 0x020A, 0x005D)]
            if 'FROM LMP_VERSION_RES' in query:
                return [(0x08, 0x020A, 0x005D)]
            return []

        output = []
        monkeypatch.setattr(metadata, 'execute_query', fake_execute_query)
        monkeypatch.setattr(metadata, 'qprint', output.append)
        monkeypatch.setattr(metadata, 'vprint', lambda _line: None)
        monkeypatch.setattr(metadata, 'string_yellow_bright', lambda value: value)
        monkeypatch.setattr(
            TME.TME_glob, 'g_printed_ChipPrint_header', False
        )

        print_ChipPrint('00:00:00:00:00:00', 0)
        rendered = '\n'.join(output)
        assert (
            'Possible chip(s): Realtek RTL8192EE, Realtek RTL8192EU, '
            'Realtek RTL8812AE -> From LL_VERSION_IND info '
            '(cross-chip SubVersNr collision; exact chip unknown; '
            'VersNr not constrained)'
        ) in rendered
        assert (
            'Possible chip(s): Realtek RTL8192EE, Realtek RTL8192EU, '
            'Realtek RTL8812AE -> From LMP_VERSION_REQ/RES info '
            '(cross-chip SubVersNr collision; exact chip unknown; '
            'VersNr not constrained)'
        ) in rendered

        chip_text, quality = chipprint_by_LL_VERSION(
            0x08, 0x020A, 0x005D
        )
        assert chip_text == (
            'Possible chip(s): Realtek RTL8192EE, Realtek RTL8192EU, '
            'Realtek RTL8812AE'
        )
        assert quality == (
            'cross-chip SubVersNr collision; exact chip unknown; '
            'VersNr not constrained'
        )

    def test_chipprint_uses_exact_lmp_tuple(self, monkeypatch):
        import TME.TME_metadata as metadata

        def fake_execute_query(query, _values):
            if 'FROM LMP_VERSION_RES' in query:
                assert 'SELECT lmp_version, lmp_sub_version, device_BT_CID' in query
                return [(0x08, 0x8821, 0x005D)]
            return []

        output = []
        monkeypatch.setattr(metadata, 'execute_query', fake_execute_query)
        monkeypatch.setattr(metadata, 'qprint', output.append)
        monkeypatch.setattr(metadata, 'vprint', lambda _line: None)
        monkeypatch.setattr(metadata, 'string_yellow_bright', lambda value: value)
        monkeypatch.setattr(TME.TME_glob, 'g_printed_ChipPrint_header', False)

        print_ChipPrint('00:00:00:00:00:00', 0)
        rendered = '\n'.join(output)
        assert 'Realtek RTL8821CE' in rendered
        assert 'exact LMP version tuple' in rendered

    def test_chipprint_uses_nordic_exact_and_fallback_metadata(self):
        chip_text, quality = chipprint_by_LL_VERSION(
            0x0A, 0x0102, 0x0059
        )
        assert chip_text == (
            'Possible chip(s): nRF52805, nRF52810, nRF52811, nRF52820, '
            'nRF52832, nRF52833, nRF52840'
        )
        assert quality.startswith('exact')

        chip_text, quality = chipprint_by_LL_VERSION(
            0x09, 0xDEAD, 0x0059
        )
        assert chip_text == 'Possible chip(s): nRF52 or newer Nordic family'
        assert quality.startswith('vendor/version')

    def test_ll_and_lmp_printers_render_realtek_patch_state(self, monkeypatch):
        import TME.TME_LLCP as llcp
        import TME.TME_LMP as lmp

        output = []
        monkeypatch.setattr(llcp, 'qprint', output.append)
        monkeypatch.setattr(lmp, 'qprint', output.append)

        print_LL_VERSION_IND_metadata(0x0A, 0x005D, 0xD922)
        print_LMP_VERSION_metadata(0x0A, 0x005D, 0xD922)
        rendered = '\n'.join(output)
        assert rendered.count('Possible chip(s): Realtek RTL8761B*') == 2
        assert rendered.count(
            'Controller firmware state: patched (patch version 0xD922)'
        ) == 2

    def test_llcp_printer_renders_exact_identification(self, monkeypatch):
        import TME.TME_LLCP as llcp

        def fake_execute_query(query, _values):
            if 'FROM LL_VERSION_IND' in query:
                return [(0x0A, 0x0102, 0x0059)]
            return []

        output = []
        monkeypatch.setattr(llcp, 'execute_query', fake_execute_query)
        monkeypatch.setattr(llcp, 'qprint', output.append)
        monkeypatch.setattr(llcp, 'vprint', lambda _line: None)
        monkeypatch.setattr(
            llcp,
            'get_bt_spec_version_numbers_to_names',
            lambda _version: 'Bluetooth Core 5.1',
        )
        monkeypatch.setattr(
            llcp,
            'BT_CID_to_company_name',
            lambda _company_id: 'Nordic Semiconductor ASA',
        )

        print_LLCP_info('4c:ad:35:4f:4c:e1', 0)
        rendered = '\n'.join(output)
        assert 'exact LL_VERSION_IND metadata match' in rendered
        assert 'Possible SoftDevice/controller: S113 7.2.0' in rendered
        assert 'Possible chip(s): nRF52805' in rendered
        assert 'Possible SDK version(s): nRF5 SDK 17.0.2' in rendered


class TestBTIDESSchemas:
    """The BTIDES_Schema/ directory ships JSON Schemas that the export path
    validates against. Just confirm they parse and look like JSON Schema.
    """

    def test_all_schemas_parse(self, schema_dir):
        schemas = list(schema_dir.glob("BTIDES_*.json"))
        assert len(schemas) >= 10, f"Expected ~12 BTIDES schemas, found {len(schemas)}"
        for schema_path in schemas:
            with open(schema_path) as f:
                data = json.load(f)
            assert "$schema" in data or "type" in data or "$ref" in data or "$defs" in data, \
                f"{schema_path.name} doesn't look like a JSON Schema"

    def test_base_schema_present(self, schema_dir):
        base = schema_dir / "BTIDES_base.json"
        assert base.exists(), "BTIDES_base.json is the root schema; it must exist"


class TestWriteBTIDESVersionGate:
    """write_BTIDES() refuses to export when the on-disk BTIDES_base.json
    advertises a schema version older than what the code requires.
    """

    @staticmethod
    def _stage_schema_dir(dst_root: Path, src_schema_dir: Path, version: str):
        """Copy the real BTIDES_Schema/ to dst_root/BTIDES_Schema/ with
        BTIDES_base.json's "version" field rewritten to `version`.
        """
        dst_schema = dst_root / "BTIDES_Schema"
        dst_schema.mkdir()
        for src in src_schema_dir.glob("BTIDES_*.json"):
            shutil.copy(src, dst_schema / src.name)
        base = dst_schema / "BTIDES_base.json"
        data = json.loads(base.read_text())
        data["version"] = version
        base.write_text(json.dumps(data))
        return dst_schema

    def test_rejects_older_schema(self, tmp_path, schema_dir, monkeypatch):
        staged = self._stage_schema_dir(tmp_path, schema_dir, "0.4.9")

        # write_BTIDES reads schemas from the absolute _BTIDES_SCHEMA_DIR
        # constant (resolved relative to TME_BTIDES_base.py), not cwd, so
        # monkeypatch that constant to the staged directory.
        import TME.TME_glob
        import TME.TME_BTIDES_base
        monkeypatch.setattr(TME.TME_BTIDES_base, "_BTIDES_SCHEMA_DIR", str(staged))

        TME.TME_glob.BTIDES_JSON = [{"bdaddr": "aa:bb:cc:dd:ee:ff", "bdaddr_rand": 0}]
        with pytest.raises(ValueError, match="0.4.9.*less than.*0.5.0"):
            TME.TME_BTIDES_base.write_BTIDES(str(tmp_path / "out.btides"))

    def test_accepts_current_schema(self, tmp_path, schema_dir, monkeypatch):
        """Sanity-check: the same staging path with the real version passes."""
        real_version = json.loads((schema_dir / "BTIDES_base.json").read_text())["version"]
        staged = self._stage_schema_dir(tmp_path, schema_dir, real_version)

        import TME.TME_glob
        import TME.TME_BTIDES_base
        monkeypatch.setattr(TME.TME_BTIDES_base, "_BTIDES_SCHEMA_DIR", str(staged))

        TME.TME_glob.BTIDES_JSON = [{"bdaddr": "aa:bb:cc:dd:ee:ff", "bdaddr_rand": 0}]
        TME.TME_BTIDES_base.write_BTIDES(str(tmp_path / "out.btides"))  # must not raise
        assert (tmp_path / "out.btides").exists()


# Small valid-shape CLUES entries used to exercise the loader. The
# loader itself only cares about UUID + optional "regex" key; the other
# fields are present so the records look like real CLUES data and so
# they survive any future per-field validation we might add to load.
def _entry(uuid, *, company="Test Co", regex=False):
    e = {
        "UUID": uuid,
        "company": company,
        "UUID_name": "Unknown",
        "UUID_purpose": "test fixture",
        "UUID_usage_array": ["GATT Service"],
        "evidence_array": [{"URL": "https://example.test", "submitter": "test"}],
    }
    if regex:
        e["regex"] = True
    return e


# UUIDs chosen so the 32-char (dashes-stripped) keys start with distinct
# hex digits — that way split-form tests verify entries actually land in
# the correct hex bucket.
_UUID_BUCKET_0 = "00001111-2222-3333-4444-555566667777"  # bucket '0'
_UUID_BUCKET_5 = "50001111-2222-3333-4444-555566667777"  # bucket '5'
_UUID_BUCKET_A = "a0001111-2222-3333-4444-555566667777"  # bucket 'a'
_UUID_BUCKET_F = "f0001111-2222-3333-4444-555566667777"  # bucket 'f'


class TestCluesIo:
    """clues_io.{load_clues,save_clues,clues_exists} are the canonical
    helpers for the two on-disk CLUES layouts. These tests exercise the
    helpers directly so the contract TME relies on is pinned by tests
    that live in this repo, not just in the CLUES_Schema submodule.
    """

    def test_load_single_file(self, tmp_path):
        path = tmp_path / "CLUES_data_test.json"
        entries = [_entry(_UUID_BUCKET_0), _entry(_UUID_BUCKET_A)]
        save_clues(entries, str(path), split=False)
        assert path.exists(), "single-file save should produce the combined file"
        loaded = load_clues(str(path))
        assert loaded == entries

    def test_load_split_files(self, tmp_path):
        """save_clues(split=True) writes 16 hex shards; load_clues merges
        them back. Verifies records land in the correct hex bucket and
        the single combined file is NOT created."""
        path = tmp_path / "CLUES_data_test.json"
        entries = [
            _entry(_UUID_BUCKET_0),
            _entry(_UUID_BUCKET_5),
            _entry(_UUID_BUCKET_A),
            _entry(_UUID_BUCKET_F),
        ]
        save_clues(entries, str(path), split=True)
        assert not path.exists(), "split-form save must not also write a combined file"
        for digit in "0123456789abcdef":
            shard = tmp_path / f"CLUES_data_test_{digit}.json"
            assert shard.exists(), f"shard {shard.name} should be created"
        # Each record landed in the bucket matching its first hex char.
        for digit, uuid in [("0", _UUID_BUCKET_0), ("5", _UUID_BUCKET_5),
                            ("a", _UUID_BUCKET_A), ("f", _UUID_BUCKET_F)]:
            shard_data = json.loads((tmp_path / f"CLUES_data_test_{digit}.json").read_text())
            assert [e["UUID"] for e in shard_data] == [uuid]
        loaded = load_clues(str(path))
        assert sorted(e["UUID"] for e in loaded) == sorted(e["UUID"] for e in entries)

    def test_load_missing_returns_empty(self, tmp_path):
        loaded = load_clues(str(tmp_path / "does_not_exist.json"))
        assert loaded == []

    def test_clues_exists_single(self, tmp_path):
        path = tmp_path / "CLUES_data_test.json"
        path.write_text("[]")
        assert clues_exists(str(path)) is True

    def test_clues_exists_split_only(self, tmp_path):
        """clues_exists must report True when the logical path is absent
        but at least one hex shard is present — this is the post-split
        on-disk state that TME_import must transparently handle."""
        path = tmp_path / "CLUES_data_test.json"
        (tmp_path / "CLUES_data_test_3.json").write_text("[]")
        assert not path.exists()
        assert clues_exists(str(path)) is True

    def test_clues_exists_neither(self, tmp_path):
        assert clues_exists(str(tmp_path / "nope.json")) is False

    def test_save_split_then_resave_preserves_layout(self, tmp_path):
        """save_clues(split=None) — the default in code paths that aren't
        SortCLUES — must preserve whatever layout is already on disk. If
        the existing layout is hex-split, the rewrite stays hex-split."""
        path = tmp_path / "CLUES_data_test.json"
        save_clues([_entry(_UUID_BUCKET_A)], str(path), split=True)
        save_clues([_entry(_UUID_BUCKET_F)], str(path))  # split=None default
        assert not path.exists(), "default save must not collapse split back to single"
        assert (tmp_path / "CLUES_data_test_f.json").exists()
        loaded = load_clues(str(path))
        assert [e["UUID"] for e in loaded] == [_UUID_BUCKET_F]


class TestTMECluesLoading:
    """TME_import._load_clues_file is the seam between CLUES_Schema's
    on-disk layout and TME's in-memory clue dicts. These tests pin the
    behavior under both single-file and 16-shard hex-split layouts,
    plus the required-file-missing error path.
    """

    @pytest.fixture
    def fresh_clues(self, monkeypatch):
        """Snapshot-and-restore TME.TME_glob.clues / clues_regexed so each
        test starts with empty dicts and doesn't leak entries into other
        tests. Returns (clues, clues_regexed) for direct assertions."""
        import TME.TME_glob
        clues = {}
        clues_regexed = {}
        monkeypatch.setattr(TME.TME_glob, "clues", clues)
        monkeypatch.setattr(TME.TME_glob, "clues_regexed", clues_regexed)
        return clues, clues_regexed

    def test_loads_single_file(self, tmp_path, fresh_clues):
        clues, _ = fresh_clues
        path = tmp_path / "CLUES_data_single.json"
        save_clues([_entry(_UUID_BUCKET_A, company="Acme")], str(path), split=False)

        from TME.TME_import import _load_clues_file
        _load_clues_file(str(path), required=False)

        key = _UUID_BUCKET_A.replace("-", "")
        assert key in clues, "single-file path should populate TME_glob.clues"
        assert clues[key]["company"] == "Acme"

    def test_loads_split_files(self, tmp_path, fresh_clues):
        """The post-split state: the logical .json path does NOT exist on
        disk, only the 16 hex shards do. _load_clues_file must still
        populate TME_glob.clues from the shards."""
        clues, _ = fresh_clues
        path = tmp_path / "CLUES_data_split.json"
        entries = [
            _entry(_UUID_BUCKET_0, company="Co0"),
            _entry(_UUID_BUCKET_5, company="Co5"),
            _entry(_UUID_BUCKET_A, company="CoA"),
            _entry(_UUID_BUCKET_F, company="CoF"),
        ]
        save_clues(entries, str(path), split=True)
        assert not path.exists(), "precondition: logical path absent in split form"

        from TME.TME_import import _load_clues_file
        _load_clues_file(str(path), required=False)

        for uuid, company in [(_UUID_BUCKET_0, "Co0"), (_UUID_BUCKET_5, "Co5"),
                              (_UUID_BUCKET_A, "CoA"), (_UUID_BUCKET_F, "CoF")]:
            key = uuid.replace("-", "")
            assert key in clues, f"entry in shard for {uuid!r} should load"
            assert clues[key]["company"] == company

    def test_required_missing_raises(self, tmp_path, fresh_clues):
        """When the file is required and neither the combined .json nor
        any hex shard exists, _load_clues_file must raise so the canonical
        CLUES_data_human_verified.json's absence isn't silently ignored."""
        from TME.TME_import import _load_clues_file
        with pytest.raises(FileNotFoundError):
            _load_clues_file(str(tmp_path / "missing.json"), required=True)

    def test_optional_missing_silent(self, tmp_path, fresh_clues):
        """Optional tiers (LLM-derived files, private overrides) must
        return silently when neither layout exists on disk."""
        clues, _ = fresh_clues
        from TME.TME_import import _load_clues_file
        _load_clues_file(str(tmp_path / "missing.json"), required=False)
        assert clues == {}

    def test_strips_dashes_from_uuid(self, tmp_path, fresh_clues):
        """TME uses dashes-stripped 32-char UUID keys internally for O(1)
        lookups. The loader is the place where dashes get normalized
        away, regardless of which on-disk layout supplied the entry."""
        clues, _ = fresh_clues
        path = tmp_path / "CLUES_data_dashes.json"
        save_clues([_entry(_UUID_BUCKET_A)], str(path), split=True)

        from TME.TME_import import _load_clues_file
        _load_clues_file(str(path), required=False)

        dashed_key = _UUID_BUCKET_A
        stripped_key = _UUID_BUCKET_A.replace("-", "")
        assert dashed_key not in clues, "dashed UUID should NOT appear as a key"
        assert stripped_key in clues, "stripped 32-char UUID should be the key"

    def test_regex_entries_added_to_regexed(self, tmp_path, fresh_clues):
        """Entries with the 'regex' field land in BOTH clues and
        clues_regexed (TME does a regex-aware lookup pass against the
        latter for entries whose UUID is itself a pattern)."""
        clues, clues_regexed = fresh_clues
        path = tmp_path / "CLUES_data_regex.json"
        save_clues(
            [_entry(_UUID_BUCKET_0), _entry(_UUID_BUCKET_F, regex=True)],
            str(path),
            split=True,
        )

        from TME.TME_import import _load_clues_file
        _load_clues_file(str(path), required=False)

        plain_key = _UUID_BUCKET_0.replace("-", "")
        regex_key = _UUID_BUCKET_F.replace("-", "")
        assert plain_key in clues and plain_key not in clues_regexed
        assert regex_key in clues and regex_key in clues_regexed
