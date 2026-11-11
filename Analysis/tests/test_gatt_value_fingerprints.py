"""GATT value rules must keep chip and module evidence separate."""

import sys
from pathlib import Path

ANALYSIS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ANALYSIS_DIR))

import TME.TME_glob as glob  # noqa: E402
import TME.TME_metadata as metadata  # noqa: E402
from TME.TME_import import import_GATT_value_fingerprints  # noqa: E402


def test_rule_matching_respects_uuid_and_address_type(monkeypatch):
    import_GATT_value_fingerprints()

    def fake_query(query, values):
        assert 'v.operation = 11' in query
        assert values == ('aa:bb:cc:00:00:01', 1)
        return [
            ('00002A24-0000-1000-8000-00805F9B34FB', 10, b'CC2640'),
            ('2a28', 12, b'nRF52-SDK17.02'),
            ('2a24', 14, b'BM71'),
            ('2a24', 16, b'FSC-BT836'),
            ('2a29', 18, b'CC2640'),  # same text, wrong UUID
            (None, 20, b'QCC3040'),  # explicitly allowed unmapped value
            (None, 22, b'BM71'),  # module rule requires its UUID
            ('2a24', 24, b'RN4020-junk'),
        ]

    monkeypatch.setattr(metadata, 'execute_query', fake_query)
    matches = metadata.lookup_GATT_value_fingerprints('aa:bb:cc:00:00:01', 1)
    assert [rule['id'] for rule, _, _ in matches] == [
        'ti_cc2640', 'nordic_nrf52_sdk', 'microchip_bm71',
        'feasycom_fsc_bt836', 'qualcomm_qcc3040',
    ]
    assert matches[2][0]['chip'] == 'Microchip IS1871'
    assert matches[2][0]['module'] == 'Microchip BM71'
    assert 'chip_maker' not in matches[3][0]  # Feasycom is a module maker


def test_module_sections_use_module_fields(monkeypatch):
    import_GATT_value_fingerprints()
    rules = {rule['id']: rule for rule in glob.gatt_value_fingerprint_rules}
    matches = [
        (rules['microchip_bm71'], '2a24', 'BM71'),
        (rules['feasycom_fsc_bt946'], '2a24', 'FSC-BT946'),
    ]
    output = []
    monkeypatch.setattr(metadata, 'qprint', output.append)
    monkeypatch.setattr(metadata, 'vprint', lambda _value: None)
    monkeypatch.setattr(metadata, 'string_yellow_bright', lambda value: value)
    monkeypatch.setattr(glob, 'g_printed_ModulePrint_header', False)
    monkeypatch.setattr(glob, 'g_printed_ModuleMakerPrint_header', False)

    metadata.print_ModulePrint('aa:bb:cc:00:00:01', 0, matches)
    metadata.print_ModuleMakerPrint('aa:bb:cc:00:00:01', 0, matches)
    rendered = '\n'.join(output)
    assert 'ModulePrint:' in rendered
    assert 'Microchip BM71' in rendered
    assert 'Feasycom FSC-BT946' in rendered
    assert 'ModuleMakerPrint:' in rendered
    assert 'Microchip Technology' in rendered
    assert 'Feasycom' in rendered
