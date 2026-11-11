# GATT SDK and module follow-up (2026-11-11)

## Scan scope and results

Scanned all 249,157 `GATT_characteristics_values` rows and 74,911
`GATT_characteristic_descriptor_values` rows in the local `bt2` database.
Characteristic values have 7,495 distinct raw byte strings; 4,412
UUID/value combinations decode as short printable UTF-8. A broad search for
SDK, SoftDevice, Gecko, NimBLE, Mynewt, Zephyr, Bluedroid, BTstack, Silicon
Labs, SimpleLink, FreeRTOS, MCUX, nRF, Nordic, and BlueZ found 26 distinct
printable UUID/value combinations, including device names and chip-family
labels. No descriptor value contained these terms.

| GATT value | Characteristic | BDADDRs | Example BDADDR | SDK conclusion |
| --- | --- | ---: | --- | --- |
| `nRF52-SDK13.0` | `2a28` (40 mapped, 1 unmapped) | 41 | `AC:23:3F:F4:2B:B8` | Device-reported nRF5 SDK 13.0.x shorthand; patch not encoded. 20 addresses also have Nordic `LL_VERSION_IND 08:0059:0098`, whose SDK compatibility metadata lists 13.0.0 and 13.1.0. |
| `nRF52-SDK17.02` | `2a28` | 18 | `C3:00:00:3D:78:FC` | Device-reported shorthand for nRF5 SDK 17.0.2. One address also has Nordic `LL_VERSION_IND 0A:0059:0103`; that tuple is compatible with 17.0.2, 17.1.0, and 17.1.1, so the GATT label adds resolution. |
| `nRF5_SDK_11.0.0_89a8197` | `2a28` | 1 | `C6:12:AC:5D:CD:D4` | Exact filename match to the downloaded `nRF5_SDK_11.0.0_89a8197.zip`; the same device's `2a27` says `NRF51822QFAAH0`. |
| `MT28xx_SDK_...`, `Release-SDK_6.5.5.*`, `SDK 2.0` | `2a26` or unmapped | 16 | `CB:43:18:EB:21:0B` | Explicit SDK tokens captured as unattributed SDKPrints. `SDK 2.0` has one mapped and two unmapped observations. No dependable chip-maker attribution or SDK archive match. |
| `BlueZ 5.66` | `2a00` | 1 | `78:1C:9D:70:3B:36` | Host stack/version in the Device Name, not a BLE firmware SDK release. |
| `Zephyr Heartrate Senso` | `2a00` | 1 | `11:22:33:44:55:66` | Sample application name on a test-like address, without a version. |
| `5505 102_LESDK` | unmapped | 1 | `44:B7:D0:23:F4:A4` | Possible Microchip SDK token, but no characteristic UUID or matching SDK release identified. Research-only. |

The Nordic SDK archives consulted are under
`/Volumes/EXFAT/B-HIVEMIND/SDKs/Nordic/nRF5_SDK`. In SDK 11.0.0,
13.0.0, and 17.0.2, the blood-pressure example defines both
`NordicSemiconductor` as `2a29` Manufacturer Name and `NS-BPS-EXAMPLE` as
`2a24` Model Number. No observed BDADDR has both exact values. The
`NordicSemiconductor` value alone appears on four addresses and is shared
across SDK releases, so it does not identify a release.

The extracted TI BLE-CC254x 1.5.2.0 SDK's SensorTag Device Information
Service defines `CC2541 SensorTag` as `2a24` and `Texas Instruments` as
`2a29`. Neither exact string appears in the scanned characteristic values,
so this source-defined pair also has no observed match.

The downloaded Silicon Labs Gecko SDK's
`app/bluetooth/common/gatt_service_device_information/sl_gatt_service_device_information.c`
writes `SL_GSDK_VERSION_STR` into `2a26` Firmware Revision. That component
exists in the downloaded v4.2.0 through v4.5.1 tags. It also writes the
board name to `2a24` and board revision to `2a27`, when configured. The
version alone is a weak candidate: `7E:24:11:BC:06:1B` reports `2a26`
`4.5.0`, which coincides with a Gecko SDK tag, but its controller Company
ID is Qualcomm (`000A`) and the GATT Manufacturer Name is Bose. The guarded
SDKPrint rule suppresses it. No observed version-only Gecko candidate has
an independent Silicon Laboratories ChipMakerPrint, and no observed device
has two exact, release-specific characteristic values from downloaded SDK
source. Thus no high-confidence source-pair SDK rule was added.
Older Gecko tag numbers such as `4.0.1`, `4.0.2`, `4.1.0`, and `4.1.3`
also occur as Bose or Sony firmware strings, further demonstrating why a
numeric match alone is insufficient. The examined GATT component was not
present in those older SDK tags, so the guarded rule starts at v4.2.0.

## Module-to-chip research

| GATT module name | Observed BDADDR | Chip relationship | Evidence |
| --- | --- | --- | --- |
| BM71 | `44:B7:D0:7A:4D:52` | IS1871 chip family; Microchip explicitly pairs BM71 with IS1871. | [Microchip BM71 product](https://www.microchip.com/en-us/product/bm71) |
| RN4020 | `00:1E:C0:59:11:CC` | Integrated BLE radio/MCU, but the available Microchip product sheet does not name a separate chip model. No chip mapping added. | [Microchip RN4020 datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/Bluetooth-Low-Energy-Module-DS50002279C.pdf) |
| FSC-BT836 | `DC:0D:30:37:A9:0B` | Feasycom's v1.5 specification names Realtek RTL8761; the observed LMP Company ID `005D` independently identifies Realtek. Exact RTL8761 suffix is unknown. Added as a family-level chip hint. | [Feasycom FSC-BT836 v1.5 specification](https://www.feasycom.net/Content/upload/2019217626/PDF/FSC-BT836-SPEC-V1.5.pdf) |
| FSC-BT946 | `DC:0D:30:11:D6:7B` | Feasycom names a BLE 5.2 SoC but does not disclose its model. No chip mapping added. | [Feasycom FSC-BT946 datasheet](https://www.feasycom.com/datasheet/fsc-bt946.pdf) |

These are mappings for the named module revisions documented above, not a
general rule that a module model always has one chip. Feasycom documents its
FSC-BT806 module as available with CSR8670 or CSR8675, an example of a
module model spanning two chips: [Feasycom FSC-BT806 article](https://www.feasycom.com/audio-solution-feasycom-audio-bt-module/).
