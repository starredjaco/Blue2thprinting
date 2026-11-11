# HCI-to-BTIDES regression fixtures

These are minimal H4 BTSnoop files (one to three records each). The two
nonlegacy advertising reports and ATT connection/read exchange come from a
2026-11-11 Pixel P1 QA capture. The two-report legacy event is synthetic:
the capture had only single-report HCI events, but the HCI format permits
multiple reports in one event. The repeated-report fixture duplicates the
sanitized 100-byte report twice in the same millisecond to guard observation
counts against value-only or millisecond-time deduplication.

The fixture generator retained packet structure and AD lengths. Device
addresses were replaced with `02:00:00:00:00:*`; the ambient product name
became `QA Extended Test`, its six RSI bytes became `01 02 03 04 05 06`,
and the ATT response value became `QATEST-EB`. The long nonconnectable AD
payload was emitted by our own QA extended advertiser and was retained to
test full 100-byte raw-data preservation. The private full P1 BTSnoop capture
is not checked in.
