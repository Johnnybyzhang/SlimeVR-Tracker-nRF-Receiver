# Passive relay sniffer

## Current transport and format, 2026-11-04

The current firmware replaces CDC with a vendor USB interface. The historical
CDC/RSN1 instructions below describe the original implementation only. Use
these commands for the current dongle. The sniffer stays passive, and no
filter is enabled or implemented. Every RADIO END, including CRC failures,
remains eligible for capture across all eight pipes.

USB identity is **1209:7691**, serial **ED3CC490E336F17A**. There is no application
serial port. Interface 0 is vendor class 255, with one full-speed 64-byte bulk
IN endpoint, currently 0x81. ASCII start/stop/dfu commands use device vendor
OUT control request 0x53, wValue=0, wIndex=0. PyUSB claims interface 0 only after
matching both VID:PID and the exact sniffer serial. No macOS kernel driver is
needed. `ports` also lists this vendor interface. Legacy CDC capture is still
available with `--port` for replaying development measurements.

```sh
source /Users/johnny/nrf54-fork/env.sh
cd /Users/johnny/nrf54-fork/sniffer
# libusb is already installed through Homebrew; PyUSB was installed with:
# uv pip install --python ../.venv/bin/python \
#   --default-index https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple pyusb
python scripts/relay_sniffer.py ports
python scripts/relay_sniffer.py capture \
  --serial ED3CC490E336F17A --receiver-id-le e528cf1a7bc3 --channel 88 \
  --seconds 120 --raw /tmp/fleet.rsn --jsonl /tmp/fleet.jsonl
python scripts/relay_sniffer.py dfu --serial ED3CC490E336F17A
# Wait for bootloader serial D1BAB5688DB0, then use only that serial:
nrfutil device program --serial-number D1BAB5688DB0 --traits nordicDfu \
  --firmware ../build/relay-sniffer/relay-sniffer.zip --json
```

The build/package/passivity commands below are unchanged. Do not send DFU to
any fleet device. The control request completes before firmware pulls P0.19
low. Command processing remains available when the stream reader stalls.
Explicit STOP stops reception, drains the radio ring, and emits a footer after
all captured records. USB unconfiguration also stops reception. There is no
CDC DTR anymore; a process killed without cleanup may leave passive RX active.
Reconnect and issue STOP while draining, or use the DFU command to reset it.

### RSN3 wire format

Version 3 is identified by the chunk magic `RSN3`. All integer fields are
little endian. USB transfer boundaries are not needed by the decoder.
A chunk is at most 1024 bytes and contains whole records:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | ASCII RSN3, format version 3 |
| 4 | 2 | Total chunk bytes, including trailing CRC |
| 6 | 2 | Number of records |
| 8 | 4 | Chunk sequence, monotonically increasing modulo 2^32 |
| 12 | variable | Whole records |
| final 4 | 4 | IEEE CRC32 over everything preceding it in this chunk |

Each record has a **12-byte header**, followed by its payload:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Local hardware END timestamp in microseconds |
| 4 | 2 | Low 16 bits of RADIO END sequence |
| 6 | 2 | END minus ADDRESS microseconds, modulo 2^16 |
| 8 | 1 | Kind in high nibble, pipe in bits 0-2, bit 3 reserved zero |
| 9 | 1 | Copied payload length, 0-72 |
| 10 | 1 | Signed RSSI |
| 11 | 1 | Flags: CRC_OK=1, LOCKED=2, B_ANCHOR=4, BAD_LENGTH=8 |
| 12 | length | Payload |
| after payload | 0 or 1 | Original RADIO length, only when BAD_LENGTH is set |

Packet kinds remain 1=packet, 2=status, 3=config, 4=STOP. Configuration payload
is channel plus six receiver ID bytes. Status and STOP payloads are three
uint32 values: total END count, cumulative ring drops, maximum rearm delay in
microseconds. This preserves overflow after the last delivered packet and
removes ambiguity across a long sequence gap. The host extends packet seq16,
checks chunk sequence and CRC, and compares the full STOP count with delivered
packets. Corruption, missing chunks, sequence gaps, missing config/footer and
truncation prevent complete-capture negative evidence. Positive observations
remain usable. There is no per-record CRC.

Firmware retains its existing B acceptance gate and sends its LOCKED and
B_ANCHOR decisions. The host derives session, network ticks, full frame,
phase, slot and ADDRESS timestamp from each accepted B payload and the local
captures. Projection uses signed modulo-2^32 microsecond deltas and floor
conversion to 32768 Hz ticks. Origin, variable 273/274-tick frames and the
11-tick B airtime convention match the C implementation. No network fields
are sent per packet. The internal 56-byte C metadata structure remains for
the ISR ring and reference clock tests, but is no longer the wire header.
RSN1 v1 files still decode, and the joiner and patch entry point use the same
JSON fields for both formats.

### Buffering and measurements

The vendor implementation queues up to four independent 1024-byte UDC IN
buffers. It retains a chunk if allocation/enqueue cannot proceed, and never
pops a record without room for the maximum encoded record. RADIO and USB
completion signal a semaphore; the fixed 1 ms polling sleep is removed.
Chunks normally flush above 512 bytes, with a 2 ms idle timeout for partial
chunks. Full-speed endpoint transactions are still 64 bytes. A short transfer
or ZLP terminates partial chunks so the host does not lose partial data on a
read timeout. Host reads are 1024 bytes. Smaller configuration/footer transfers
are expected. The radio ring remains 512 records; RAM is about 91 KiB.

All measurement captures used channel 88 and receiver ID e528cf1a7bc3, with
no receiver/tracker commands or fleet firmware changes by this task. These
are observed traffic rates, not a synthetic USB capacity benchmark. Traffic
and RF errors vary between runs. The historical 8402/60 s and 39512/180 s ring
drops were not reproduced by the unchanged image in today's baseline.

| Step | Duration | Stream bytes/s | Ring drops | Max rearm |
| --- | --- | --- | --- | --- |
| Original RSN1, CDC | 120 s | 110832 | 0 | 53 us |
| RSN3 compact chunks, original CDC/polling | 30 s | 57120 | 0 | 50 us |
| RSN3 vendor bulk, with 1 ms polling delay | 30 s | 49012 | 0 | 47 us |
| RSN3 vendor bulk, semaphore draining, preliminary | 30 s | 49404 | 0 | 47 us |

Every listed capture has a clean STOP and no stream errors. The final committed
image's 120-second acceptance result, commit SHA and artifact hashes are in
`out/relay-debug-20261102/sniffer/README.md` and `throughput/measurements.json`
in the main workspace. Raw captures, JSONL, per-stage build/flash logs, native
sanitizer/host tests, passivity results and the final image are retained there.
Tests compare C-generated legacy and compact packet metadata, including local
and network clock wrap, and check byte fragmentation, chunk CRC/count/gaps,
seq16 wrap, final-only overflow, FIFO overflow and both joiner entry points.



This is a separate CDC-only application in the receiver repository. Build this
directory, not the repository root. It includes the receiver's existing board,
boot partitions and `src/connection/relay_protocol.h` directly. It links none of
the receiver's application sources. No fleet checkout needs to change.

The implementation is host-tested and builds for HolyIOT-21017 nRF52840. The
new dongle was unavailable during implementation. No serial console, SWD, DFU,
flashing or RF experiment was performed. USB throughput, antenna/FEM reception
and timing accuracy still need the arrival checks below.

## Radio and passivity

The application uses plain RADIO RX. There is no ESB instance or auto-ACK
engine, including on pipe 0. Pairing, PING, coordinator B, HID, settings,
channel scanning and channel migration are absent. The host's `start` and
`stop` commands only enable or disable reception. The application has no DFU
command or 1200-baud DFU touch.

`radio.c` clears inherited PPI enables and resets RADIO on startup. Its only
RADIO task writes are RXEN, START, DISABLE and RSSISTOP. Its only shortcuts
are READY->START and ADDRESS->RSSISTART. PPI channels 0 and 1 connect ADDRESS
and END exclusively to TIMER2 captures. TIMER2 runs from the crystal HF clock
at 1 MHz with a 32-bit counter. The application owns these peripherals. ESB,
MPSL, Bluetooth and nrfx PPI allocation are disabled. The HolyIOT FEM CTX/PA
pin P0.24 is held low; CRX P0.22 stays high for reception.

Run `scripts/check_sniffer_passive.py BUILD` after building. It checks task
writes, shortcuts, PPI endpoints, PA configuration, the actual `.config`, and
the linked map. Host tests also inject TX and ESB paths and require rejection.
This is source/configuration/link evidence, not a spectrum measurement.

The on-air configuration matches the workspace SDK ESB implementation. RADIO
END, CRCERROR and RXIDLE behavior follows the
[Nordic nRF52840 RADIO specification](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/radio.html).

| Setting | Value |
| --- | --- |
| Mode | Nordic proprietary 2 Mbps, fast RX ramp |
| Preamble/address | 16-bit preamble, five-byte address |
| DPL PCF | Eight-bit length, three S1 bits, two RAM header bytes |
| Byte order/whitening | Big endian on air, whitening off |
| Hardware CRC | CRC16, initial 0xffff, polynomial 0x11021, address included |
| Payload bound | 72 bytes |
| Listening | All eight logical pipes simultaneously |

Pipe 0 uses receiver discovery base `62 39 8a f2`, prefix `fe`. Pipes 1-7 use
the paired base and prefixes derived by `esb_set_addr_unified()`. Given the
receiver's six FICR DEVICEADDR bytes in RAM order, base byte i is byte i plus
byte 4, and prefix i is byte 5 plus i. Each addition wraps at eight bits.
Values 00/55/aa gain eight, with the same wrapping. The application applies
the SDK's base/address bit reversal. Direct traffic and helper repairs use
pipe `1 + id % 7`; B uses paired pipe 1. PING/PONG and maintenance traffic
matching these addresses is retained too, as `air_packet` when not decoded.

The firmware default in the fleet is channel 84, but saved NVS overrides it.
The archived final fleet logs show channel **88**, receiver address
**C37B1ACF28E5**. See `round10/proof-final-restored-smol3.txt`, lines 31-32.
The matching host argument is `--receiver-id-le e528cf1a7bc3 --channel 88`.
These are archived settings, not a fresh fleet query. USB serial derives from
FICR DEVICEID and must not be used to derive the network address.

Relay v3 slots do not hop channels. Manual channel changes and the receiver's
optional runtime channel-avoidance process can migrate the fleet. This
sniffer stays on the supplied channel. Stop and restart a new capture with
the new channel if the fleet migrates. It does not sweep channels and miss
slots while searching. A different paired fleet needs its own receiver ID.

## Time and records

Each RADIO END produces a record, including failed hardware CRCs and repeated
ESB PIDs. No deduplication occurs. The ISR copies the completed DMA payload
while RADIO is in RXIDLE, issues START without ramp-up, then enqueues the
record. Decode, B clock updates, stream CRC and USB work happen in the main
thread. ADDRESS and END are hardware captures, not ISR-entry timestamps.
`rearm_max_us` reports the largest END-to-START service delay, conservatively
including the following TIMER capture read.

A valid B on paired pipe 1 establishes network time. As in the tracker,
the B END is assigned `preamble_ticks + RELAY_V3_CONTROL_AIR_TICKS`, eleven
32768 Hz ticks after the advertised preamble. Subsequent Bs must advance the
frame and agree within four ticks. A new session bootstraps again. No PING is
needed for the initial passive lock. One second without an accepted B expires
the lock. Bad hardware CRC, bad lengths, invalid protocol CRC and replayed Bs
cannot update it. The protocol's `relay_frame_start` and `relay_frame_at_tick`
convert the projected tick to full frame and phase. The 273/274-tick cadence
is preserved; this is not a fixed 272-tick frame approximation.

Both ADDRESS and END have network tick, full frame, phase and slot fields.
Slots 0-10 are D0-D10, 11 is B, 12-16 are R0-R4, and 17 is the frame tail.
`phase` is ticks from frame start; `phase % 16` is the slot tick offset, also
provided as `tick_offset` and `address_tick_offset` in JSON.
The host provides names. Before lock or after timeout, network fields are
null in JSON. Hardware microseconds remain available. Tick conversion has
roughly one-tick quantization and the same rounded B airtime convention as
the tracker; it is not a sub-microsecond clock calibration. Local TIMER wrap,
receiver tick wrap and 16-bit repair-frame wrap have host coverage. Keep a
single capture below the receiver tick horizon, about 36 hours, and restart
for receiver resets or network changes.

The binary ABI is little endian RSN1 v1, with a packed 56-byte header,
0-72 payload bytes, and a four-byte IEEE CRC32 over header plus payload.
`sniffer/core.h` and Python `HEADER` define the exact field order. The header
contains record kind, END sequence, cumulative ring drops, both local captures,
network session, both network frames/ticks/phases/slots, pipe, copied length,
flags, original RADIO length byte and signed RSSI. Bad oversized lengths are
capped for DMA copying, while `radio_length` retains the received length byte.
The payload and its claimed length are untrusted when CRC fails.

Packet kinds are 1=packet, 2=status, 3=start configuration, 4=stop footer.
Status/footer payloads contain the cumulative maximum rearm delay. Config
contains channel followed by six receiver identity bytes. The host commands
are ASCII `start CHANNEL ID_LE_HEX\n` and `stop\n`. DTR removal stops RX.
The firmware does not receive until an explicit valid start command.

The host emits these JSONL events:

- `air_source`: type, source ID and inferred full `pose_frame`. Ordinary pose
  payloads do not encode a full network frame. It comes from the B-locked
  ADDRESS slot. A separate flag confirms the ID/pipe/direct-slot match.
- `air_B`: advertised frame/session, members, expected mask, all three missing
  masks, five grants, helper assignments, watch generation and control flags.
- `air_repair`: helper/session, overflow flag and each child's capture frame,
  full reconstructed frame, age, embedded length/type and helper capture RSSI.
- `air_crc_fail`: raw bytes and hardware metadata. A `candidate_child` can be
  inferred from the B member list, physical direct slot and matched pipe.
  The corrupted payload's source ID is never trusted.
- `air_packet`, `air_invalid`, configuration, status, stop and explicit stream
  errors retain other traffic and malformed or incomplete evidence.

RSSI is the negative SoC input reading. It includes the FEM receive gain and
is not calibrated antenna-port RSSI. Repair-record RSSI belongs to the helper;
the packet header RSSI belongs to the sniffer.

## Capacity and gaps

The ISR ring contains 512 128-byte entries, 64 KiB. Main and CDC transmit
queues add 8 KiB each. The actual linked RAM usage is 104824 bytes, 102.4 KiB. Every
END advances `seq`, even when the ring is full; `dropped` advances on each
failed insertion. Periodic status and the drained stop footer report the final
count, even if the final packets overflow. Whole records wait for USB space,
and partial CDC FIFO writes retain their unsent tail. Stream CRC32, sequence
gaps, missing config/footer and truncation are visible to the host.

At 120 frames/s and 17 occupied slots, the scheduled peak is 2040 packets/s.
A maximum-sized record occupies 132 bytes, giving **269280 bytes/s** for an
all-72-byte bound. With 17-byte direct poses, 72-byte B and maximum repairs,
the bound is **196680 bytes/s**. USB full-speed bulk's ideal 19 x 64 bytes/ms
is 1216000 bytes/s. The worst record bound uses 22.1% of that capacity; six
64-byte transactions/ms would already exceed the bound. Actual controller,
host scheduling and hub headroom remain unmeasured until the dongle arrives.
The raw ring alone buffers about 251 ms at 2040 packets/s. A measured host
decode benchmark is recorded in `build-host-tests.log`, roughly 42000 records/s
on this Mac. It does not measure USB delivery or ISR timing.

Nominal minimum scheduled interpacket space is about 159 us after a 72-byte
packet. The joiner declines negative evidence if maximum rearm service reaches
100 us. This is conservative coverage gating, not proof against RF collisions
or transmitter timing deviations. Address corruption, undetectable preambles,
collisions and arrivals inside the RX restart gap cannot create END records.
The overflow counter counts firmware buffering loss, not every unseen RF packet.

## Build and host checks

Use the existing workspace environment. No dependency install is needed.

```sh
source /Users/johnny/nrf54-fork/env.sh
cd /Users/johnny/nrf54-fork
west build -b holyiot_21017 -s sniffer/sniffer \
  -d build/relay-sniffer --no-sysbuild
cd sniffer
python -m unittest discover -s tests/sniffer -v
python scripts/check_sniffer_passive.py ../build/relay-sniffer
python /Users/johnny/nrf54/scripts/package-receiver.py \
  ../build/relay-sniffer/zephyr/zephyr.hex \
  ../build/relay-sniffer/relay-sniffer.zip 0xda000
```

The packager asserts all HEX segments fit the application partition, beginning
at 0x1000 and ending below 0xda000. The image does not overwrite MBR, storage,
bootloader or UICR. It uses the same existing Nordic open-DFU packaging helper
as the receiver. ELF, HEX, BIN, ZIP, config, map, hashes and logs are copied to
`/Users/johnny/nrf54/out/relay-debug-20261102/sniffer/`. The build directory is
`/Users/johnny/nrf54-fork/build/relay-sniffer`.

Nine Python tests plus the native C assertions cover synthetic packets built
with the unchanged shared protocol encoders, all slots and variable frame
lengths, B lock/replay/innovation/CRC/timeout, session change, wrap, FIFO order
and explicit overflow, byte-fragmented/corrupt/truncated streams, refusal to
open a fleet port, injected TX-path rejection and both joiner entry points.
The C fixture runs with address and undefined-behavior sanitizers.

## Identify and flash the new dongle after arrival

Do not select a device by enumeration order or a reused `/dev/cu.*` suffix.
The existing receiver was archived at application port `/dev/cu.usbmodem21101`,
VID:PID **1209:7690**. Its Nordic bootloader serial is **C37B1ACF28E5** and its
bootloader port was `/dev/cu.usbmodemC37B1ACF28E51`. Those are exclusion values,
not targets. Ports can change. Never run the archived `receiver-image.py`
for this sniffer; it explicitly targets that existing receiver.

1. Before plugging in the new dongle, save a USB metadata inventory with
   `python scripts/relay_sniffer.py ports`. This enumerates without opening
   consoles. Plug only the new dongle into a known USB socket, repeat, and
   label the added device physically. It may initially expose factory firmware.
2. Use the new dongle's physical reset/DFU button to enter its nRF5/OpenDFU
   bootloader. Inventory again with `nrfutil device list --json` and USB metadata.
   Record its exact bootloader serial and location. Verify it differs from
   C37B1ACF28E5 and belongs to the newly inserted socket. A stock UF2/MCUboot or
   different bootloader needs its own installation path; do not erase blindly.
3. Only with that concrete new identity, program the prepared ZIP:

   ```sh
   nrfutil device program --serial-number NEW_BOOTLOADER_SERIAL \
     --traits nordicDfu --firmware \
     /Users/johnny/nrf54/out/relay-debug-20261102/sniffer/relay-sniffer.zip --json
   ```

4. The application should enumerate as product **Passive relay sniffer**,
   VID:PID **1209:7691**, with a unique 16-hex FICR DEVICEID-based USB serial.
   This is a local experimental PID, not a public USB allocation. Save the new
   application port, serial and USB location. Bootloader and application
   serials need not match. The capture tool requires the exact application
   port AND serial AND VID:PID before opening anything.

Reflashing later also uses the new dongle's physical DFU entry. The sniffer
does not implement the receiver console's `dfu` command.

## Capture and forced-drop procedure

First place the sniffer on a USB extension near the receiver, away from the
host's USB noise. Capture an unblocked baseline. Replace both placeholders
below with the newly inventoried sniffer identity:

```sh
source /Users/johnny/nrf54-fork/env.sh
cd /Users/johnny/nrf54-fork/sniffer
python scripts/relay_sniffer.py capture \
  --port /dev/cu.NEW_SNIFFER --serial NEW_APPLICATION_USB_SERIAL \
  --receiver-id-le e528cf1a7bc3 --channel 88 --seconds 60 \
  --raw /tmp/sniffer-baseline.rsn --jsonl /tmp/sniffer-baseline.jsonl
```

Raw and JSONL paths must be new. The tool records a config response, streams
until the requested time or Ctrl-C, requests STOP, and waits up to ten seconds
for a drained footer. An absent footer is an explicit incomplete-capture error.
Start long enough before the ledger interval to lock B and bracket its bounds.
Check B session/frame advance, direct IDs 0-10, RSSI, CRC failures, rearm maximum,
zero cumulative drops, and contiguous packet sequences. A quiet unblocked run
need not have repairs; every empty repair slot is not a missing transmission.

For the later controlled test, use the established fleet controller in a
separate operator session. This capture tool cannot send receiver commands.

1. Confirm v3 is active and record the fleet's current network address/channel.
   Arm core ledgers for the chosen child on source, receiver and helpers, with
   complete bounds. Include T0/T1 if collecting their helper evidence.
2. Start a sniffer capture extending before and after the planned ledger window.
   Use a fresh output name. The baseline command above with `--seconds 60` is
   long enough for a short controlled run if the operator starts promptly.
3. On the already identified receiver console, issue `relay block 3 100`, or
   the chosen child instead of 3. Retain B and R0-R4 traffic and the ledgers.
4. **Always issue `relay block 3 0` in the controller's `finally` cleanup**, using
   the same child ID, including on interruption or capture error. Confirm the
   receiver reports no active block. Do not leave the block until log processing.
5. Stop/dump bounded ledgers and let the sniffer drain its footer. Join:

   ```sh
   python scripts/relay_sniffer.py join 3 SOURCE.txt RECEIVER.txt HELPERS.txt \
     --joiner /Users/johnny/nrf54-fork/tracker/scripts/relay_ledger_join.py \
     --air /tmp/sniffer-block3.jsonl -o /tmp/sniffer-block3-joined.json
   ```

The wrapper imports the current joiner read-only and preserves its denominator,
delivery bins, refusal reasons and loss attribution. It adds `air_events`,
`air_source` and `air_capture_complete` per row. `yes` is a valid source pose in
the matching physical slot and pipe. `CRC-bad` is an address/slot/pipe candidate
with failed CRC, never a trusted corrupted ID. `no` means not observed at this
antenna, only when the stream has one config/footer, no drops/errors/gaps,
adequate rearm service and accepted Bs in the previous/current/next frame.
Otherwise absence is `unknown`. Positive evidence survives partial captures.
A repair carries evidence of its helper's transmitted copy; it does not turn
`air_source` into `yes` for an unobserved original.

For replay, `python scripts/relay_sniffer.py decode CAPTURE.rsn -o CAPTURE.jsonl`
requires no device. The optional `patches/tracker-relay-ledger-air.patch` adds
`--air CAPTURE.jsonl --air-tool /path/to/relay_sniffer.py` to the tracker CLI.
It is committed as a patch only. The tracker checkout was not modified.

Repeat a run near the source and compare positive observations with a run near
the receiver. One antenna location is neither the receiver's view nor any
helper's view. A decoded packet proves it was on air and reached this sniffer;
its absence, including a CRC candidate, cannot prove every helper lost it or
that the source never transmitted. Separate sniffer and source TX-END evidence
would be needed to settle that distinction. New captures cannot reconstruct
the twelve unknown historical frames.

## Provenance

Worktree `/Users/johnny/nrf54-fork/sniffer`, branch `relay-sniffer`, forked from
receiver `b7294b8d9ddc94cbef749a9e592b70c1c079dfa9`. SDK source is
`d6462fd580522f1f9d16aa977c8d359939abbab6`. The shared protocol header SHA256
is `114b6c207c685c045e3e9343318eb91b3e55f495fecc6d9904bec22d7eae4e3c`.
The final implementation commit SHA and exact artifact hashes are recorded in
the handoff copy of this README and `manifest.json` beside the prepared ZIP.
All commits are local. Nothing was pushed.
