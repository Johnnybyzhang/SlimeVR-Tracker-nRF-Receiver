#!/usr/bin/env python3
"""Capture/decode RSN1 and attach independent air observations to relay ledgers.

Only 'capture' opens a device. It requires an exact port AND USB serial match.
'decode' and 'join' use files. No command controls the receiver or any tracker.
"""
import argparse
import collections
import importlib.util
import json
import pathlib
import struct
import sys
import time
import zlib

HEADER = struct.Struct('<4sHBB9IHH6BbB')
assert HEADER.size == 56
UNKNOWN = 0xffffffff


def crc8(data):
    value = 7
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = ((value << 1) ^ (7 if value & 128 else 0)) & 255
    return value


def slot_name(slot):
    if slot < 11:
        return f'D{slot}'
    return 'B' if slot == 11 else f'R{slot - 12}' if slot < 17 else 'tail' if slot == 17 else None


def pose(data):
    return len(data) >= 2 and data[1] < 16 and (
        len(data) == 17 and data[0] < 16 or len(data) >= 5 and data[0] == 0xfe)


def decode_record(raw):
    values = HEADER.unpack_from(raw)
    keys = ('magic', 'size', 'version', 'kind', 'seq', 'dropped', 'end_us', 'address_us',
            'session', 'frame', 'end_tick', 'address_tick', 'address_frame', 'phase',
            'address_phase', 'slot', 'pipe', 'length', 'flags', 'address_slot',
            'radio_length', 'rssi', 'reserved2')
    r = dict(zip(keys, values))
    data = raw[HEADER.size:-4]
    if r['version'] != 1 or r['size'] != len(raw) or r['length'] != len(data):
        raise ValueError('invalid RSN1 header')
    if zlib.crc32(raw[:-4]) != struct.unpack_from('<I', raw, len(raw) - 4)[0]:
        raise ValueError('RSN1 stream CRC32 mismatch')
    if r['kind'] not in (1, 2, 3, 4) or (r['kind'] != 1 and len(data) != (7 if r['kind'] == 3 else 4)):
        raise ValueError('invalid RSN1 record kind/length')
    for key in ('magic', 'reserved2', 'size', 'version'):
        del r[key]
    r['payload_hex'] = data.hex()
    if r['kind'] != 1:
        r['event'] = {2: 'air_status', 3: 'air_config', 4: 'air_stop'}.get(r['kind'], 'air_unknown')
        if r['kind'] == 3 and len(data) == 7:
            r.update(channel=data[0], receiver_id_le=data[1:].hex())
        elif r['kind'] in (2, 4) and len(data) == 4:
            r['rearm_max_us'] = struct.unpack('<I', data)[0]
        return r
    r.update(crc_ok=bool(r['flags'] & 1), locked=bool(r['flags'] & 2),
             b_anchor=bool(r['flags'] & 4), bad_length=bool(r['flags'] & 8),
             slot_name=slot_name(r['slot']), address_slot_name=slot_name(r['address_slot']),
             tick_offset=r['phase'] % 16 if r['flags'] & 2 else None,
             address_tick_offset=r['address_phase'] % 16 if r['flags'] & 2 else None,
             type=data[0] if data else None)
    if not r['locked']:
        for key in ('session', 'frame', 'end_tick', 'address_tick', 'address_frame', 'phase', 'address_phase'):
            r[key] = None
    r['event'] = 'air_packet'
    if not r['crc_ok']:
        # The length/PCF and payload can be corrupted too. Never trust an ID.
        r['event'] = 'air_crc_fail'
    elif r['bad_length']:
        r['event'] = 'air_invalid'
    elif len(data) == 72 and data[0] in (0xe8, 0xec) and data[1] == 4 and ((data[68] & 63) in (15, 16) if not data[3] & 128 else (data[68] & 63) >> 1 <= 16) and 0 < int.from_bytes(data[69:71], 'big') <= 32768 and crc8(data[:71]) == data[71]:
        r.update(event='air_B', epoch=data[2], repair_count=data[3] & 7,
                 next_repairs=(data[67] >> 2) & 7, next2_repairs=(data[67] >> 5) & 7,
                 direct_count=((data[3] >> 3) & 15) + 1,
                 slot_ticks=(15 if data[68] & 1 else 16) if data[3] & 128 else data[68] & 63,
                 second_b=data[68] >> 6, second_copy=data[0] == 0xec,
                 tps_max=int.from_bytes(data[69:71], 'big'), on_demand=bool(data[3] & 128),
                 packet_session=int.from_bytes(data[4:8], 'big'),
                 b_frame=int.from_bytes(data[8:12], 'big'),
                 preamble_ticks=int.from_bytes(data[12:16], 'big'),
                 members=int.from_bytes(data[16:18], 'big'),
                 expected=int.from_bytes(data[18:20], 'big'),
                 missing=[int.from_bytes(data[i:i+2], 'big') for i in (20, 22, 24)],
                 primary_valid=int.from_bytes(data[26:28], 'big'),
                 backup_valid=int.from_bytes(data[28:30], 'big'),
                 helpers=list(data[30:46]),
                 grants=[dict(slot=f'R{i}', owner=data[46+i],
                              children=int.from_bytes(data[51+2*i:53+2*i], 'big')) for i in range(5)],
                 survey=int.from_bytes(data[61:63], 'big'), maintenance_owner=((data[68] & 63) >> 1 if (data[68] & 63) >> 1 < 16 else 255) if data[3] & 128 else data[63],
                 watch_generation=0 if data[3] & 128 else int.from_bytes(data[64:66], 'big'), profile=1 if data[3] & 128 else data[66], control_flags=data[67] & 3)
        if data[3] & 128:
            r['missing'] += [int.from_bytes(data[i:i+2], 'big') for i in (63, 65)]
    elif len(data) >= 8 and data[0] == 0xe9:
        r.update(event='air_repair', helper=data[1], epoch=data[2],
                 packet_session=int.from_bytes(data[4:8], 'big'),
                 repair_overflow=bool(data[3] & 128), records=[])
        count, pos = data[3] & 3, 8
        valid = data[1] < 16 and count > 0 and not data[3] & 0x7c
        for _ in range(count):
            if pos + 4 > len(data):
                valid = False
                break
            captured, length, rssi = struct.unpack_from('>HBB', data, pos)
            source = data[pos+4:pos+4+length]
            if length > 60 or len(source) != length or not pose(source) or source[1] == data[1]:
                valid = False
                break
            age = ((r['address_frame'] - captured) & 0xffff) if r['locked'] else None
            full = r['address_frame'] - age if age is not None else None
            r['records'].append(dict(child=source[1], capture_frame16=captured, frame=full,
                                     age=age, rssi=-rssi, length=length, type=source[0], payload_hex=source.hex()))
            pos += 4 + length
        duplicates = [(v['child'], v['capture_frame16']) for v in r['records']]
        if not valid or pos != len(data) or len(set(duplicates)) != len(duplicates):
            r.update(event='air_invalid', decode_error='invalid repair envelope')
    elif pose(data):
        # Ordinary poses contain sequence data, not a full network frame.
        r.update(event='air_source', source=data[1], pose_frame=r['address_frame'])
    return r


class LegacyStream:
    """Incremental decoder. Every discarded byte becomes an explicit error."""
    def __init__(self):
        self.buffer = bytearray()
        self.members = None
        self.session = None
        self.layouts = {}

    def feed(self, data):
        self.buffer.extend(data)
        out = []
        while len(self.buffer) >= 4:
            if self.buffer[:4] != b'RSN1':
                at = self.buffer.find(b'RSN1', 1)
                n = at if at >= 0 else len(self.buffer) - 3
                del self.buffer[:n]
                out.append(dict(event='air_stream_error', reason='lost framing', bytes=n))
                continue
            if len(self.buffer) < HEADER.size:
                break
            size = struct.unpack_from('<H', self.buffer, 4)[0]
            if not HEADER.size + 4 <= size <= HEADER.size + 72 + 4:
                del self.buffer[0]
                out.append(dict(event='air_stream_error', reason='invalid size'))
                continue
            if len(self.buffer) < size:
                break
            raw = bytes(self.buffer[:size])
            try:
                r = decode_record(raw)
            except ValueError as exc:
                del self.buffer[0]
                out.append(dict(event='air_stream_error', reason=str(exc)))
                continue
            del self.buffer[:size]
            if r['event'] == 'air_config':
                self.members = self.session = None
                self.layouts.clear()
            if r.get('b_anchor'):
                self.members, self.session = r['members'], r['session']
                for i, repairs in enumerate((r['repair_count'], r['next_repairs'], r['next2_repairs'])):
                    self.layouts[r['session'], (r['b_frame'] + i) & UNKNOWN] = r['direct_count'], r['slot_ticks'], repairs, r['second_b']
            same = r.get('locked') and r.get('session') == self.session and self.members is not None
            members = [i for i in range(16) if self.members & (1 << i)] if same else []
            slot = r.get('address_slot', 255)
            candidate = members[slot] if slot < len(members) else None
            if r['event'] == 'air_source':
                r['matches_direct_slot'] = candidate == r['source'] and r['pipe'] == 1 + r['source'] % 7
            if r['event'] == 'air_crc_fail' and candidate is not None and r['pipe'] == 1 + candidate % 7:
                r['candidate_child'] = candidate
            if same:
                for fk, sk, pk, nk, ok in (('frame', 'slot', 'phase', 'slot_name', 'tick_offset'),
                                            ('address_frame', 'address_slot', 'address_phase', 'address_slot_name', 'address_tick_offset')):
                    geometry = self.layouts.get((r['session'], r[fk]))
                    if geometry:
                        n, width, repairs, second = geometry
                        slot = r[sk]
                        r[nk] = f'D{slot}' if slot < n else 'B' if slot == n else 'guard' if second == 1 and slot == n + 1 else 'B2' if second == 1 and slot == n + 2 or second == 2 and slot == n + repairs + 1 else f'R{slot-n-1-2*(second==1)}' if slot <= n + repairs + 2*(second==1) else 'tail'
                        r[ok] = r[pk] % width
            out.append(r)
        return out

    def finish(self):
        return [dict(event='air_stream_error', reason='truncated record', bytes=len(self.buffer))] if self.buffer else []


class Stream:
    """RSN3 chunk CRC and sequence checks, with RSN1 replay compatibility."""
    def __init__(self):
        self.buffer = bytearray()
        self.legacy = LegacyStream()
        self.mode = None
        self.chunk_seq = None
        self.seq = 0
        self.dropped = self.missing = 0
        self.anchor = None
        self.timeline = {}

    def record(self, raw):
        end, seq16, delta, kp, length, rssi, flags = struct.unpack_from('<IHHBBbB', raw)
        kind, pipe = kp >> 4, kp & 7
        data = raw[12:12 + length]
        if kind == 3:
            self.seq = self.dropped = self.missing = 0
            self.anchor = None
        seq = self.seq + ((seq16 - self.seq) & 65535)
        if kind == 1:
            self.missing += max(0, seq - self.seq - 1)
            self.dropped = max(self.dropped, self.missing)
            self.seq = seq
        if kind in (2, 4):
            if len(data) != 12:
                raise ValueError('invalid RSN3 summary')
            seq, reported_drops, rearm = struct.unpack('<III', data)
            self.dropped = max(self.dropped, reported_drops)
            data = struct.pack('<I', rearm)
        fields = dict(session=UNKNOWN, frame=UNKNOWN, end_tick=UNKNOWN,
                      address_tick=UNKNOWN, address_frame=UNKNOWN, phase=65535,
                      address_phase=65535, slot=255, address_slot=255)
        address = (end - delta) & UNKNOWN if kind == 1 else 0
        if kind == 1:
            if flags & 4:
                if not (flags & 3 == 3 and pipe == 1 and len(data) == 72
                        and data[0] in (0xe8, 0xec) and data[1] == 4 and crc8(data[:71]) == data[71]):
                    raise ValueError('invalid RSN3 B anchor')
                session, frame, preamble = struct.unpack_from('>III', data, 4)
                direct, width, cap = ((data[3] >> 3) & 15) + 1, data[68], int.from_bytes(data[69:71], 'big')
                width &= 63
                second = data[68] >> 6
                if data[3] & 128:
                    width = 15 if width & 1 else 16
                if width not in (15, 16) or not 0 < cap <= 32768 or second > 2 or (data[0] == 0xec and not second):
                    raise ValueError('invalid runtime geometry')
                if self.anchor is None or session != self.anchor[0] or data[2] != self.anchor[4]:
                    self.timeline.clear()
                copy_offset = (2 * width if second == 1 else ((data[3] & 7) + 1) * width) if data[0] == 0xec else 0
                start = (preamble - copy_offset - direct * width - 2) & UNKNOWN
                for i, repairs in enumerate((data[3] & 7, (data[67] >> 2) & 7, (data[67] >> 5) & 7)):
                    f = (frame + i) & UNKNOWN
                    period = max((direct + 1 + repairs + (2 if second == 1 else bool(second))) * width, (f + 1) * 32768 // cap - f * 32768 // cap)
                    self.timeline[f] = start, (start + period) & UNKNOWN
                    start = (start + period) & UNKNOWN
                self.timeline[(frame + 3) & UNKNOWN] = start, (start + direct * width) & UNKNOWN
                self.timeline = {f: v for f, v in self.timeline.items() if (frame + 3 - f) & UNKNOWN < 16}
                self.anchor = session, end, (preamble + 11) & UNKNOWN, width, data[2]
            if flags & 2:
                if self.anchor is None:
                    raise ValueError('locked record without B anchor')
                session, local, tick, width, epoch = self.anchor
                fields['session'] = session
                for us, tk, fk, pk, sk in ((end, 'end_tick', 'frame', 'phase', 'slot'),
                                          (address, 'address_tick', 'address_frame', 'address_phase', 'address_slot')):
                    signed = ((us - local + 0x80000000) & UNKNOWN) - 0x80000000
                    net = (tick + signed * 32768 // 1000000) & UNKNOWN
                    match = next(((f, start) for f, (start, stop) in reversed(self.timeline.items())
                                  if (net - start) & UNKNOWN < (stop - start) & UNKNOWN), None)
                    if match is None:
                        raise ValueError('locked record outside announced horizon')
                    f, start = match
                    phase = (net - start) & UNKNOWN
                    fields.update({tk: net, fk: f, pk: phase, sk: phase // width})
        else:
            fields = dict.fromkeys(fields, 0)
        radio_length = (raw[-1] if flags & 8 else length) if kind == 1 else 0
        header = HEADER.pack(b'RSN1', HEADER.size + len(data) + 4, 1, kind,
                             seq, self.dropped, end, address,
                             *(fields[k] for k in ('session', 'frame', 'end_tick', 'address_tick', 'address_frame',
                                                  'phase', 'address_phase', 'slot')),
                             pipe, len(data), flags, fields['address_slot'], radio_length, rssi, 0)
        packet = header + data
        return packet + struct.pack('<I', zlib.crc32(packet))

    @staticmethod
    def frame_start(frame):
        return frame // 15 * 4096 + (frame % 15) * 4096 // 15

    def feed(self, data):
        if self.mode == 1:
            return self.legacy.feed(data)
        self.buffer.extend(data)
        if self.mode is None and len(self.buffer) >= 4 and self.buffer[:4] == b'RSN1':
            self.mode = 1
            data, self.buffer = self.buffer, bytearray()
            return self.legacy.feed(data)
        out = []
        while len(self.buffer) >= 12:
            if self.buffer[:4] != b'RSN3':
                del self.buffer[0]
                out.append(dict(event='air_stream_error', reason='lost chunk framing'))
                continue
            size, count, seq = struct.unpack_from('<HHI', self.buffer, 4)
            if not 16 <= size <= 1024:
                del self.buffer[0]
                out.append(dict(event='air_stream_error', reason='invalid chunk size'))
                continue
            if len(self.buffer) < size:
                break
            chunk = bytes(self.buffer[:size])
            del self.buffer[:size]
            if zlib.crc32(chunk[:-4]) != struct.unpack_from('<I', chunk, size - 4)[0]:
                self.anchor = None
                out.append(dict(event='air_stream_error', reason='chunk CRC32 mismatch'))
                continue
            if self.chunk_seq is not None and seq != (self.chunk_seq + 1) & UNKNOWN:
                out.append(dict(event='air_stream_error', reason='chunk sequence gap'))
                self.anchor = None
            self.chunk_seq = seq
            try:
                records, pos = [], 12
                for _ in range(count):
                    if pos + 12 > size - 4:
                        raise ValueError('truncated chunk record')
                    n = 12 + chunk[pos + 9] + bool(chunk[pos + 11] & 8)
                    if n > 85 or pos + n > size - 4:
                        raise ValueError('invalid chunk record length')
                    records.append(chunk[pos:pos + n])
                    pos += n
                if pos != size - 4:
                    raise ValueError('chunk record count mismatch')
                for raw in records:
                    out.extend(self.legacy.feed(self.record(raw)))
            except (ValueError, struct.error) as exc:
                self.anchor = None
                out.append(dict(event='air_stream_error', reason=str(exc)))
        return out

    def finish(self):
        if self.mode == 1:
            return self.legacy.finish()
        return [dict(event='air_stream_error', reason='truncated record', bytes=len(self.buffer))] if self.buffer else []


def decode_file(path):
    decoder = Stream()
    with path.open('rb') as src:
        while chunk := src.read(65536):
            yield from decoder.feed(chunk)
    yield from decoder.finish()


def attach_air(joined, events):
    """Preserve original joiner's loss bins/attribution, add independent evidence.

    'no' means this sniffer did not observe the source. It never proves no TX.
    CRC-bad is a slot/pipe candidate, never a decoded corrupted source ID.
    """
    events = list(events)
    configs = [e for e in events if e['event'] == 'air_config']
    stops = [e for e in events if e['event'] == 'air_stop']
    packets = [e for e in events if e.get('kind') == 1]
    errors = [e for e in events if e['event'] == 'air_stream_error']
    expected_seq = list(range(1, len(packets) + 1))
    complete = (len(configs) == len(stops) == 1 and not errors and bool(packets) and
                all(e.get('dropped', 0) == 0 for e in events) and
                [e['seq'] for e in packets] == expected_seq and
                stops[0]['seq'] == len(packets))
    rearm_max = max((e.get('rearm_max_us', 0) for e in events), default=0)
    # 100 us is below the scheduled interpacket gap for v3 payload caps.
    complete = complete and rearm_max < 100
    indexed = collections.defaultdict(list)
    anchors = collections.defaultdict(list)
    child = joined['child']
    for e in packets:
        if not e.get('locked'):
            continue
        session = e['session']
        if e['event'] == 'air_B' and e['b_anchor']:
            anchors[session].append(e['b_frame'])
        frame = e.get('pose_frame') if e['event'] == 'air_source' else e['address_frame']
        if (e['event'] == 'air_source' and e['source'] == child or
            e['event'] == 'air_crc_fail' and e.get('candidate_child') == child or e['event'] == 'air_B'):
            indexed[session, frame].append(e)
        if e['event'] == 'air_repair' and e['packet_session'] == session:
            for record in e['records']:
                if record['child'] == child and record['age'] is not None and record['age'] < 3:
                    indexed[session, record['frame']].append(e)
    counts = collections.Counter()
    for row in joined['rows']:
        s, f = row['session'], row['frame']
        air = indexed[s, f]
        good = any(e['event'] == 'air_source' and e['matches_direct_slot'] for e in air)
        bad = any(e['event'] == 'air_crc_fail' for e in air)
        # Need anchors bracketing the whole frame; no extrapolated absence
        # claim through B outages, unlocks, resets, overflow or a short file.
        b = anchors[s]
        covered = complete and f - 1 in b and f in b and f + 1 in b
        state = 'yes' if good else 'CRC-bad' if bad else 'no' if covered else 'unknown'
        row['air_source'] = state
        row['air_capture_complete'] = bool(covered)
        row['air_events'] = air
        counts[state] += 1
    joined['sniffer'] = dict(complete=bool(complete), stream_errors=len(errors),
                             dropped=max((e.get('dropped', 0) for e in events), default=0),
                             rearm_max_us=rearm_max, source=dict(counts),
                             meaning='no = not observed here; CRC-bad = slot/pipe candidate; neither proves absence of TX')
    return joined


def load_joiner(path):
    spec = importlib.util.spec_from_file_location('existing_relay_ledger_join', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BulkPort:
    """Vendor interface 0: bulk IN stream and device vendor request 0x53."""
    def __init__(self, serial_number):
        if serial_number != 'ED3CC490E336F17A':
            raise ValueError('only the identified sniffer serial is authorized; no device opened')
        import usb.core
        import usb.util
        import usb.backend.libusb1
        self.usb = usb
        backend = usb.backend.libusb1.get_backend()
        if backend is None and sys.platform == 'darwin':
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda _: '/opt/homebrew/opt/libusb/lib/libusb-1.0.dylib')
        if backend is None:
            raise ValueError('libusb not found; install libusb and pyusb')
        devices = usb.core.find(find_all=True, idVendor=0x1209, idProduct=0x7691, backend=backend)
        matches = [d for d in devices if d.serial_number == serial_number]
        if len(matches) != 1:
            raise ValueError('exact VID:PID 1209:7691 and sniffer serial required; no interface opened')
        self.device = matches[0]
        cfg = self.device.get_active_configuration()
        iface = cfg[(0, 0)]
        if iface.bInterfaceClass != 255 or iface.bNumEndpoints != 1:
            raise ValueError('sniffer vendor bulk interface required')
        self.endpoint = next(e.bEndpointAddress for e in iface if e.bEndpointAddress & 128)
        usb.util.claim_interface(self.device, 0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.usb.util.dispose_resources(self.device)

    def write(self, data):
        return self.device.ctrl_transfer(0x40, 0x53, 0, 0, data, timeout=2000)

    def read(self, size):
        try:
            return bytes(self.device.read(self.endpoint, 1024, timeout=100))
        except self.usb.core.USBTimeoutError:
            return b''


def capture(args):
    import serial
    from serial.tools import list_ports
    matches = [p for p in list_ports.comports() if p.device == args.port and
               p.vid == 0x1209 and p.pid == 0x7691 and p.serial_number == args.serial]
    if args.port and len(matches) != 1:
        raise ValueError('exact port/serial/VID:PID 1209:7691 match required; no device opened')
    receiver = bytes.fromhex(args.receiver_id_le)
    if len(receiver) != 6 or not 0 <= args.channel <= 100:
        raise ValueError('need six receiver identity bytes in RAM order and channel 0..100')
    decoder, stopped, started = Stream(), False, False
    with (serial.Serial(args.port, 115200, timeout=0.1, write_timeout=2, exclusive=True)
          if args.port else BulkPort(args.serial)) as port, \
            args.raw.open('xb') as raw, args.jsonl.open('x') as dst:
        def consume(chunk):
            nonlocal stopped, started
            raw.write(chunk)
            for event in decoder.feed(chunk):
                dst.write(json.dumps(event, separators=(',', ':')) + '\n')
                started |= event['event'] == 'air_config'
                stopped |= event['event'] == 'air_stop' and started
        # DTR is already asserted. Reject an old undrained capture instead of
        # mixing it with this one. Boot firmware itself has no auto-start.
        port.write(f'start {args.channel} {receiver.hex()}\n'.encode())
        deadline = time.monotonic() + args.seconds
        try:
            start_deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                consume(port.read(8192))
                if not started and time.monotonic() > start_deadline:
                    raise ValueError('no config response; close an earlier capture and reconnect the sniffer')
        except KeyboardInterrupt:
            pass
        finally:
            port.write(b'stop\n')
            end = time.monotonic() + 10
            while not stopped and time.monotonic() < end:
                consume(port.read(8192))
            for event in decoder.finish():
                dst.write(json.dumps(event) + '\n')
        if not stopped:
            raise ValueError('missing stop footer: capture incomplete; raw evidence retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    subs.add_parser('ports', help='enumerate USB metadata without opening ports')
    cap = subs.add_parser('capture')
    cap.add_argument('--port', help='legacy CDC port; omit for vendor bulk')
    for name in ('serial', 'receiver-id-le'):
        cap.add_argument('--' + name, required=True)
    cap.add_argument('--channel', type=int, required=True)
    cap.add_argument('--seconds', type=float, default=60)
    cap.add_argument('--raw', type=pathlib.Path, required=True)
    cap.add_argument('--jsonl', type=pathlib.Path, required=True)
    dfu = subs.add_parser('dfu', help='enter sniffer bootloader via vendor interface')
    dfu.add_argument('--serial', required=True)
    dec = subs.add_parser('decode')
    dec.add_argument('raw', type=pathlib.Path)
    dec.add_argument('-o', type=pathlib.Path, required=True)
    join = subs.add_parser('join')
    join.add_argument('child', type=int)
    join.add_argument('ledgers', nargs='+', type=pathlib.Path)
    join.add_argument('--joiner', type=pathlib.Path, required=True)
    join.add_argument('--air', type=pathlib.Path, required=True)
    join.add_argument('-o', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.command == 'ports':
        from serial.tools import list_ports
        for p in list_ports.comports():
            print(json.dumps(dict(port=p.device, vid=p.vid, pid=p.pid, serial=p.serial_number,
                                  product=p.product, location=p.location)))
        try:
            with BulkPort('ED3CC490E336F17A') as bulk:
                print(json.dumps(dict(vid=0x1209, pid=0x7691, serial=bulk.device.serial_number,
                                      product=bulk.device.product, interface='vendor bulk',
                                      endpoint=bulk.endpoint)))
        except ValueError:
            pass
    elif args.command == 'dfu':
        with BulkPort(args.serial) as port:
            port.write(b'dfu\n')
    elif args.command == 'capture':
        if args.seconds <= 0:
            raise ValueError('seconds must be positive')
        capture(args)
    elif args.command == 'decode':
        with args.o.open('w') as dst:
            for event in decode_file(args.raw):
                dst.write(json.dumps(event, separators=(',', ':')) + '\n')
    else:
        result = load_joiner(args.joiner).join(args.ledgers, args.child)
        with args.air.open() as src:
            attach_air(result, (json.loads(line) for line in src if line.strip()))
        args.o.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result['sniffer'], indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(str(exc))
