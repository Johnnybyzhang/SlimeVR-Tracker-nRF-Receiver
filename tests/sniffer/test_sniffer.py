import copy
import importlib.util
import json
import pathlib
import struct
import zlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sniffer', ROOT / 'scripts/relay_sniffer.py')
sniffer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sniffer)


class SnifferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = pathlib.Path(cls.tmp.name)
        exe = cls.path / 'fixture'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I' + str(ROOT / 'sniffer'),
                        '-I' + str(ROOT / 'src/connection'), str(ROOT / 'sniffer/core.c'),
                        str(ROOT / 'tests/sniffer/fixture.c'), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        cls.legacy_raw = subprocess.check_output([str(exe), '--fixture', '--legacy'])
        cls.raw = subprocess.check_output([str(exe), '--fixture'])
        cls.events = sniffer.Stream().feed(cls.raw)
        cls.wrap_v3 = subprocess.check_output([str(exe), '--fixture', '--v3', '--wrap'])
        cls.wrap_v1 = subprocess.check_output([str(exe), '--fixture', '--legacy', '--wrap'])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_b_copies(self):
        base = bytearray.fromhex(next(e['payload_hex'] for e in self.events if e['event'] == 'air_B'))
        for mode in (1,2):
            stream=sniffer.Stream()
            data=bytearray(base)
            data[3]=(10<<3)|4
            data[67]=(4<<2)|(4<<5)
            data[68]=16|(mode<<6)
            data[71]=sniffer.crc8(data[:71])
            first=sniffer.decode_record(stream.record(struct.pack('<IHHBBbB',1000000,1,302,0x11,72,-42,7)+data))
            self.assertEqual(first['second_b'],mode)
            offset=32 if mode==1 else 80
            preamble=int.from_bytes(data[12:16],'big')
            data[0]=0xec
            data[12:16]=((preamble+offset)&sniffer.UNKNOWN).to_bytes(4,'big')
            data[71]=sniffer.crc8(data[:71])
            end=1000000+(offset*1000000+32767)//32768
            second=sniffer.decode_record(stream.record(struct.pack('<IHHBBbB',end,2,302,0x11,72,-42,7)+data))
            self.assertTrue(second['second_copy'])
            self.assertEqual(first['frame'],second['frame'])
            self.assertEqual(first['grants'],second['grants'])
            self.assertEqual(second['slot'],13 if mode==1 else 16)
            frame=first['frame']
            start,stop=stream.timeline[frame]
            occupied=(11+1+4+(2 if mode==1 else 1))*16
            self.assertEqual((stop-start)&sniffer.UNKNOWN,max(occupied,(frame+1)*32768//120-frame*32768//120))

    def test_runtime_demand_decode(self):
        for width in (15, 16):
            for repairs in range(6):
                data = bytearray.fromhex(next(e['payload_hex'] for e in self.events if e['event'] == 'air_B'))
                data[3] = 128 | (3 << 3) | repairs
                data[16:20] = bytes.fromhex('000f000f')
                data[63:67] = bytes.fromhex('00010002')
                data[67] = 2 << 2 | 3 << 5
                data[68] = 32 | (width == 15)
                data[69:71] = (170).to_bytes(2, 'big')
                data[71] = sniffer.crc8(data[:71])
                raw = struct.pack('<IHHBBbB', 1000000, 1, 302, 0x11, 72, -42, 7) + data
                stream = sniffer.Stream()
                event = sniffer.decode_record(stream.record(raw))
                self.assertEqual(event['repair_count'], repairs)
                self.assertEqual(event['direct_count'], 4)
                self.assertEqual(event['slot_ticks'], width)
                self.assertEqual(event['tps_max'], 170)
                self.assertEqual(event['missing'][-2:], [1, 2])
                self.assertEqual(event['maintenance_owner'], 255)
                self.assertEqual((event['next_repairs'], event['next2_repairs']), (2, 3))

    def test_protocol_decode(self):
        b = next(e for e in self.events if e['event'] == 'air_B')
        self.assertEqual(b['missing'], [8, 0, 0])
        self.assertEqual(b['grants'][0], dict(slot='R0', owner=4, children=8))
        self.assertTrue(b['b_anchor'])
        r = next(e for e in self.events if e['event'] == 'air_repair')
        self.assertEqual(r['helper'], 4)
        self.assertEqual([(c['child'], c['frame'], c['age'], c['rssi']) for c in r['records']],
                         [(3, 65539, 1, -53), (9, 65538, 2, -61)])
        src = next(e for e in self.events if e['event'] == 'air_source')
        self.assertTrue(src['matches_direct_slot'])
        self.assertEqual(src['address_slot_name'], 'D3')
        self.assertEqual(src['pose_frame'], 65535)
        bad = next(e for e in self.events if e['event'] == 'air_crc_fail')
        self.assertEqual(bad['candidate_child'], 3)
        self.assertNotIn('source', bad)

    def test_fragmented_stream(self):
        decoder, events = sniffer.Stream(), []
        for value in self.raw:
            events.extend(decoder.feed(bytes([value])))
        self.assertEqual(events, self.events)
        self.assertEqual(decoder.finish(), [])

    def test_corruption_and_truncation(self):
        data = bytearray(self.raw)
        data[80] ^= 1
        events = sniffer.Stream().feed(data)
        self.assertTrue(any(e['event'] == 'air_stream_error' for e in events))
        self.assertEqual(events[-1]['event'], 'air_stop')
        decoder = sniffer.Stream()
        decoder.feed(self.raw[:-1])
        self.assertEqual(decoder.finish()[0]['reason'], 'truncated record')

    def test_v3_matches_legacy_network_fields(self):
        legacy = sniffer.Stream().feed(self.legacy_raw)
        self.assertEqual([e for e in self.events if e['kind'] == 1],
                         [e for e in legacy if e['kind'] == 1])
        self.assertLess(len(self.raw), len(self.legacy_raw))
        self.assertEqual([e for e in sniffer.Stream().feed(self.wrap_v3) if e.get('kind') == 1],
                         [e for e in sniffer.Stream().feed(self.wrap_v1) if e.get('kind') == 1])
        self.assertEqual(self.raw[:4], b'RSN3')
        self.assertEqual(struct.unpack_from('<H', self.raw, 4)[0], 16 + 12 + 7)

    @staticmethod
    def chunk(records, seq=0):
        data = b''.join(records)
        header = struct.pack('<4sHHI', b'RSN3', 16 + len(data), len(records), seq)
        body = header + data
        return body + struct.pack('<I', zlib.crc32(body))

    @staticmethod
    def wire(kind, seq, data=b'', flags=0, end=0, delta=0):
        return struct.pack('<IHHBBbB', end, seq & 65535, delta, kind << 4,
                           len(data), -45, flags) + data

    def test_chunk_gaps_crc_and_count(self):
        first = struct.unpack_from('<H', self.raw, 4)[0]
        second = struct.unpack_from('<H', self.raw, first + 4)[0]
        dropped = self.raw[:first] + self.raw[first + second:]
        events = sniffer.Stream().feed(dropped)
        self.assertTrue(any(e.get('reason') == 'chunk sequence gap' for e in events))
        corrupt = bytearray(self.raw)
        corrupt[20] ^= 1
        self.assertEqual(sniffer.Stream().feed(corrupt)[0]['reason'], 'chunk CRC32 mismatch')
        bad = bytearray(self.chunk([self.wire(3, 0, bytes(7))]))
        bad[6] = 2
        bad[-4:] = struct.pack('<I', zlib.crc32(bad[:-4]))
        self.assertEqual(sniffer.Stream().feed(bad)[0]['reason'], 'truncated chunk record')

    def test_overflow_accounting_and_sequence_wrap(self):
        decoder = sniffer.Stream()
        records = [self.wire(3, 0, bytes(7)), self.wire(1, 65535), self.wire(1, 65536),
                   self.wire(2, 65536, struct.pack('<III', 65536, 65534, 50)),
                   self.wire(1, 65538),
                   self.wire(4, 65538, struct.pack('<III', 65538, 65535, 50))]
        events = decoder.feed(self.chunk(records))
        self.assertEqual([e['seq'] for e in events if e.get('kind') == 1], [65535, 65536, 65538])
        self.assertEqual(events[-1]['dropped'], 65535)
        self.assertEqual(events[-1]['seq'], 65538)
        self.assertFalse(sniffer.attach_air(self.joined(), events)['sniffer']['complete'])
        # Overflow after the final delivered packet must survive in the footer.
        footer = self.wire(4, 65555, struct.pack('<III', 65555, 65552, 50))
        self.assertEqual(decoder.feed(self.chunk([footer], 1))[-1]['dropped'], 65552)

    def test_bad_radio_length_and_timer_wrap(self):
        raw = self.wire(1, 1, bytes(72), flags=8, end=5, delta=300) + bytes([250])
        e = sniffer.Stream().feed(self.chunk([raw]))[0]
        self.assertEqual(e['radio_length'], 250)
        self.assertEqual(e['address_us'], (5 - 300) & 0xffffffff)
        self.assertEqual(e['length'], 72)
        with self.assertRaisesRegex(ValueError, 'no device opened'):
            sniffer.BulkPort('receiver-serial')

    def test_capture_rejects_fleet_ports(self):
        # No serial module or real enumeration is called in this test.
        serial = SimpleNamespace(Serial=mock.Mock(side_effect=AssertionError('opened a device')))
        ports = SimpleNamespace(comports=lambda: [SimpleNamespace(
            device='/dev/fleet', vid=0x1209, pid=0x7690, serial_number='existing-receiver')])
        tools = SimpleNamespace(list_ports=ports)
        with mock.patch.dict('sys.modules', {'serial': serial, 'serial.tools': tools}):
            with self.assertRaisesRegex(ValueError, 'no device opened'):
                sniffer.capture(SimpleNamespace(port='/dev/fleet', serial='existing-receiver'))
        serial.Serial.assert_not_called()

    def test_passive_checker_rejects_tx(self):
        check_spec = importlib.util.spec_from_file_location('passive_check', ROOT / 'scripts/check_sniffer_passive.py')
        checker = importlib.util.module_from_spec(check_spec)
        check_spec.loader.exec_module(checker)
        checker.ROOT = self.path / 'bad-firmware'
        app = checker.ROOT / 'sniffer'
        app.mkdir(parents=True, exist_ok=True)
        for name in ('CMakeLists.txt', 'core.c', 'main.c', 'radio.c'):
            (app / name).write_text((ROOT / 'sniffer' / name).read_text())
        good = (app / 'radio.c').read_text()
        for tx in ('NRF_RADIO->TASKS_TXEN = 1;', 'esb_init(&config);',
                   'NRF_PPI->CH[2].TEP = (uint32_t)&NRF_RADIO->TASKS_TXEN;'):
            (app / 'radio.c').write_text(good + '\n' + tx)
            with self.assertRaises(AssertionError):
                checker.check(self.path / 'unused-build')

    def joined(self):
        return dict(child=3, rows=[dict(session=123, frame=f, events=[], age=None)
                                  for f in range(65535, 65550)])

    def test_join_air_states(self):
        result = sniffer.attach_air(self.joined(), self.events)
        self.assertTrue(result['sniffer']['complete'])
        byframe = {r['frame']: r for r in result['rows']}
        self.assertEqual(byframe[65537]['air_source'], 'yes')
        self.assertEqual(byframe[65538]['air_source'], 'CRC-bad')
        self.assertEqual(byframe[65539]['air_source'], 'no')
        self.assertEqual(byframe[65539]['air_events'][-1]['event'], 'air_repair')

    def test_join_missing_evidence(self):
        for removed in ('air_config', 'air_stop', 'air_B'):
            events = [e for e in self.events if e['event'] != removed]
            result = sniffer.attach_air(self.joined(), events)
            self.assertFalse(result['sniffer']['complete'])
            self.assertEqual(result['rows'][4]['air_source'], 'unknown')
        events = copy.deepcopy(self.events)
        events[-1]['dropped'] = 17
        result = sniffer.attach_air(self.joined(), events)
        self.assertEqual(result['sniffer']['dropped'], 17)
        self.assertFalse(result['sniffer']['complete'])
        self.assertEqual(result['rows'][4]['air_source'], 'unknown')
        self.assertEqual(result['rows'][2]['air_source'], 'yes')
        events = copy.deepcopy(self.events)
        events[-1]['rearm_max_us'] = 200
        self.assertFalse(sniffer.attach_air(self.joined(), events)['sniffer']['complete'])

    def test_existing_joiner_cli(self):
        # Copying/importing the real joiner is read-only. No tracker edits.
        joiner = pathlib.Path('/Users/johnny/nrf54-fork/tracker/scripts/relay_ledger_join.py')
        if not joiner.exists():
            self.skipTest('pass --joiner on a different workspace')
        source, receiver = self.path / 'source.txt', self.path / 'receiver.txt'
        for path, event in ((source, 11), (receiver, 6)):
            rows = [f'LEDGER 123 {f} 3 {event} 0 0 0' for f in range(65534, 65551)]
            path.write_text(f'LEDGER begin count={len(rows)} dropped=0\n' + '\n'.join(rows) + '\nLEDGER end\n')
        baseline = sniffer.load_joiner(joiner).join([source, receiver], 3)
        air, output = self.path / 'air.jsonl', self.path / 'joined.json'
        air.write_text(''.join(json.dumps(e) + '\n' for e in self.events))
        subprocess.run(['python3', str(ROOT / 'scripts/relay_sniffer.py'), 'join', '3',
                        str(source), str(receiver), '--joiner', str(joiner), '--air', str(air),
                        '-o', str(output)], check=True, stdout=subprocess.PIPE)
        result = json.loads(output.read_text())
        self.assertEqual(result['rows'][0]['frame'], 65537)
        for key in ('ages', 'within3', 'loss_attribution', 'denominator'):
            self.assertEqual(result[key], baseline[key])
        self.assertEqual(next(r for r in result['rows'] if r['frame'] == 65538)['air_source'], 'CRC-bad')

        # The optional tracker change exists only as a patch in this worktree.
        import shutil
        checkout = self.path / 'patched'
        (checkout / 'scripts').mkdir(parents=True, exist_ok=True)
        shutil.copy(joiner, checkout / 'scripts/relay_ledger_join.py')
        subprocess.run(['git', 'apply',
                        str(ROOT / 'patches/tracker-relay-ledger-air.patch')], check=True,
                       cwd=checkout)
        subprocess.run(['python3', str(checkout / 'scripts/relay_ledger_join.py'), '3',
                        str(source), str(receiver), '--air', str(air), '--air-tool',
                        str(ROOT / 'scripts/relay_sniffer.py'), '-o', str(output)],
                       check=True, stdout=subprocess.PIPE)
        self.assertEqual(json.loads(output.read_text()), result)

    def test_host_headroom(self):
        start = time.perf_counter()
        count = 0
        for _ in range(200):
            count += len(sniffer.Stream().feed(self.raw))
        rate = count / (time.perf_counter() - start)
        print(f'host decode: {rate:.0f} records/s; scheduled peak 2040 packets/s')
        self.assertGreater(rate, 2040)


if __name__ == '__main__':
    unittest.main(verbosity=2)
