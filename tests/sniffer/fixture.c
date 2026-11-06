#include "core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static struct relay_control control(uint32_t origin, uint32_t frame)
{
	struct relay_control b
		= {.session = 123,
		   .epoch = 7,
		   .frame = frame,
		   .preamble_ticks = relay_frame_start(origin, frame) + RELAY_V3_B_PREAMBLE,
		   .members = 0x7ff,
		   .expected = 0x7ff,
		   .profile = RELAY_PROFILE_120HZ,
		   .direct_count = 11,
		   .slot_ticks = 16,
		   .tps_max = 120,
		   .repair_count = 5,
		   .maintenance_owner = RELAY_OWNER_IDLE};
	for (unsigned i = 0; i < 5; i++) {
		b.grants[i].owner = RELAY_OWNER_IDLE;
	}
	b.missing[0] = 1U << 3;
	b.grants[0] = (struct relay_grant){.owner = 4, .children = 1U << 3};
	return b;
}

static struct sniff_record broadcast(struct relay_control b, uint32_t end_us)
{
	struct sniff_record r
		= {.kind = 1, .end_us = end_us, .address_us = end_us - 302, .flags = SNIFF_CRC_OK, .pipe = 1, .rssi = -42};
	r.length = relay_control_encode(r.data, &b);
	return r;
}

static void runtime_tests(void)
{
	for (unsigned n = 4; n <= 16; n += (n == 4 ? 7 : 5)) {
		for (unsigned width = 15; width <= 16; width++) {
			for (unsigned repairs = 0; repairs <= 5; repairs++) {
				struct sniff_clock clock = {0};
				struct relay_control b = control(0, 123);
				b.direct_count = n;
				b.members = b.expected = (1U << n) - 1U;
				b.slot_ticks = width;
				b.tps_max = 170;
				b.repair_count = repairs;
				b.on_demand = true;
				b.preamble_ticks = 0xffffff00U + n * width + 2U;
				for (unsigned i = 0; i < 5; i++) {
					b.grants[i] = (struct relay_grant){.owner = RELAY_OWNER_IDLE};
				}
				relay_control_set_next_repairs(&b, (repairs + 1) % 6);
				relay_control_set_next2_repairs(&b, (repairs + 2) % 6);
				struct sniff_record packet = broadcast(b, 1000000);
				sniff_stamp(&clock, &packet);
				assert(packet.flags & SNIFF_B_ANCHOR);
				assert(packet.frame == 123 && packet.slot == n);
				uint32_t starts[] = {clock.anchor.next_start, clock.anchor.following_start};
				for (unsigned i = 0; i < 2; i++) {
					uint32_t tick = starts[i] + width + 5;
					int32_t dt = (int32_t)(tick - clock.net_tick);
					uint32_t us = clock.local_us + ((int64_t)dt * 1000000 + 32767) / 32768;
					packet = (struct sniff_record){.end_us = us, .address_us = us};
					sniff_stamp(&clock, &packet);
					assert(packet.flags & SNIFF_LOCKED);
					assert(packet.frame == 124 + i && packet.slot == 1 && packet.phase == width + 5);
				}
				uint32_t tick = clock.anchor.third_start + n * width + 5;
				int32_t dt = (int32_t)(tick - clock.net_tick);
				uint32_t us = clock.local_us + ((int64_t)dt * 1000000 + 32767) / 32768;
				packet = (struct sniff_record){.end_us = us, .address_us = us};
				sniff_stamp(&clock, &packet);
				assert(!(packet.flags & SNIFF_LOCKED) && packet.frame == UINT32_MAX);
			}
		}
	}
}

static void core_tests(void)
{
	runtime_tests();
	struct sniff_clock c = {0};
	const uint32_t origin = 0xfffff000;
	struct relay_control b = control(origin, 65535);
	struct sniff_record r = broadcast(b, 0xfffff000);
	sniff_stamp(&c, &r);
	assert(r.flags & SNIFF_B_ANCHOR);
	assert(r.frame == 65535 && r.slot == 11 && r.phase == 189);
	assert(r.address_frame == 65535 && r.address_slot == 11);
	for (uint32_t f = 65536; f < 65538; f++) {
		for (unsigned slot = 0; slot < 17; slot++) {
			uint32_t tick = relay_frame_start(origin, f) + slot * 16 + 5;
			int32_t dt = (int32_t)(tick - c.net_tick);
			// Round up to the first microsecond representing this network tick.
			int64_t us = ((int64_t)dt * 1000000 + 32767) / 32768;
			if (dt < 0) {
				us = (int64_t)dt * 1000000 / 32768;
			}
			r = (struct sniff_record){.end_us = c.local_us + us, .address_us = c.local_us + us - 2};
			sniff_stamp(&c, &r);
			assert(r.frame == f && r.slot == slot);
			assert(r.phase == slot * 16 + 5);
		}
	}
	// Sequential B lock through local TIMER wrap; reject replay/outlier/CRC.
	uint32_t next = c.local_us + 8333;
	r = broadcast(control(origin, 65536), next);
	sniff_stamp(&c, &r);
	assert(r.flags & SNIFF_B_ANCHOR);
	assert(r.frame == 65536);
	r = broadcast(control(origin, 65536), next + 1);
	sniff_stamp(&c, &r);
	assert(!(r.flags & SNIFF_B_ANCHOR));
	r = broadcast(control(origin, 65537), next + 8333 + 1000);
	sniff_stamp(&c, &r);
	assert(!(r.flags & SNIFF_B_ANCHOR));
	r = broadcast(control(origin, 65537), next + 8333);
	r.flags = 0;
	sniff_stamp(&c, &r);
	assert(!(r.flags & SNIFF_B_ANCHOR));
	r = broadcast(control(origin, 65537), next + 8333);
	r.data[71] ^= 1;
	sniff_stamp(&c, &r);
	assert(!(r.flags & SNIFF_B_ANCHOR));
	r = (struct sniff_record){.end_us = c.local_us + SNIFF_LOCK_US + 1};
	sniff_stamp(&c, &r);
	assert(!(r.flags & SNIFF_LOCKED) && r.frame == UINT32_MAX);
	b = control(0, 1);
	b.session++;
	r = broadcast(b, next + SNIFF_LOCK_US + 2);
	sniff_stamp(&c, &r);
	assert(r.flags & SNIFF_B_ANCHOR);
	assert(r.session == 124);

	static struct sniff_ring q;
	for (unsigned i = 0; i < SNIFF_RING_SIZE + 17; i++) {
		sniff_push(&q, &r);
	}
	assert(q.seen == SNIFF_RING_SIZE + 17 && q.dropped == 17);
	for (unsigned i = 0; i < SNIFF_RING_SIZE; i++) {
		assert(sniff_pop(&q, &r) && r.seq == i + 1 && r.dropped == 0);
	}
	assert(!sniff_pop(&q, &r));
	assert(sniff_push(&q, &r));
	assert(sniff_pop(&q, &r) && r.seq == SNIFF_RING_SIZE + 18 && r.dropped == 17);
	for (unsigned i = 0; i < 100000; i++) {
		assert(sniff_push(&q, &r) && sniff_pop(&q, &r));
	}
	q.head = q.tail = UINT32_MAX - 5;
	q.seen = UINT32_MAX - 5;
	for (unsigned i = 0; i < 20; i++) {
		assert(sniff_push(&q, &r) && sniff_pop(&q, &r));
	}
	assert(q.head == 14 && q.tail == 14 && q.seen == 14 && q.dropped == 17);
	uint32_t base0, base1, prefix[2];
	const uint8_t id[] = {0, 0x55, 0xaa, 0xff, 0, 0x54};
	sniff_addresses(id, &base0, &base1, prefix);
	assert(base0 == 0x469c514f && base1 == 0x10ba4dff);
	assert((prefix[0] & 0xffff) == 0xba7f); // pipe 1 0x55 -> 0x5d -> bit reverse
	assert(sniff_crc32("123456789", 9) == 0xcbf43926);
}

static uint32_t sequence;
static bool legacy;
static void emit(struct sniff_record *r)
{
	memcpy(r->magic, "RSN1", 4);
	r->version = 1;
	r->size = SNIFF_HEADER_SIZE + r->length + 4;
	if (r->kind == 1) {
		r->seq = ++sequence;
		r->radio_length = r->length;
	} else {
		r->seq = sequence;
	}
	if (legacy) {
		uint32_t crc = sniff_crc32(r, r->size - 4);
		assert(fwrite(r, 1, r->size - 4, stdout) == r->size - 4);
		assert(fwrite(&crc, 1, 4, stdout) == 4);
	} else {
		static uint32_t chunk_seq;
		uint8_t wire[SNIFF_CHUNK_MAX];
		size_t size = 12 + sniff_encode(r, wire + 12);
		size = sniff_chunk_finish(wire, size, 1, chunk_seq++);
		assert(fwrite(wire, 1, size, stdout) == size);
	}
}

static bool wrap_fixture;
static void fixture(void)
{
	struct sniff_clock c = {0};
	struct sniff_record cfg = {.kind = SNIFF_CONFIG, .length = 7, .data = {84, 1, 2, 3, 4, 5, 6}};
	emit(&cfg);
	uint32_t base = wrap_fixture ? 0xfffff000 : 1000000, first = 65534, origin = wrap_fixture ? 0xfffff000 : 17000;
	uint32_t first_tick = relay_frame_start(origin, first);
	for (uint32_t f = first; f <= 65550; f++) {
		uint32_t tick = relay_frame_start(origin, f);
		uint32_t local_start = base + (uint64_t)(tick - first_tick) * 1000000 / 32768;
		uint8_t source[17] = {0, 3};
		if (f != first && f != 65539) {
			struct sniff_record r
				= {.kind = SNIFF_PACKET,
				   .pipe = 4,
				   .length = 17,
				   .flags = f == 65538 ? 0 : SNIFF_CRC_OK,
				   .rssi = -51,
				   .end_us = local_start + 1630,
				   .address_us = local_start + 1554};
			memcpy(r.data, source, 17);
			sniff_stamp(&c, &r);
			emit(&r);
		}
		struct sniff_record b = broadcast(control(origin, f), local_start + 5762);
		sniff_stamp(&c, &b);
		assert(b.flags & SNIFF_B_ANCHOR);
		emit(&b);
		if (f == 65540) {
			struct relay_repair repair = {.helper = 4, .epoch = 7, .session = 123, .count = 2};
			repair.records[0] = (struct relay_repair_record){
				.capture_frame = (uint16_t)65539,
				.source = {.frame = source, .length = 17, .rssi = 53}
			};
			uint8_t source9[17] = {1, 9};
			repair.records[1] = (struct relay_repair_record){
				.capture_frame = (uint16_t)65538,
				.source = {.frame = source9, .length = 17, .rssi = 61}
			};
			struct sniff_record r
				= {.kind = SNIFF_PACKET,
				   .pipe = 5,
				   .flags = SNIFF_CRC_OK,
				   .rssi = -45,
				   .end_us = local_start + 6200,
				   .address_us = local_start + 5980};
			r.length = relay_repair_encode(r.data, &repair);
			struct relay_repair decoded;
			assert(relay_repair_decode(r.data, r.length, &decoded));
			sniff_stamp(&c, &r);
			emit(&r);
		}
	}
	struct sniff_record stop = {.kind = SNIFF_STOP, .length = legacy ? 4 : 12};
	if (legacy) {
		stop.data[0] = 8;
	} else {
		memcpy(stop.data, &sequence, 4);
		stop.data[8] = 8;
	}
	emit(&stop);
}

int main(int argc, char **argv)
{
	legacy = argc > 2 && !strcmp(argv[2], "--legacy");
	wrap_fixture = argc > 3;
	core_tests();
	if (argc > 1) {
		fixture();
	} else {
		puts("core: clock, all slots, wrap, B gate, ring overflow and addresses passed");
	}
}
