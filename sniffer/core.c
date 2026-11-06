#include "core.h"

bool sniff_push(struct sniff_ring *q, struct sniff_record *r)
{
	r->seq = ++q->seen;
	if (q->head - q->tail == SNIFF_RING_SIZE) {
		q->dropped++;
		return false;
	}
	r->dropped = q->dropped;
	q->records[q->head++ % SNIFF_RING_SIZE] = *r;
	return true;
}

bool sniff_pop(struct sniff_ring *q, struct sniff_record *r)
{
	if (q->head == q->tail) {
		return false;
	}
	*r = q->records[q->tail++ % SNIFF_RING_SIZE];
	return true;
}

/* Floor signed deltas so an ADDRESS just before a tick stays before it. */
static int32_t ticks(int32_t us)
{
	int64_t n = (int64_t)us * 32768;
	return (int32_t)((n - (n < 0 ? 999999 : 0)) / 1000000);
}

static uint32_t project(const struct sniff_clock *c, uint32_t us)
{
	return c->net_tick + ticks((int32_t)(us - c->local_us));
}

void sniff_stamp(struct sniff_clock *c, struct sniff_record *r)
{
	r->session = r->frame = r->end_tick = r->address_tick = r->address_frame = UINT32_MAX;
	r->phase = r->address_phase = UINT16_MAX;
	r->slot = r->address_slot = UINT8_MAX;
	if (c->locked && (uint32_t)(r->end_us - c->local_us) > SNIFF_LOCK_US) {
		c->locked = false;
	}
	struct relay_control b;
	if (r->pipe == 1 && (r->flags & (SNIFF_CRC_OK | SNIFF_BAD_LENGTH)) == SNIFF_CRC_OK
		&& relay_control_decode(r->data, r->length, &b)) {
		uint32_t end = b.preamble_ticks + RELAY_V3_CONTROL_AIR_TICKS;
		if (r->data[0] == RELAY_CONTROL_REPEAT) {
			end += relay_second_b_offset(b.direct_count, b.repair_count, b.slot_ticks, b.second_b);
		}
		int32_t error = (int32_t)(end - project(c, r->end_us));
		bool same = c->locked && b.session == c->session;
		/* Like tracker B sync: accept at most four ticks of innovation and
		 * never reuse an old B. Bootstrap/reboot needs no transmitting PING. */
		if (!same || ((int32_t)(b.frame - c->frame) > 0 && error >= -4 && error <= 4)) {
			if (!same || c->epoch != b.epoch) {
				relay_timeline_clear(&c->timeline);
			}
			c->locked = true;
			c->epoch = b.epoch;
			c->session = b.session;
			c->frame = b.frame;
			c->local_us = r->end_us;
			c->net_tick = end;
			relay_runtime_anchor_set(
				&c->anchor,
				b.frame,
				b.preamble_ticks,
				b.direct_count,
				b.repair_count,
				relay_control_next_repairs(&b),
				relay_control_next2_repairs(&b),
				b.slot_ticks,
				b.tps_max
			);
			relay_runtime_anchor_second_b(
				&c->anchor,
				b.repair_count,
				relay_control_next_repairs(&b),
				relay_control_next2_repairs(&b),
				b.tps_max,
				b.second_b
			);
			relay_timeline_announce(&c->timeline, &c->anchor);
			r->flags |= SNIFF_B_ANCHOR;
		}
	}
	if (!c->locked) {
		return;
	}
	uint32_t end_tick = project(c, r->end_us), address_tick = project(c, r->address_us);
	uint32_t frames[2], starts[2];
	uint32_t ts[2] = {end_tick, address_tick};
	for (unsigned j = 0; j < 2; j++) {
		bool found = false;
		for (int i = 3; i >= -12; i--) {
			uint32_t f = c->frame + i, start, next;
			if (!relay_timeline_start(&c->timeline, f, &start)) {
				continue;
			}
			if (!relay_timeline_start(&c->timeline, f + 1U, &next)) {
				next = start + c->anchor.direct * c->anchor.slot_ticks;
			}
			if ((int32_t)(ts[j] - start) >= 0 && (int32_t)(ts[j] - next) < 0) {
				frames[j] = f;
				starts[j] = start;
				found = true;
				break;
			}
		}
		if (!found) {
			return;
		}
	}
	r->flags |= SNIFF_LOCKED;
	r->session = c->session;
	r->end_tick = end_tick;
	r->address_tick = address_tick;
	r->frame = frames[0];
	r->address_frame = frames[1];
	r->phase = end_tick - starts[0];
	r->address_phase = address_tick - starts[1];
	r->slot = r->phase / c->anchor.slot_ticks;
	r->address_slot = r->address_phase / c->anchor.slot_ticks;
}

static uint8_t reverse(uint8_t v)
{
	v = (v >> 4) | (v << 4);
	v = ((v & 0xcc) >> 2) | ((v & 0x33) << 2);
	return ((v & 0xaa) >> 1) | ((v & 0x55) << 1);
}

void sniff_addresses(const uint8_t id[6], uint32_t *base0, uint32_t *base1, uint32_t prefix[2])
{
	/* Same derivation as receiver esb_set_addr_unified(), then ESB's
	 * addr_conv()/bytewise_bit_swap(). id is FICR DEVICEADDR in RAM order. */
	const uint8_t discovery[] = {0x62, 0x39, 0x8a, 0xf2};
	uint8_t addr[4], p[8] = {0xfe};
	for (unsigned i = 0; i < 4; i++) {
		addr[i] = id[i] + id[4];
		if (addr[i] == 0 || addr[i] == 0x55 || addr[i] == 0xaa) {
			addr[i] += 8;
		}
	}
	for (unsigned i = 1; i < 8; i++) {
		p[i] = id[5] + i;
		if (p[i] == 0 || p[i] == 0x55 || p[i] == 0xaa) {
			p[i] += 8;
		}
	}
	*base0 = *base1 = prefix[0] = prefix[1] = 0;
	for (unsigned i = 0; i < 4; i++) {
		*base0 |= (uint32_t)reverse(discovery[i]) << (24 - i * 8);
		*base1 |= (uint32_t)reverse(addr[i]) << (24 - i * 8);
		prefix[0] |= (uint32_t)reverse(p[i]) << (i * 8);
		prefix[1] |= (uint32_t)reverse(p[i + 4]) << (i * 8);
	}
}

uint32_t sniff_crc32(const void *data, size_t length)
{
	const uint8_t *p = data;
	uint32_t crc = UINT32_MAX;
	while (length--) {
		crc ^= *p++;
		for (unsigned b = 0; b < 8; b++) {
			crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
		}
	}
	return ~crc;
}

size_t sniff_encode(const struct sniff_record *r, uint8_t wire[SNIFF_WIRE_MAX])
{
	uint16_t seq = r->seq, delta = r->end_us - r->address_us;
	memcpy(wire, &r->end_us, 4);
	memcpy(wire + 4, &seq, 2);
	memcpy(wire + 6, &delta, 2);
	wire[8] = (r->kind << 4) | (r->pipe & 7);
	wire[9] = r->length;
	wire[10] = (uint8_t)r->rssi;
	/* Original RADIO length is derivable unless capped. Oversize implies
	 * bad length; retain the original length as one extra payload byte. */
	wire[11] = r->flags;
	memcpy(wire + 12, r->data, r->length);
	if (r->flags & SNIFF_BAD_LENGTH) {
		wire[12 + r->length] = r->radio_length;
		return 13 + r->length;
	}
	return 12 + r->length;
}

size_t sniff_chunk_finish(uint8_t *wire, size_t length, uint16_t count, uint32_t seq)
{
	uint16_t size = length + 4;
	memcpy(wire, "RSN3", 4);
	memcpy(wire + 4, &size, 2);
	memcpy(wire + 6, &count, 2);
	memcpy(wire + 8, &seq, 4);
	uint32_t crc = sniff_crc32(wire, length);
	memcpy(wire + length, &crc, 4);
	return size;
}
