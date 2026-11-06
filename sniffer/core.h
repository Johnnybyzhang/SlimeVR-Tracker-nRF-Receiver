#ifndef RELAY_SNIFFER_CORE_H
#define RELAY_SNIFFER_CORE_H
#include "relay_protocol.h"

#define SNIFF_PACKET 1
#define SNIFF_STATUS 2
#define SNIFF_CONFIG 3
#define SNIFF_STOP 4
#define SNIFF_CRC_OK 1
#define SNIFF_LOCKED 2
#define SNIFF_B_ANCHOR 4
#define SNIFF_BAD_LENGTH 8
#define SNIFF_RING_SIZE 512U
#define SNIFF_LOCK_US 1000000U

/* Little endian, packed USB ABI v1. A CRC32 follows header + length bytes.
 * Unknown frame/tick/phase/slot fields are all-ones. seq counts RADIO ENDs,
 * including ring overflow. Status/stop seq is the total END count. */
struct sniff_record {
	uint8_t magic[4];
	uint16_t size;
	uint8_t version, kind;
	uint32_t seq, dropped, end_us, address_us;
	uint32_t session, frame, end_tick, address_tick, address_frame;
	uint16_t phase, address_phase;
	uint8_t slot, pipe, length, flags, address_slot, radio_length;
	int8_t rssi;
	uint8_t reserved2;
	uint8_t data[RELAY_FRAME_MAX];
} __attribute__((packed));
#define SNIFF_HEADER_SIZE offsetof(struct sniff_record, data)
_Static_assert(SNIFF_HEADER_SIZE == 56, "USB ABI");

/* RSN3 chunks contain 12-byte records. See README for the wire layout. */
#define SNIFF_WIRE_HEADER_SIZE 12U
#define SNIFF_WIRE_MAX (SNIFF_WIRE_HEADER_SIZE + RELAY_FRAME_MAX + 1U)
#define SNIFF_CHUNK_MAX 1024U
size_t sniff_encode(const struct sniff_record *r, uint8_t wire[SNIFF_WIRE_MAX]);
size_t sniff_chunk_finish(uint8_t *wire, size_t length, uint16_t count, uint32_t seq);

struct sniff_clock {
	bool locked;
	uint8_t epoch;
	uint32_t session, frame, local_us, net_tick;
	struct relay_runtime_anchor anchor;
	struct relay_timeline timeline;
};
struct sniff_ring {
	struct sniff_record records[SNIFF_RING_SIZE];
	uint32_t head, tail, seen, dropped;
};
/* Caller serializes ring operations against the RADIO ISR. */
bool sniff_push(struct sniff_ring *q, struct sniff_record *r);
bool sniff_pop(struct sniff_ring *q, struct sniff_record *r);
void sniff_stamp(struct sniff_clock *clock, struct sniff_record *r);
void sniff_addresses(const uint8_t receiver[6], uint32_t *base0, uint32_t *base1, uint32_t prefix[2]);
uint32_t sniff_crc32(const void *data, size_t length);
#endif
