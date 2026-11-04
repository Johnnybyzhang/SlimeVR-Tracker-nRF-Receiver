#include "relay_coord.h"
#include <string.h>

struct relay_coord rc;
struct relay_control c;
struct rc_grant_plan plan;
uint8_t payload[RELAY_CONTROL_LEN];
struct relay_control_crc_plan crc;
static uint32_t state;

static uint32_t rnd(void)
{
	state ^= state << 13;
	state ^= state >> 17;
	state ^= state << 5;
	return state;
}

void setup(unsigned seed)
{
	state = seed + 1;
	memset(&rc, 0, sizeof(rc));
	memset(&c, 0, sizeof(c));
	c.members = (1U << (11U + seed % 6U)) - 1U;
	c.expected = c.members;
	rc.learn_members = c.members;
	c.frame = 30 + seed / 6 % 10;
	c.repair_count = RELAY_V3_REPAIR_SLOTS;
	c.profile = RELAY_PROFILE_120HZ;
	c.primary_valid = c.backup_valid = c.members;
	for (unsigned id = 0; id < RC_MAX; id++) {
		rc.t[id].direct_permille = 1000;
		rc.maintenance_ms[id] = seed % 13 == 0 ? 1000 : seed % 13 == 1 ? 3500 : 5000;
		rc.report_ms[id] = seed % 7 == 0 ? 0 : 5000;
	}
	/* Full, backup-only, newest-backup-only, sparse, common and distinct helpers. */
	unsigned mode = seed / 1000 % 6;
	for (unsigned age = 0; age < RELAY_V3_CACHE_FRAMES; age++) {
		unsigned i = (c.frame - age) % RELAY_V3_CACHE_FRAMES;
		rc.watch[i].frame = c.frame - age;
		rc.watch[i].members = c.members;
		rc.watch[i].survey = seed % 3 == 0 ? c.members : 0;
		rc.watch[i].primary_valid = mode == 1 || mode == 2 ? 0 :
			mode == 3 ? rnd() & c.members : c.members;
		rc.watch[i].backup_valid = mode == 2 && age != 0 ? 0 :
			mode == 3 ? rnd() & c.members : c.members;
		for (unsigned id = 0; id < RC_MAX; id++) {
			rc.watch[i].helpers[id] = seed < 4 || mode == 4 ? 0x11 : mode == 5 ? id * 0x11 : rnd();
		}
	}
	relay_coord_plan_grants(&rc, &c, &plan, 5000);
	relay_control_encode(payload, &c);
	crc = relay_control_plan_crc(payload);
	for (unsigned age = 0; age < RELAY_V3_CACHE_FRAMES; age++) {
		unsigned i = plan.receipt_index[age];
		rc.receipt[i].frame = c.frame - age;
		rc.receipt[i].received = ~(seed % 5 == 0 ? 0 : seed % 5 == 1 ? c.members : rnd() & c.members);
	}
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
void timed(void)
{
	for (unsigned age = 0; age < RELAY_V3_CACHE_FRAMES; age++) {
		const struct rc_receipt *r = &rc.receipt[plan.receipt_index[age]];
		uint16_t got = r->frame == c.frame - age ? r->received : 0;
		c.missing[age] = c.expected & ~got;
	}
	relay_coord_finish_frozen(&c, &plan, payload);
	relay_control_finish_encode(payload, &c, crc, false);
}

#ifdef RELAY_BENCH_FREESTANDING
void *memset(void *dst, int value, size_t n)
{
	unsigned char *p = dst;
	while (n--) *p++ = value;
	return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
	unsigned char *p = dst;
	const unsigned char *q = src;
	while (n--) *p++ = *q++;
	return dst;
}
#endif
