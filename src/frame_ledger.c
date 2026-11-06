#include "frame_ledger.h"
#ifdef CONFIG_RELAY_FRAME_LEDGER
#include "connection/relay_protocol.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Never overwrite records silently: the host rejects any overflow. */
struct ledger_record {
	uint32_t session, frame;
	int16_t detail;
	uint8_t child, event, peer, age;
};
static struct ledger_record records[4096];
static unsigned count, dropped;
static uint16_t selected;

int ledger_child_enabled(unsigned child)
{
	return child < RELAY_MAX_TRACKERS && (selected & (1U << child));
}

void ledger_command_mask(uint16_t mask)
{
	unsigned bits = relay_mask_count(mask);
	if (!bits || bits > 3) {
		printk("LEDGER invalid mask\n");
		return;
	}
	unsigned key = irq_lock();
	count = dropped = 0;
	selected = mask;
	irq_unlock(key);
	printk("LEDGER armed mask=0x%04x capacity=%u\n", mask, (unsigned)ARRAY_SIZE(records));
}

void ledger_note(
	uint32_t session,
	uint32_t frame,
	uint8_t child,
	uint8_t event,
	int16_t detail,
	uint8_t peer,
	uint8_t age
)
{
	if (!ledger_child_enabled(child)) {
		return;
	}
	unsigned key = irq_lock();
	if (ledger_child_enabled(child)) {
		if (count < ARRAY_SIZE(records)) {
			records[count++] = (struct ledger_record){session, frame, detail, child, event, peer, age};
		} else {
			dropped++;
		}
	}
	irq_unlock(key);
}

void ledger_command(int child)
{
	if (child < -1 || child >= (int)RELAY_MAX_TRACKERS) {
		printk("LEDGER invalid child\n");
		return;
	}
	unsigned key = irq_lock();
	selected = 0;
	unsigned n = count, lost = dropped;
	if (child >= 0) {
		count = dropped = 0;
		selected = 1U << child;
	}
	irq_unlock(key);
	if (child >= 0) {
		printk("LEDGER armed child=%d capacity=%u\n", child, (unsigned)ARRAY_SIZE(records));
		return;
	}
	printk("LEDGER begin count=%u dropped=%u\n", n, lost);
	for (unsigned i = 0; i < n; i++) {
		const struct ledger_record *r = &records[i];
		printk("LEDGER %u %u %u %u %d %u %u\n", r->session, r->frame, r->child, r->event, r->detail, r->peer, r->age);
		k_msleep(10);
	}
	printk("LEDGER end\n");
}
#endif
