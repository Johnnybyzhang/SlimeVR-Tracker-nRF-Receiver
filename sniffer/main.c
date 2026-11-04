#include "radio.h"
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/usb/udc.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/usb/usbd.h>

/* Local experimental device identity, product and FICR-derived USB serial
 * distinguish it from the receiver. This PID is not a public allocation. */
USBD_DEVICE_DEFINE(sniffer_usb, DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)), 0x1209, 0x7691);
USBD_DESC_LANG_DEFINE(lang);
USBD_DESC_MANUFACTURER_DEFINE(mfr, "Holyiot");
USBD_DESC_PRODUCT_DEFINE(product, "Passive relay sniffer");
USBD_DESC_SERIAL_NUMBER_DEFINE(serial_number);
USBD_DESC_CONFIG_DEFINE(cfg_desc, "Sniffer bulk v3");
USBD_CONFIGURATION_DEFINE(cfg, 0, 100, &cfg_desc);
RING_BUF_DECLARE(rx, 128);
K_SEM_DEFINE(sniff_wake, 0, 1);
static struct usbd_class_data *bulk_class;
static atomic_t bulk_enabled, in_flight;
static struct usb_if_descriptor bulk_iface = {
	.bLength = sizeof(struct usb_if_descriptor), .bDescriptorType = USB_DESC_INTERFACE,
	.bNumEndpoints = 1, .bInterfaceClass = USB_BCC_VENDOR,
};
static struct usb_ep_descriptor bulk_in = {
	.bLength = sizeof(struct usb_ep_descriptor), .bDescriptorType = USB_DESC_ENDPOINT,
	.bEndpointAddress = 0x81, .bmAttributes = USB_EP_TYPE_BULK,
	.wMaxPacketSize = sys_cpu_to_le16(64),
};
static struct usb_desc_header bulk_nil;
static const struct usb_desc_header *bulk_desc[] = {
	(void *)&bulk_iface, (void *)&bulk_in, &bulk_nil,
};
static const struct usbd_cctx_vendor_req vendor_requests = USBD_VENDOR_REQ(0x53);
static void *bulk_get_desc(struct usbd_class_data *c, enum usbd_speed speed)
{
	ARG_UNUSED(c); ARG_UNUSED(speed); return bulk_desc;
}
static int bulk_init(struct usbd_class_data *c) { bulk_class = c; return 0; }
static void bulk_enable(struct usbd_class_data *c)
{
	ARG_UNUSED(c); atomic_set(&bulk_enabled, 1); k_sem_give(&sniff_wake);
}
static void bulk_disable(struct usbd_class_data *c)
{
	ARG_UNUSED(c); atomic_clear(&bulk_enabled); k_sem_give(&sniff_wake);
}
static int bulk_request(struct usbd_class_data *c, struct net_buf *buf, int err)
{
	ARG_UNUSED(c); ARG_UNUSED(err);
	net_buf_unref(buf); atomic_dec(&in_flight); k_sem_give(&sniff_wake); return 0;
}
static int bulk_command(struct usbd_class_data *c, const struct usb_setup_packet *setup,
	const struct net_buf *buf)
{
	ARG_UNUSED(c);
	if (setup->bRequest != 0x53 || setup->RequestType.recipient != USB_REQTYPE_RECIPIENT_DEVICE ||
	    !buf->len || buf->len > 63 || ring_buf_space_get(&rx) < buf->len) {
		errno = -EINVAL; return 0;
	}
	ring_buf_put(&rx, buf->data, buf->len); k_sem_give(&sniff_wake); return 0;
}
static const struct usbd_class_api bulk_api = {
	.get_desc = bulk_get_desc, .init = bulk_init, .enable = bulk_enable,
	.disable = bulk_disable, .request = bulk_request, .control_to_dev = bulk_command,
};
USBD_DEFINE_CLASS(sniffer_bulk, &bulk_api, NULL, &vendor_requests);

/* The VBUS callback and boot path may both enable; -EALREADY is success. */
static int usb_enable(struct usbd_context *ctx)
{
	int err = usbd_enable(ctx);
	return err == -EALREADY ? 0 : err;
}

static void usb_message(struct usbd_context *const ctx, const struct usbd_msg *msg)
{
	if (msg->type == USBD_MSG_VBUS_READY) {
		usb_enable(ctx);
	} else if (msg->type == USBD_MSG_VBUS_REMOVED) {
		usbd_disable(ctx);
	}
}

static int usb_init(void)
{
	int err;
#define TRY(call) do { err = (call); if (err) return err; } while (0)
	TRY(usbd_add_descriptor(&sniffer_usb, &lang));
	TRY(usbd_add_descriptor(&sniffer_usb, &mfr));
	TRY(usbd_add_descriptor(&sniffer_usb, &product));
	TRY(usbd_add_descriptor(&sniffer_usb, &serial_number));
	TRY(usbd_add_configuration(&sniffer_usb, USBD_SPEED_FS, &cfg));
	TRY(usbd_register_all_classes(&sniffer_usb, USBD_SPEED_FS, 1, NULL));
	TRY(usbd_msg_register_cb(&sniffer_usb, usb_message));
	TRY(usbd_init(&sniffer_usb));
	/* Handles boot with VBUS already present, as in receiver usb.c. */
	if (!usbd_can_detect_vbus(&sniffer_usb) || (NRF_POWER->USBREGSTATUS & POWER_USBREGSTATUS_VBUSDETECT_Msk)) {
		TRY(usb_enable(&sniffer_usb));
	}
	return 0;
#undef TRY
}

static uint8_t chunk[SNIFF_CHUNK_MAX];
static size_t chunk_used = 12;
static uint16_t chunk_count;
static uint32_t chunk_seq;

static bool flush_chunk(void)
{
	if (!chunk_count) return true;
	if (!atomic_get(&bulk_enabled) || atomic_get(&in_flight) >= 4) return false;
	struct net_buf *buf = usbd_ep_buf_alloc(bulk_class, bulk_in.bEndpointAddress, SNIFF_CHUNK_MAX);
	if (!buf) return false;
	size_t size = sniff_chunk_finish(chunk, chunk_used, chunk_count, chunk_seq);
	net_buf_add_mem(buf, chunk, size);
	if (size % 64 == 0 && size < SNIFF_CHUNK_MAX) udc_ep_buf_set_zlp(buf);
	atomic_inc(&in_flight);
	if (usbd_ep_enqueue(bulk_class, buf)) {
		atomic_dec(&in_flight); net_buf_unref(buf); return false;
	}
	chunk_seq++;
	chunk_used = 12;
	chunk_count = 0;
	return true;
}

static bool record_room(void)
{
	return chunk_used + SNIFF_WIRE_MAX + 4 <= sizeof(chunk) || flush_chunk();
}

static void send_record(struct sniff_record *r)
{
	chunk_used += sniff_encode(r, chunk + chunk_used);
	chunk_count++;
}

/* Same nRF5 bootloader entry as the receiver's `dfu` command: P0.19 low,
 * so reflashing does not need the physical button. */
static void enter_dfu(void)
{
	sniff_radio_stop();
	/* Complete the vendor request status stage before dropping USB. */
	k_msleep(50);
	const struct device *gpio0 = DEVICE_DT_GET(DT_NODELABEL(gpio0));
	gpio_pin_configure(gpio0, 19, GPIO_OUTPUT | GPIO_OUTPUT_INIT_LOW);
	k_msleep(100);
	sys_reboot(SYS_REBOOT_COLD);
}

static void summary(uint8_t kind)
{
	unsigned key = irq_lock();
	struct sniff_record r = {.kind = kind, .seq = sniff_queue.seen,
		.dropped = sniff_queue.dropped, .end_us = sniff_now_us(), .length = 12};
	memcpy(r.data, &r.seq, 4);
	memcpy(r.data + 4, &r.dropped, 4);
	memcpy(r.data + 8, &sniff_rearm_max_us, 4);
	irq_unlock(key);
	send_record(&r);
}

int main(void)
{
	if (sniff_radio_init() || usb_init()) {
		return 1;
	}
	struct sniff_clock clock = {0};
	bool active = false, stopping = false;
	char line[64];
	unsigned used = 0;
	int64_t status_at = 0;
	while (1) {
		bool connected = atomic_get(&bulk_enabled);
		if (!connected && active) {
			sniff_radio_stop();
			active = false;
			stopping = true;
		}
		/* Retain whole records until the USB queue has room, with a bound
		 * on each turn so STOP can be processed under sustained load. */
		for (unsigned i = 0; connected && i < 32 && record_room(); i++) {
			struct sniff_record r;
			unsigned key = irq_lock();
			bool got = sniff_pop(&sniff_queue, &r);
			irq_unlock(key);
			if (!got) {
				break;
			}
			sniff_stamp(&clock, &r);
			send_record(&r);
		}
		if (connected && record_room()) {
			if (stopping && sniff_queue.head == sniff_queue.tail) {
				summary(SNIFF_STOP);
				stopping = false;
			} else if (active && k_uptime_get() >= status_at) {
				summary(SNIFF_STATUS);
				status_at = k_uptime_get() + 1000;
			}
		}
		{ /* Commands must remain available even with a stalled bulk reader. */
			uint8_t ch;
			while (ring_buf_get(&rx, &ch, 1)) {
				if (ch != '\n') {
					if (used < sizeof(line) - 1) {
						line[used++] = ch;
					}
					continue;
				}
				line[used] = 0;
				used = 0;
				if (!strcmp(line, "dfu")) {
					enter_dfu();
				} else if (!strcmp(line, "stop") && active) {
					sniff_radio_stop();
					active = false;
					stopping = true;
				} else if (!active && !stopping && record_room()) {
					unsigned channel;
					char hex[13], extra;
					if (sscanf(line, "start %u %12[0123456789abcdefABCDEF]%c", &channel, hex, &extra) != 2 ||
					    channel > 100 || strlen(hex) != 12) {
						continue;
					}
					struct sniff_record cfg_record = {.kind = SNIFF_CONFIG, .length = 7};
					cfg_record.data[0] = channel;
					for (unsigned i = 0; i < 6; i++) {
						char b[3] = {hex[i * 2], hex[i * 2 + 1], 0};
						cfg_record.data[i + 1] = strtoul(b, NULL, 16);
					}
					memset(&sniff_queue, 0, sizeof(sniff_queue));
					memset(&clock, 0, sizeof(clock));
					sniff_rearm_max_us = 0;
					send_record(&cfg_record);
					sniff_radio_start(channel, cfg_record.data + 1);
					active = true;
					status_at = k_uptime_get() + 1000;
				}
			}
		}
		/* Batch at least 512 bytes when traffic is continuous; a bounded
		 * timeout flushes partial config/status/STOP chunks during silence. */
		if (chunk_used >= 512 || !active || k_sem_take(&sniff_wake, K_MSEC(2)) != 0) {
			flush_chunk();
		}
		if (sniff_queue.head == sniff_queue.tail || !record_room()) {
			k_sem_take(&sniff_wake, K_MSEC(active ? 2 : 100));
		}
	}
}
