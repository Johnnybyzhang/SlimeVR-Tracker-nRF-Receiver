/* This image owns RADIO, TIMER2 and PPI 0/1 exclusively. No ESB, MPSL,
 * Bluetooth, FEM driver, coordinator or receiver object is linked. */
#include "radio.h"
#include <hal/nrf_radio.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>
#include <zephyr/drivers/gpio.h>

extern struct k_sem sniff_wake;
struct sniff_ring sniff_queue;
uint32_t sniff_rearm_max_us;
static uint8_t dma[2 + RELAY_FRAME_MAX] __attribute__((aligned(4)));

uint32_t sniff_now_us(void)
{
	NRF_TIMER2->TASKS_CAPTURE[2] = 1;
	return NRF_TIMER2->CC[2];
}

static void radio_isr(const void *unused)
{
	ARG_UNUSED(unused);
	if (!NRF_RADIO->EVENTS_END) {
		return;
	}
	NRF_RADIO->EVENTS_END = 0;
	struct sniff_record r = {.kind = SNIFF_PACKET,
		.end_us = NRF_TIMER2->CC[1], .address_us = NRF_TIMER2->CC[0],
		.pipe = NRF_RADIO->RXMATCH, .length = MIN(dma[0], RELAY_FRAME_MAX), .radio_length = dma[0],
		.flags = (NRF_RADIO->CRCSTATUS ? SNIFF_CRC_OK : 0) |
			(dma[0] > RELAY_FRAME_MAX ? SNIFF_BAD_LENGTH : 0),
		.rssi = -(int8_t)NRF_RADIO->RSSISAMPLE};
	memcpy(r.data, dma + 2, r.length);
	/* RX stops at END in RXIDLE; DMA cannot change while copying. START
	 * resumes RX directly, with no ramp-up and no RX->TX shortcut. */
	NRF_RADIO->TASKS_RSSISTOP = 1;
	NRF_RADIO->EVENTS_ADDRESS = 0;
	NRF_RADIO->EVENTS_CRCOK = 0;
	NRF_RADIO->EVENTS_CRCERROR = 0;
	__DMB();
	NRF_RADIO->TASKS_START = 1;
	uint32_t delay = sniff_now_us() - r.end_us;
	if (delay > sniff_rearm_max_us) {
		sniff_rearm_max_us = delay;
	}
	sniff_push(&sniff_queue, &r);
	k_sem_give(&sniff_wake);
}

int sniff_radio_init(void)
{
	/* Discard any state inherited across a bootloader application jump,
	 * including fixed PPI channels that could enable the transmitter. */
	NRF_PPI->CHENCLR = UINT32_MAX;
	NRF_RADIO->POWER = 0;
	NRF_RADIO->POWER = 1;
	NRF_RADIO->INTENCLR = UINT32_MAX;
	NRF_RADIO->SHORTS = 0;
	NRF_PPI->FORK[0].TEP = 0;
	NRF_PPI->FORK[1].TEP = 0;
	/* FEM PA/CTX stays low forever. CRX high selects its receive path.
	 * Do not let MPSL switch either pin. RSSI is the SoC input reading. */
	static const struct gpio_dt_spec pa = GPIO_DT_SPEC_GET(DT_NODELABEL(nrf_radio_fem), ctx_gpios);
	static const struct gpio_dt_spec lna = GPIO_DT_SPEC_GET(DT_NODELABEL(nrf_radio_fem), crx_gpios);
	int err = gpio_pin_configure_dt(&pa, GPIO_OUTPUT_INACTIVE);
	if (!err) {
		err = gpio_pin_configure_dt(&lna, GPIO_OUTPUT_ACTIVE);
	}
	if (err) {
		return err;
	}
	/* Request HFXO through the on/off manager the USB driver also uses; a
	 * direct clock_control_on() would make its later request fail (-EPERM). */
	static struct onoff_client hf;
	struct onoff_manager *mgr = z_nrf_clock_control_get_onoff(CLOCK_CONTROL_NRF_SUBSYS_HF);
	int res;
	sys_notify_init_spinwait(&hf.notify);
	err = onoff_request(mgr, &hf);
	if (err < 0) {
		return err;
	}
	while (sys_notify_fetch_result(&hf.notify, &res) == -EAGAIN) {
	}
	if (res < 0) {
		return res;
	}
	NRF_TIMER2->MODE = TIMER_MODE_MODE_Timer;
	NRF_TIMER2->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
	NRF_TIMER2->PRESCALER = 4; /* 16 MHz / 16 = 1 MHz */
	NRF_TIMER2->TASKS_CLEAR = 1;
	NRF_TIMER2->TASKS_START = 1;
	NRF_PPI->CH[0].EEP = (uint32_t)&NRF_RADIO->EVENTS_ADDRESS;
	NRF_PPI->CH[0].TEP = (uint32_t)&NRF_TIMER2->TASKS_CAPTURE[0];
	NRF_PPI->CH[1].EEP = (uint32_t)&NRF_RADIO->EVENTS_END;
	NRF_PPI->CH[1].TEP = (uint32_t)&NRF_TIMER2->TASKS_CAPTURE[1];
	NRF_PPI->CHENSET = 3;
	IRQ_CONNECT(RADIO_IRQn, 0, radio_isr, NULL, 0);
	return 0;
}

void sniff_radio_stop(void)
{
	irq_disable(RADIO_IRQn);
	NRF_RADIO->SHORTS = 0;
	NRF_RADIO->TASKS_DISABLE = 1;
	while (NRF_RADIO->STATE != RADIO_STATE_STATE_Disabled) {
	}
	/* An END pending when STOP arrived is still an observed packet. */
	radio_isr(NULL);
	NRF_RADIO->TASKS_DISABLE = 1;
	while (NRF_RADIO->STATE != RADIO_STATE_STATE_Disabled) {
	}
}

void sniff_radio_start(uint8_t channel, const uint8_t receiver[6])
{
	uint32_t base0, base1, prefix[2];
	sniff_addresses(receiver, &base0, &base1, prefix);
	NRF_RADIO->POWER = 1;
	NRF_RADIO->MODE = RADIO_MODE_MODE_Nrf_2Mbit;
	NRF_RADIO->MODECNF0 = RADIO_MODECNF0_RU_Fast;
	NRF_RADIO->FREQUENCY = channel;
	/* Match SDK ESB DPL exactly: LFLEN=8 for max length 72, S1=3 bits,
	 * MSB-first, 5-byte address, 16-bit preamble, no whitening. */
	NRF_RADIO->PCNF0 = (8U << RADIO_PCNF0_LFLEN_Pos) |
		(3U << RADIO_PCNF0_S1LEN_Pos) |
		(RADIO_PCNF0_PLEN_16bit << RADIO_PCNF0_PLEN_Pos);
	NRF_RADIO->PCNF1 = RELAY_FRAME_MAX | (4U << RADIO_PCNF1_BALEN_Pos) |
		(RADIO_PCNF1_ENDIAN_Big << RADIO_PCNF1_ENDIAN_Pos);
	NRF_RADIO->CRCCNF = RADIO_CRCCNF_LEN_Two; /* address included */
	NRF_RADIO->CRCINIT = 0xffff;
	NRF_RADIO->CRCPOLY = 0x11021;
	NRF_RADIO->BASE0 = base0;
	NRF_RADIO->BASE1 = base1;
	NRF_RADIO->PREFIX0 = prefix[0];
	NRF_RADIO->PREFIX1 = prefix[1];
	NRF_RADIO->RXADDRESSES = 0xff;
	NRF_RADIO->PACKETPTR = (uint32_t)dma;
	NRF_RADIO->EVENTS_END = 0;
	NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_ADDRESS_RSSISTART_Msk;
	NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk;
	NVIC_ClearPendingIRQ(RADIO_IRQn);
	irq_enable(RADIO_IRQn);
	NRF_RADIO->TASKS_RXEN = 1;
}
