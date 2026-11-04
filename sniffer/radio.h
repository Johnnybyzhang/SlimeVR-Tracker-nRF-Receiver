#ifndef SNIFFER_RADIO_H
#define SNIFFER_RADIO_H
#include "core.h"
extern struct sniff_ring sniff_queue;
extern uint32_t sniff_rearm_max_us;
int sniff_radio_init(void);
void sniff_radio_start(uint8_t channel, const uint8_t receiver[6]);
void sniff_radio_stop(void);
uint32_t sniff_now_us(void);
#endif
