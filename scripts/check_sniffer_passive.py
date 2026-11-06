#!/usr/bin/env python3
"""Fail closed if the sniffer gains a radio TX path or links fleet code."""
import argparse
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check(build):
    cmake = (ROOT / 'sniffer/CMakeLists.txt').read_text()
    assert 'target_sources(app PRIVATE main.c radio.c core.c)' in cmake
    source = '\n'.join((ROOT / 'sniffer' / name).read_text() for name in ('main.c', 'radio.c', 'core.c'))
    # Strip comments before looking for actual task/shortcut uses.
    code = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    assert not re.search(r'\b(?:esb_\w+|mpsl_\w+|TXEN|TXPOWER)\b', code)
    tasks = set(re.findall(r'NRF_RADIO->TASKS_(\w+)\s*=', code))
    assert tasks == {'RXEN', 'START', 'DISABLE', 'RSSISTOP'}, tasks
    shorts = set(re.findall(r'RADIO_SHORTS_(\w+)_Msk', code))
    assert shorts == {'READY_START', 'ADDRESS_RSSISTART'}, shorts
    # Every PPI task endpoint goes to timer capture, no radio task or fork.
    endpoints = re.findall(r'NRF_PPI->CH\[\d+\]\.TEP\s*=\s*([^;]+);', code)
    assert len(endpoints) == 2
    assert all(re.fullmatch(r'\(uint32_t\)&NRF_TIMER2->TASKS_CAPTURE\[[01]\]', e) for e in endpoints)
    forks = re.findall(r'NRF_PPI->FORK\[\d+\]\.TEP\s*=\s*([^;]+);', code)
    assert forks == ['0', '0']
    assert 'NRF_PPI->CHENCLR = UINT32_MAX' in code
    assert 'gpio_pin_configure_dt(&pa, GPIO_OUTPUT_INACTIVE)' in code
    assert 'gpio_pin_set' not in code
    config = (build / 'zephyr/.config').read_text()
    for option in ('ESB', 'MPSL', 'MPSL_FEM', 'BT', 'USBD_HID_SUPPORT', 'UART_CONSOLE',
                   'SHELL', 'SETTINGS', 'NRFX_PPI', 'NRFX_GPPI', 'NRFX_TIMER2',
                   'NRF_RTC_TIMER_TRIGGER_OVERFLOW', 'USBD_CDC_ACM_CLASS'):
        assert f'CONFIG_{option}=y' not in config, option
    for node in ('app/libapp.a', 'zephyr/zephyr.elf', 'zephyr/zephyr.hex'):
        assert (build / node).exists(), node
    link_map = (build / 'zephyr/zephyr.map').read_text()
    for forbidden in ('esb_init', 'esb_start_tx', 'esb_write_payload', 'mpsl_init',
                      'relay_coord_init', 'receiver_usb_init', 'bt_enable'):
        assert forbidden not in link_map, forbidden
    print('PASS: only RXEN/START/DISABLE/RSSISTOP; two capture-only PPI endpoints; RX-only shorts; PA low')
    print('PASS: linked image excludes ESB, ACK engine, MPSL, Bluetooth, HID, settings and receiver/coordinator code')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=pathlib.Path)
    check(parser.parse_args().build)
