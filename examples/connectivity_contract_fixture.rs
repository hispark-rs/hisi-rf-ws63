//! Credential-free QEMU fixture for the connectivity marker contract.
//!
//! This image exercises target startup, UART serialization and the shared host
//! parser. It does not initialize RF hardware and is never valid silicon
//! connectivity evidence; the dedicated fixture marker makes that boundary
//! machine-checkable.

#![no_std]
#![no_main]

use hisi_hal::Peripherals;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_riscv_rt::entry;

#[entry]
fn main() -> ! {
    let p = Peripherals::take().expect("peripherals already taken");
    let uart = Uart::new_uart0(
        p.UART0,
        UartConfig {
            clock: UartClock::Boot,
            ..UartConfig::default()
        },
    );
    Watchdog::new(p.WDT).disable();

    uart.write(b"\r\nRFDBG_CONNECTIVITY_CONTRACT_FIXTURE scope=contract-only\r\n");
    uart.write(b"RF1_IMAGE_OK\r\n");
    uart.write(b"RF2_INIT_OK ifname=hisi-rf\r\n");
    uart.write(b"A4_RADIO_EVENT kind=initialized\r\n");
    uart.write(b"RF3_SCAN_OK count=0x00000001 truncated=0x00000000\r\n");
    uart.write(b"A4_RADIO_EVENT kind=scan-completed\r\n");
    uart.write(b"W2D_WPA2_CONNECT_OK\r\n");
    uart.write(b"A4_RADIO_EVENT kind=connected\r\n");
    uart.write(b"RF5A_DHCP_OK addr=192.0.2.2\r\n");
    uart.write(b"RF5A_ARP_OK evidence=l2-arp-reply\r\n");
    uart.write(
        b"RF5C_LOCAL_DATA_PATH_OK arp_reply=0x00000001 \
arp_request=0x00000001 gateway=192.0.2.1\r\n",
    );
    uart.write(
        b"RF5C_PUBLIC_DNS_BEGIN primary=223.5.5.5 secondary=180.76.76.76 \
attempts=0x00000004\r\n",
    );
    uart.write(
        b"RF5C_PUBLIC_DNS_SAMPLE attempt=0x00000001 txid=0x00005754 \
target=223.5.5.5 status=ok answers=0x00000001\r\n",
    );
    uart.write(
        b"RF5C_PUBLIC_DNS_OK target=223.5.5.5 attempts=0x00000001 \
responses=0x00000001 invalid=0x00000000 tx_error=0x00000000\r\n",
    );
    uart.write(
        b"RF5C_CONNECTIVITY_SUMMARY arp_request=0x00000001 \
arp_reply=0x00000001 dns_attempts=0x00000001 dns_responses=0x00000001 \
dns_invalid=0x00000000 dns_tx_error=0x00000000 rx_queue_drop=0x00000000\r\n",
    );
    uart.write(b"A4_NET_RUNNER_STEADY lease=managed neighbor_cache=managed\r\n");
    uart.write(b"A4_DHCP_RENEW_OK client=0x00000001 server=0x00000001\r\n");
    uart.write(b"RFDBG_CONNECTIVITY_CONTRACT_FIXTURE_OK\r\n");

    loop {
        core::hint::spin_loop();
    }
}
