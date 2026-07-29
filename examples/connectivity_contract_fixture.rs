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
    uart.write(b"RF5A_ARP_OK mode=smoltcp-neighbor-cache\r\n");
    uart.write(
        b"RF5C_PING_OK target=223.5.5.5 tx=0x00000005 rx=0x00000000 \
drop=0x00000000 tx_error=0x00000000 rx_queue_drop=0x00000000\r\n",
    );
    uart.write(b"RF5C_LOCAL_DATA_PATH_OK gateway_rx=0x00000001 gateway_tx=0x00000005\r\n");
    uart.write(
        b"RF5C_PUBLIC_ICMP_OBSERVED target=223.5.5.5 tx=0x00000005 \
rx=0x00000000 loss=0x00000005\r\n",
    );
    uart.write(
        b"RF5C_CONNECTIVITY_SUMMARY gateway_tx=0x00000005 \
gateway_rx=0x00000001 public_tx=0x00000005 public_rx=0x00000000 \
rx_queue_drop=0x00000000\r\n",
    );
    uart.write(b"A4_NET_RUNNER_STEADY lease=managed neighbor_cache=managed\r\n");
    uart.write(b"A4_DHCP_RENEW_OK client=0x00000001 server=0x00000001\r\n");
    uart.write(b"RFDBG_CONNECTIVITY_CONTRACT_FIXTURE_OK\r\n");

    loop {
        core::hint::spin_loop();
    }
}
