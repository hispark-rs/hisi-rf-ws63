//! Credential-free target fixture for caller-owned arena admission errors.

#![no_std]
#![no_main]

use core::fmt;

use hisi_hal::Peripherals;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_ws63::{RadioArenaStorage, SelectedProfile};
use hisi_riscv_rt::entry;

static INSUFFICIENT_ARENA: RadioArenaStorage<0> = RadioArenaStorage::new();

struct JsonBuffer {
    bytes: [u8; 512],
    len: usize,
}

impl JsonBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Write for JsonBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

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

    let error = match INSUFFICIENT_ARENA.claim_for::<SelectedProfile>() {
        Ok(_) => panic!("undersized arena was admitted"),
        Err(error) => error,
    };
    let diagnostic = error.diagnostic();
    let mut json = JsonBuffer::new();
    diagnostic
        .write_json(&mut json)
        .expect("diagnostic JSON fits the fixed buffer");

    uart.write(b"\r\nRFDBG_A5U_TYPED_ERROR_JSON ");
    uart.write(json.bytes());
    uart.write(b"\r\nRFDBG_A5U_TYPED_ERROR_OK code=");
    uart.write(diagnostic.code().as_str().as_bytes());
    uart.write(b" stage=");
    uart.write(diagnostic.stage().as_str().as_bytes());
    uart.write(b" action=");
    uart.write(diagnostic.action().as_str().as_bytes());
    uart.write(b"\r\n");

    loop {
        core::hint::spin_loop();
    }
}
