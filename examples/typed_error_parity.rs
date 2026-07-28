//! Credential-free target fixture for generic typed-error serialization parity.

#![no_std]
#![no_main]

use core::fmt;

use hisi_hal::Peripherals;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_core::{BackendError, BackendErrorClass, Error};
use hisi_riscv_rt::entry;

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

    let cancelled = Error::Backend(BackendError::new(BackendErrorClass::Cancelled, 0)).diagnostic();
    let mut cancelled_json = JsonBuffer::new();
    cancelled
        .write_json(&mut cancelled_json)
        .expect("cancelled diagnostic JSON fits the fixed buffer");
    uart.write(b"\r\nRFDBG_A5U_CANCEL_JSON ");
    uart.write(cancelled_json.bytes());
    uart.write(b"\r\nRFDBG_A5U_CANCEL_OK code=");
    uart.write(cancelled.code().as_str().as_bytes());
    uart.write(b" stage=");
    uart.write(cancelled.stage().as_str().as_bytes());
    uart.write(b" action=");
    uart.write(cancelled.action().as_str().as_bytes());

    let timeout = Error::Backend(BackendError::new(BackendErrorClass::Timeout, 7)).diagnostic();
    let mut timeout_json = JsonBuffer::new();
    timeout
        .write_json(&mut timeout_json)
        .expect("timeout diagnostic JSON fits the fixed buffer");
    uart.write(b"\r\nRFDBG_A5U_BACKEND_TIMEOUT_JSON ");
    uart.write(timeout_json.bytes());
    uart.write(b"\r\nRFDBG_A5U_BACKEND_TIMEOUT_OK code=");
    uart.write(timeout.code().as_str().as_bytes());
    uart.write(b" stage=");
    uart.write(timeout.stage().as_str().as_bytes());
    uart.write(b" action=");
    uart.write(timeout.action().as_str().as_bytes());
    uart.write(b"\r\n");

    loop {
        core::hint::spin_loop();
    }
}
