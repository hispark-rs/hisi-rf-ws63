//! Credential-free operation-level cancellation and timeout injection fixture.

#![no_std]
#![no_main]

use core::fmt;

use hisi_hal::Peripherals;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_core::Diagnostic;
use hisi_rf_ws63::firmware_diagnostic_fixtures;
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

fn emit(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, marker: &[u8], value: Diagnostic) {
    let mut json = JsonBuffer::new();
    value
        .write_json(&mut json)
        .expect("operation diagnostic JSON fits the fixed buffer");
    uart.write(marker);
    uart.write(json.bytes());
    uart.write(b"\r\n");
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

    let (cancelled, timeout) = firmware_diagnostic_fixtures::operation_error_injection()
        .expect("production operation injection reaches both terminal paths");
    emit(&uart, b"\r\nRFDBG_A5U_OPERATION_CANCEL_JSON ", cancelled);
    uart.write(b"RFDBG_A5U_OPERATION_CANCEL_OK code=");
    uart.write(cancelled.code().as_str().as_bytes());
    uart.write(b" stage=");
    uart.write(cancelled.stage().as_str().as_bytes());
    uart.write(b" action=");
    uart.write(cancelled.action().as_str().as_bytes());
    uart.write(b"\r\n");

    emit(&uart, b"RFDBG_A5U_OPERATION_TIMEOUT_JSON ", timeout);
    uart.write(b"RFDBG_A5U_OPERATION_TIMEOUT_OK code=");
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
