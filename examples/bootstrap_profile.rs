//! Credential-free WS63 radio bootstrap profiler.
//!
//! The fixture executes the production composition root through native
//! supplicant construction, reports each blocking bootstrap stage, and then
//! stops. It deliberately performs no scan, association, or IP operation.

#![no_std]
#![no_main]

use core::num::NonZeroU32;

use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::interrupt;
use hisi_hal::rf_power::RfPower;
use hisi_hal::software_interrupt::SoftwareInterrupt0;
use hisi_hal::time::Instant;
use hisi_hal::timer::TimerAlarm0;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_ws63::{BootstrapStage, SelectedProfile, Storage};
use hisi_riscv_rt::entry;

const RADIO_EVENT_DEPTH: usize = 8;
static RADIO_STORAGE: Storage<SelectedProfile, RADIO_EVENT_DEPTH> = Storage::new();

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
    uart.write(b"\r\nRFDBG_BOOTSTRAP_PROFILE_BEGIN\r\n");

    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();
    uart.write(b"RFDBG_RF_POWER_OK\r\n");

    let _timer = TimerAlarm0::new(p.TIMER);
    let _software_interrupt = SoftwareInterrupt0::new(p.SYS_CTL1);
    let _runtime = hisi_rtos::start_with_port(
        hisi_rtos::PortedConfig {
            radio_task_policy: hisi_rtos::RunPolicy::Cooperative,
            ..hisi_rtos::PortedConfig::default()
        },
        hisi_rtos::Resources {
            allocate: rtos_allocate,
            deallocate: rtos_deallocate,
            monotonic_ms,
        },
        hisi_rtos::SchedulerPort {
            max_timer_delay: NonZeroU32::new(TimerAlarm0::MAX_DELAY_MS)
                .expect("timer maximum delay must be non-zero"),
            arm_timer: TimerAlarm0::arm_millis,
            disarm_timer: TimerAlarm0::disarm,
            pend_reschedule: SoftwareInterrupt0::pend_interrupt,
            contract_violation: rtos_contract_violation,
        },
    )
    .expect("start ported runtime");

    unsafe { interrupt::enable_global() };
    hisi_rtos::request_reschedule();
    uart.write(b"RFDBG_RTOS_OK\r\n");

    let result = hisi_rf_ws63::init_incremental_after_blocking_bootstrap(
        hisi_rf_core::RadioConfig::default(),
        hisi_rf_ws63::Resources::new(efuse, p.KM, p.SPACC, p.PKE, p.TRNG),
        &RADIO_STORAGE,
    );

    let bootstrap = hisi_rf_ws63::blocking_backend_metrics().bootstrap;
    for stage in BootstrapStage::ALL {
        let metrics = bootstrap.stage(stage);
        uart.write(b"RFDBG_BOOT_STAGE name=");
        uart.write(stage.as_str().as_bytes());
        uart.write(b" calls=0x");
        uart.write(&hex8(metrics.calls));
        uart.write(b" completed=0x");
        uart.write(&hex8(metrics.completed_calls));
        uart.write(b" failed=0x");
        uart.write(&hex8(metrics.failed_calls));
        uart.write(b" timed=0x");
        uart.write(&hex8(metrics.timed_calls));
        uart.write(b" max_ms=0x");
        uart.write(&hex8(metrics.max_elapsed_ms));
        uart.write(b"\r\n");
    }

    match result {
        Ok(_controller) => uart.write(b"RFDBG_BOOTSTRAP_PROFILE_OK\r\n"),
        Err(error) => {
            let diagnostic = error.diagnostic();
            uart.write(b"RFDBG_BOOTSTRAP_PROFILE_ERR code=");
            uart.write(diagnostic.code().as_str().as_bytes());
            uart.write(b" stage=");
            uart.write(diagnostic.stage().as_str().as_bytes());
            if let Some(code) = diagnostic.backend_code() {
                uart.write(b" backend=0x");
                uart.write(&hex8(code));
            }
            uart.write(b"\r\n");
        }
    }

    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn TIMER_INT0() {
    TimerAlarm0::clear_interrupt();
    hisi_rtos::interrupt_enter();
    hisi_rtos::on_timer_interrupt();
    hisi_rtos::interrupt_exit();
}

#[unsafe(no_mangle)]
extern "C" fn SOFT_INT0() {
    SoftwareInterrupt0::clear_interrupt();
    hisi_rtos::interrupt_enter();
    hisi_rtos::on_software_interrupt();
    hisi_rtos::interrupt_exit();
}

unsafe fn rtos_allocate(size: usize) -> *mut u8 {
    hisi_rf_ws63::alloc::osal_kmalloc(size).cast()
}

unsafe fn rtos_deallocate(pointer: *mut u8) {
    hisi_rf_ws63::alloc::osal_kfree(pointer.cast());
}

fn monotonic_ms() -> u64 {
    // The RF ROM timebase is initialized by a later measured bootstrap stage.
    // TIMER0 needs a clock before that stage, so use the always-on 24 MHz TCXO.
    Instant::now().raw() / 24_000
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}

fn hex8(value: u32) -> [u8; 8] {
    let mut output = [0_u8; 8];
    for (index, digit) in output.iter_mut().enumerate() {
        let nibble = ((value >> ((7 - index) * 4)) & 0xf) as u8;
        *digit = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    output
}
