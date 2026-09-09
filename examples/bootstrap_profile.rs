//! Credential-free WS63 radio bootstrap profiler.
//!
//! The fixture executes the production composition root through native
//! supplicant construction, reports each blocking bootstrap stage, and then
//! stops. It deliberately performs no scan, association, or IP operation.

#![no_std]
#![no_main]

use core::num::NonZeroUsize;

use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::rf_power::RfPower;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_ws63::BootstrapStage;
use hisi_riscv_rt::entry;

#[cfg(feature = "standard-l2")]
#[path = "support/net0_storage.rs"]
mod net0_storage;
#[cfg(feature = "standard-l2")]
use net0_storage::{NET0_RTOS_ARENA as RTOS_ARENA, RADIO_STORAGE};

const RADIO_EVENT_DEPTH: usize = 8;
static RTOS_STORAGE: hisi_rtos::SchedulerStorage<15> = hisi_rtos::SchedulerStorage::new();
#[cfg(not(feature = "standard-l2"))]
#[unsafe(link_section = ".hisi.shared-arena")]
static RTOS_ARENA: hisi_rtos::SchedulerArena<{ hisi_rf_ws63::SELECTED_RUNTIME_ARENA_BYTES }> =
    hisi_rtos::SchedulerArena::new();

hisi_rtos::bind_interrupts!(struct RtosIrqs {
    TIMER_INT0 => hisi_rtos::ws63::TimerInterrupt;
    SOFT_INT0 => hisi_rtos::ws63::SoftwareInterrupt;
});
#[cfg(not(feature = "standard-l2"))]
hisi_rf_ws63::declare_radio_storage!(static RADIO_STORAGE, events = RADIO_EVENT_DEPTH);

#[entry]
fn main() -> ! {
    #[cfg(feature = "standard-l2")]
    net0_storage::retain_layout();
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

    let installed_storage = RADIO_STORAGE
        .install()
        .expect("install caller-owned radio storage");
    let scheduler_storage = RTOS_STORAGE
        .install(&RTOS_ARENA)
        .expect("install caller-owned scheduler storage");
    uart.write(b"RFDBG_A5U_ARENA_OK bytes=0x");
    uart.write(&hex8(hisi_rf_ws63::rf_heap_metrics().arena_bytes as u32));
    uart.write(b"\r\n");

    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();
    uart.write(b"RFDBG_RF_POWER_OK\r\n");

    let _runtime = hisi_rtos::ws63::start(
        hisi_rtos::ws63::Config {
            minimum_stack_size: NonZeroUsize::new(hisi_rf_ws63::SELECTED_MINIMUM_TASK_STACK_BYTES)
                .expect("selected minimum stack is non-zero"),
            radio_task_policy: hisi_rtos::RunPolicy::Cooperative,
            // UART stage tracing is intentionally synchronous and can extend
            // the vendor's bootstrap scheduler-lock interval. Keep the normal
            // runtime default at 100 ms; only this diagnostic fixture gets a
            // wider observation window.
            max_scheduler_lock_duration: if cfg!(feature = "bootstrap-stage-diag") {
                core::num::NonZeroU32::new(5_000).unwrap()
            } else {
                hisi_rtos::ws63::Config::default().max_scheduler_lock_duration
            },
        },
        hisi_rtos::ws63::Resources {
            timer: p.TIMER,
            software_interrupt: p.SYS_CTL1,
            storage: scheduler_storage,
            contract_violation: rtos_contract_violation,
            irqs: RtosIrqs::new(),
        },
    )
    .expect("start ported runtime");
    uart.write(b"RFDBG_RTOS_START_OK\r\n");

    uart.write(b"RFDBG_RTOS_IRQ_OK\r\n");
    hisi_rtos::request_reschedule();
    uart.write(b"RFDBG_RTOS_OK\r\n");

    let (control_storage, radio_arena) = installed_storage.into_init_parts();
    let resources =
        hisi_rf_ws63::Resources::<hisi_rf_ws63::SelectedProfile>::builder(efuse, radio_arena)
            .crypto(p.KM, p.SPACC, p.TRNG)
            .build();
    let result = hisi_rf_ws63::init_incremental(
        hisi_rf_core::RadioConfig::default(),
        resources,
        control_storage,
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
        Ok(_controller) => {
            uart.write(b"RFDBG_BOOTSTRAP_PROFILE_OK\r\n");
            let report = RADIO_STORAGE.report();
            let diagnostics = hisi_rtos::diagnostics();
            uart.write(b"A5U_TASK_STACK_ADMISSION_OK bytes=0x");
            uart.write(&hex8(report.task_stack_bytes.unwrap_or(0) as u32));
            uart.write(b" reserved=0x");
            uart.write(&hex8(u32::from(diagnostics.dynamic_reserved)));
            uart.write(b"\r\n");
        }
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
