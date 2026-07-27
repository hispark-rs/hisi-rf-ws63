//! Credential-free WS63 incremental initialize/scan profiler.
//!
//! This HIL fixture completes the measured blocking bootstrap, then drives the
//! production incremental controller and WS63 wait platform through initialize
//! acknowledgement and one scan. It reports only bounded counters and timings;
//! SSIDs, BSSIDs, credentials, and frame contents are never emitted.

#![no_std]
#![no_main]

use core::cell::Cell;
use core::num::NonZeroU32;

use critical_section::Mutex;
use embassy_executor::{Executor, Spawner};
use embassy_time::{Duration, with_timeout};
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
use hisi_rf_core::{
    IncrementalDriverEvent, IncrementalRunnerDiagnostics, ScanConfig, ScanResult, WifiController,
    WorkBudget,
};
use hisi_rf_ws63::{
    IncrementalRadioParts, IncrementalRadioRunner, SelectedProfile, Storage,
    Ws63IncrementalWaitDiagnostics,
};
use hisi_riscv_rt::entry;
use static_cell::StaticCell;

const RADIO_EVENT_DEPTH: usize = 8;
const SCAN_RESULT_DEPTH: usize = 16;
const RUNNER_BUDGET: WorkBudget =
    WorkBudget::try_new(8, 10_000).expect("non-zero incremental work budget");

static RADIO_STORAGE: Storage<SelectedProfile, RADIO_EVENT_DEPTH> = Storage::new();
static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static UART: StaticCell<Uart<'static, hisi_hal::peripherals::Uart0<'static>>> = StaticCell::new();
static RADIO_PARTS: StaticCell<
    Result<IncrementalRadioParts<RADIO_EVENT_DEPTH>, hisi_rf_ws63::InitError>,
> = StaticCell::new();
static RUNNER_DIAGNOSTICS: Mutex<Cell<Option<IncrementalRunnerDiagnostics>>> =
    Mutex::new(Cell::new(None));
static WAIT_DIAGNOSTICS: Mutex<Cell<Option<Ws63IncrementalWaitDiagnostics>>> =
    Mutex::new(Cell::new(None));

#[entry]
fn main() -> ! {
    let p = Peripherals::take().expect("peripherals already taken");
    let uart = UART.init(Uart::new_uart0(
        p.UART0,
        UartConfig {
            clock: UartClock::Boot,
            ..UartConfig::default()
        },
    ));
    Watchdog::new(p.WDT).disable();
    uart.write(b"\r\nRFDBG_A5B_SCAN_BEGIN\r\n");

    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();
    uart.write(b"RFDBG_A5B_RF_POWER_OK\r\n");

    let _timer = TimerAlarm0::new(p.TIMER);
    let _software_interrupt = SoftwareInterrupt0::new(p.SYS_CTL1);
    let runtime = hisi_rtos::start_with_port(
        hisi_rtos::PortedConfig {
            radio_task_policy: hisi_rtos::RunPolicy::Cooperative,
            #[cfg(feature = "bootstrap-stage-diag")]
            max_scheduler_lock_duration: NonZeroU32::new(5_000).unwrap(),
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

    // The adopted main thread hosts Embassy's executor. Executor idle does not
    // call the RTOS yield contract, so let the timer preempt it and run vendor
    // workers that produce scan/result callbacks.
    let main_task = hisi_rf_rtos_driver::current_task().expect("adopted main task");
    runtime
        .set_task_run_policy(
            main_task,
            hisi_rtos::RunPolicy::Preemptive {
                time_slice: NonZeroU32::new(5).unwrap(),
            },
        )
        .expect("configure Embassy executor thread");

    unsafe { interrupt::enable_global() };
    hisi_rtos::request_reschedule();
    uart.write(b"RFDBG_A5B_RTOS_OK\r\n");

    let bootstrap_started = monotonic_ms();
    let parts = RADIO_PARTS.init_with(|| {
        hisi_rf_ws63::init_incremental_after_blocking_bootstrap(
            hisi_rf_core::RadioConfig::default(),
            hisi_rf_ws63::Resources::new(efuse, p.KM, p.SPACC, p.PKE, p.TRNG),
            &RADIO_STORAGE,
        )
        .map(|controller| controller.split(RUNNER_BUDGET))
    });
    let parts = match parts {
        Ok(parts) => parts,
        Err(error) => {
            uart.write(b"RFDBG_A5B_BOOTSTRAP_ERR code=");
            uart.write((*error).diagnostic().code().as_str().as_bytes());
            uart.write(b"\r\n");
            halt()
        }
    };
    write_metric(
        uart,
        b"RFDBG_A5B_BOOTSTRAP_OK elapsed_ms=0x",
        monotonic_ms().wrapping_sub(bootstrap_started),
    );

    start_executor(parts, uart)
}

// Keep executor construction out of the bootstrap frame. The vendor Wi-Fi
// initializer has a measured deep stack requirement; unrelated diagnostic
// futures must not consume that stack until the synchronous call has returned.
#[inline(never)]
fn start_executor(
    parts: &'static mut IncrementalRadioParts<RADIO_EVENT_DEPTH>,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) -> ! {
    let IncrementalRadioParts { wifi, runner } = parts;
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner: Spawner| {
        spawner.spawn(radio_runner(runner, uart).unwrap());
        spawner.spawn(scan_profile(&mut wifi.controller, uart).unwrap());
    })
}

#[embassy_executor::task]
async fn radio_runner(
    runner: &'static mut IncrementalRadioRunner<RADIO_EVENT_DEPTH>,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    loop {
        let ready = runner.wait_ready().await.expect("infallible WS63 wait");
        uart.write(b"RFDBG_A5B_RUNNER_WAKE ready=0x");
        uart.write(&hex8(u32::from(ready.bits())));
        uart.write(b"\r\n");
        let started = monotonic_ms();
        let event = runner.run_once(ready).expect("incremental runner");
        write_incremental_event(uart, event);
        write_metric(
            uart,
            b"RFDBG_A5B_RUNNER_ELAPSED_MS value=0x",
            monotonic_ms().wrapping_sub(started),
        );
        critical_section::with(|cs| {
            RUNNER_DIAGNOSTICS
                .borrow(cs)
                .set(Some(runner.diagnostics()));
            WAIT_DIAGNOSTICS
                .borrow(cs)
                .set(Some(runner.wait_diagnostics()));
        });
    }
}

#[embassy_executor::task]
async fn scan_profile(
    controller: &'static mut WifiController<RADIO_EVENT_DEPTH>,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    let initialize_started = monotonic_ms();
    match with_timeout(Duration::from_secs(30), controller.initialize()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            uart.write(b"RFDBG_A5B_INITIALIZE_ERR reason=backend\r\n");
            halt()
        }
        Err(_) => {
            uart.write(b"RFDBG_A5B_INITIALIZE_ERR reason=timeout\r\n");
            halt()
        }
    }
    write_metric(
        uart,
        b"RFDBG_A5B_INITIALIZE_OK elapsed_ms=0x",
        monotonic_ms().wrapping_sub(initialize_started),
    );

    let mut scan_results = [ScanResult::empty(); SCAN_RESULT_DEPTH];
    let scan_started = monotonic_ms();
    let outcome = match with_timeout(
        Duration::from_secs(30),
        controller.scan(
            ScanConfig::try_from_timeout_ms(15_000).expect("non-zero scan timeout"),
            &mut scan_results,
        ),
    )
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            let diagnostic = error.diagnostic();
            uart.write(b"RFDBG_A5B_SCAN_ERR code=");
            uart.write(diagnostic.code().as_str().as_bytes());
            uart.write(b" stage=");
            uart.write(diagnostic.stage().as_str().as_bytes());
            if let Some(code) = diagnostic.backend_code() {
                uart.write(b" backend=0x");
                uart.write(&hex8(code));
            }
            uart.write(b"\r\n");
            let trace = diagnostic.trace();
            for index in 0..trace.len() {
                let entry = trace.get(index).expect("bounded diagnostic trace");
                uart.write(b"RFDBG_A5B_SCAN_TRACE kind=");
                uart.write(entry.kind().as_str().as_bytes());
                uart.write(b" value=0x");
                uart.write(&hex8(entry.value()));
                uart.write(b"\r\n");
            }
            uart.write(b"RFDBG_A5B_SCAN_STATE values=");
            for value in hisi_rf_ws63::upstream_supplicant_scan_diagnostic_snapshot() {
                uart.write(&hex8(value));
                uart.write(b",");
            }
            uart.write(b"\r\n");
            halt()
        }
        Err(_) => {
            uart.write(b"RFDBG_A5B_SCAN_ERR reason=timeout\r\n");
            halt()
        }
    };
    uart.write(b"RFDBG_A5B_SCAN_OK elapsed_ms=0x");
    uart.write(&hex8(
        u32::try_from(monotonic_ms().wrapping_sub(scan_started)).unwrap_or(u32::MAX),
    ));
    uart.write(b" count=0x");
    uart.write(&hex8(u32::try_from(outcome.count).unwrap_or(u32::MAX)));
    uart.write(b" truncated=0x");
    uart.write(&hex8(u32::from(outcome.truncated)));
    uart.write(b"\r\n");

    let event = controller.event_diagnostics();
    uart.write(b"RFDBG_A5B_EVENT pending=0x");
    uart.write(&hex8(u32::try_from(event.pending).unwrap_or(u32::MAX)));
    uart.write(b" high_water=0x");
    uart.write(&hex8(u32::try_from(event.high_water).unwrap_or(u32::MAX)));
    uart.write(b" dropped=0x");
    uart.write(&hex8(event.dropped));
    uart.write(b"\r\n");

    let control = controller.blocking_runner_diagnostics();
    uart.write(b"RFDBG_A5B_CONTROL pending=0x");
    uart.write(&hex8(
        u32::try_from(control.command_queue_pending).unwrap_or(u32::MAX),
    ));
    uart.write(b" high_water=0x");
    uart.write(&hex8(
        u32::try_from(control.command_queue_high_water).unwrap_or(u32::MAX),
    ));
    uart.write(b"\r\n");

    let (runner, wait) = critical_section::with(|cs| {
        (
            RUNNER_DIAGNOSTICS.borrow(cs).get(),
            WAIT_DIAGNOSTICS.borrow(cs).get(),
        )
    });
    if let Some(diagnostics) = runner {
        write_runner_diagnostics(uart, diagnostics);
    } else {
        uart.write(b"RFDBG_A5B_RUNNER_ERR reason=missing_snapshot\r\n");
    }
    if let Some(diagnostics) = wait {
        write_wait_diagnostics(uart, diagnostics);
    } else {
        uart.write(b"RFDBG_A5B_WAIT_ERR reason=missing_snapshot\r\n");
    }

    let blocking = hisi_rf_ws63::blocking_backend_metrics();
    uart.write(b"RFDBG_A5B_BLOCKING init_calls=0x");
    uart.write(&hex8(blocking.initialize.calls));
    uart.write(b" init_max_ms=0x");
    uart.write(&hex8(blocking.initialize.max_elapsed_ms));
    uart.write(b" scan_calls=0x");
    uart.write(&hex8(blocking.scan.calls));
    uart.write(b" poll_calls=0x");
    uart.write(&hex8(blocking.poll.calls));
    uart.write(b" internal_sleep=0x");
    uart.write(&hex8(blocking.internal_sleep_calls));
    uart.write(b" supplicant_poll=0x");
    uart.write(&hex8(blocking.supplicant_poll_calls));
    uart.write(b"\r\nRFDBG_A5B_SCAN_PROFILE_OK\r\n");

    halt()
}

fn write_runner_diagnostics(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    diagnostics: IncrementalRunnerDiagnostics,
) {
    uart.write(b"RFDBG_A5B_RUNNER run=0x");
    uart.write(&hex8(diagnostics.run_once_calls));
    uart.write(b" waits=0x");
    uart.write(&hex8(diagnostics.wait_ready_calls));
    uart.write(b" wake=0x");
    uart.write(&hex8(diagnostics.wait_ready_completions));
    uart.write(b" immediate=0x");
    uart.write(&hex8(diagnostics.immediate_ready_completions));
    uart.write(b" operations=0x");
    uart.write(&hex8(diagnostics.operations_started));
    uart.write(b" completed=0x");
    uart.write(&hex8(diagnostics.operations_completed));
    uart.write(b" pending=0x");
    uart.write(&hex8(diagnostics.pending_polls));
    uart.write(b" exhausted=0x");
    uart.write(&hex8(diagnostics.budget_exhaustions));
    uart.write(b" errors=0x");
    uart.write(&hex8(
        diagnostics
            .driver_errors
            .saturating_add(diagnostics.protocol_errors)
            .saturating_add(diagnostics.wait_ready_errors),
    ));
    uart.write(b"\r\n");
}

fn write_wait_diagnostics(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    diagnostics: Ws63IncrementalWaitDiagnostics,
) {
    uart.write(b"RFDBG_A5B_WAIT backend=0x");
    uart.write(&hex8(diagnostics.backend_signals));
    uart.write(b" l2=0x");
    uart.write(&hex8(diagnostics.l2_rx_signals));
    uart.write(b" waker=0x");
    uart.write(&hex8(diagnostics.waker_notifications));
    uart.write(b" polls=0x");
    uart.write(&hex8(diagnostics.poll_calls));
    uart.write(b" pending=0x");
    uart.write(&hex8(diagnostics.pending_polls));
    uart.write(b" ready=0x");
    uart.write(&hex8(diagnostics.ready_polls));
    uart.write(b" timer=0x");
    uart.write(&hex8(diagnostics.timer_ready_polls));
    uart.write(b"\r\n");
}

fn write_metric(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, prefix: &[u8], value: u64) {
    uart.write(prefix);
    uart.write(&hex8(u32::try_from(value).unwrap_or(u32::MAX)));
    uart.write(b"\r\n");
}

fn write_incremental_event(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    event: IncrementalDriverEvent,
) {
    uart.write(b"RFDBG_A5B_RUNNER_EVENT kind=");
    match event {
        IncrementalDriverEvent::Idle => uart.write(b"idle"),
        IncrementalDriverEvent::Started { .. } => uart.write(b"started"),
        IncrementalDriverEvent::Waiting { wait_for, .. } => {
            uart.write(b"waiting wait=0x");
            uart.write(&hex8(u32::from(wait_for.bits())));
        }
        IncrementalDriverEvent::Pending {
            made_progress,
            wait_for,
            ..
        } => {
            uart.write(b"pending progress=0x");
            uart.write(&hex8(u32::from(made_progress)));
            uart.write(b" wait=0x");
            uart.write(&hex8(u32::from(wait_for.bits())));
        }
        IncrementalDriverEvent::BudgetExhausted {
            made_progress,
            wait_for,
            ..
        } => {
            uart.write(b"budget_exhausted progress=0x");
            uart.write(&hex8(u32::from(made_progress)));
            uart.write(b" wait=0x");
            uart.write(&hex8(u32::from(wait_for.bits())));
        }
        IncrementalDriverEvent::CancelRequested { .. } => uart.write(b"cancel_requested"),
        IncrementalDriverEvent::Completed { .. } => uart.write(b"completed"),
        IncrementalDriverEvent::Cancelled { .. } => uart.write(b"cancelled"),
        IncrementalDriverEvent::Failed { .. } => uart.write(b"failed"),
    }
    uart.write(b"\r\n");
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
    Instant::now().raw() / 24_000
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
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
