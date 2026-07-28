//! WS63 incremental initialize/scan profiler.
//!
//! This HIL fixture completes the measured blocking bootstrap, then drives the
//! production incremental controller and WS63 wait platform through initialize
//! acknowledgement and one scan. It reports only bounded counters and timings;
//! SSIDs, BSSIDs, credentials, and frame contents are never emitted. The
//! optional `incremental-connect-profile` extends the same image through one
//! association and disconnect using compile-time environment credentials.

#![no_std]
#![no_main]

use core::cell::Cell;
use core::num::NonZeroU32;

use critical_section::Mutex;
use embassy_executor::{Executor, Spawner};
use embassy_time::{Duration, Timer, with_timeout};
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
use hisi_rf_core::DiagnosticCode;
#[cfg(all(feature = "incremental-connect-profile", feature = "wpa3-personal"))]
use hisi_rf_core::SaePwe;
use hisi_rf_core::{
    IncrementalDriverEvent, IncrementalRunnerDiagnostics, ScanConfig, ScanResult, WifiController,
    WorkBudget,
};
#[cfg(feature = "incremental-connect-profile")]
use hisi_rf_core::{Passphrase, Security, StationConfig};
use hisi_rf_ws63::{
    IncrementalRadioParts, IncrementalRadioRunner, InstalledRadioArena, SelectedProfile, Storage,
    Ws63IncrementalWaitDiagnostics, declare_radio_arena,
};
use hisi_riscv_rt::entry;
use static_cell::StaticCell;

const RADIO_EVENT_DEPTH: usize = 8;
const SCAN_RESULT_DEPTH: usize = 32;
#[cfg(not(feature = "incremental-connect-profile"))]
const RUNNER_BUDGET: WorkBudget =
    WorkBudget::try_new(8, 10_000).expect("non-zero incremental work budget");
// The association ioctl timing probe measured a 40 ms maximum across a
// transition-mode 10-reset matrix, including status-30 and first-EAPOL
// recovery. Keep a conservative 100 ms fixture budget while the remaining
// synchronous hostap callbacks are split into smaller steps.
#[cfg(feature = "incremental-connect-profile")]
const RUNNER_BUDGET: WorkBudget =
    WorkBudget::try_new(8, 100_000).expect("non-zero incremental work budget");

#[cfg(all(
    feature = "incremental-connect-profile",
    not(any(feature = "wpa2-personal", feature = "wpa3-personal"))
))]
compile_error!("incremental-connect-profile requires wpa2-personal or wpa3-personal");
#[cfg(all(
    feature = "incremental-connect-profile",
    feature = "wpa2-personal",
    feature = "wpa3-personal"
))]
compile_error!("incremental-connect-profile requires exactly one WPA profile");

#[cfg(feature = "incremental-connect-profile")]
const TEST_SSID: &[u8] = match option_env!("WS63_WIFI_SSID") {
    Some(value) => value.as_bytes(),
    None => b"",
};
#[cfg(feature = "incremental-connect-profile")]
const TEST_PASSPHRASE: &[u8] = match option_env!("WS63_WIFI_PASSPHRASE") {
    Some(value) => value.as_bytes(),
    None => b"",
};

static RADIO_STORAGE: Storage<SelectedProfile, RADIO_EVENT_DEPTH> = Storage::new();
declare_radio_arena!(static RADIO_ARENA);
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

    let radio_arena = RADIO_ARENA
        .claim_for::<SelectedProfile>()
        .and_then(|arena| arena.install())
        .expect("install shared RF arena");

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
    let resources =
        hisi_rf_ws63::Resources::<hisi_rf_ws63::SelectedProfile>::builder(efuse, radio_arena)
            .crypto(p.KM, p.SPACC, p.TRNG);
    #[cfg(feature = "wpa2-personal")]
    let resources = resources.build();
    #[cfg(feature = "wpa3-personal")]
    let resources = resources.pke(p.PKE).build();
    let parts = RADIO_PARTS.init_with(|| {
        hisi_rf_ws63::init_incremental_after_blocking_bootstrap(
            hisi_rf_core::RadioConfig::default(),
            resources,
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
    let mut scan_attempt = 0_u8;
    #[cfg(feature = "incremental-connect-profile")]
    let mut missing_ap_retry = false;
    let outcome = loop {
        match with_timeout(
            Duration::from_secs(30),
            controller.scan(
                ScanConfig::try_from_timeout_ms(15_000).expect("non-zero scan timeout"),
                &mut scan_results,
            ),
        )
        .await
        {
            Ok(Ok(outcome)) => {
                #[cfg(feature = "incremental-connect-profile")]
                if !missing_ap_retry
                    && !scan_results[..outcome.count]
                        .iter()
                        .any(|result| result.ssid.as_bytes() == TEST_SSID)
                {
                    uart.write(b"RFDBG_A5B_SCAN_RETRY reason=ap_not_found\r\n");
                    missing_ap_retry = true;
                    Timer::after(Duration::from_millis(250)).await;
                    continue;
                }
                break outcome;
            }
            Ok(Err(error))
                if scan_attempt == 0
                    && error.diagnostic().code() == DiagnosticCode::BackendTimeout =>
            {
                uart.write(b"RFDBG_A5B_SCAN_RETRY reason=backend_timeout\r\n");
                write_scan_diagnostics(uart, b"RFDBG_A5B_SCAN_RETRY");
                scan_attempt = 1;
                // `wal_force_scan_complete()` stops the active firmware scan,
                // but its completion cleanup is asynchronous. Do not race a
                // replacement scan against the old transaction.
                Timer::after(Duration::from_millis(250)).await;
            }
            Ok(Err(error)) => {
                write_controller_error(uart, b"RFDBG_A5B_SCAN_ERR", error);
                write_scan_diagnostics(uart, b"RFDBG_A5B_SCAN_STATE");
                halt()
            }
            Err(_) => {
                uart.write(b"RFDBG_A5B_SCAN_ERR reason=outer_timeout\r\n");
                write_scan_diagnostics(uart, b"RFDBG_A5B_SCAN_STATE");
                halt()
            }
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

    #[cfg(feature = "incremental-connect-profile")]
    run_connect_profile(controller, uart, &scan_results[..outcome.count]).await;

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
    #[cfg(not(feature = "incremental-connect-profile"))]
    uart.write(b"\r\nRFDBG_A5B_SCAN_PROFILE_OK\r\n");
    #[cfg(feature = "incremental-connect-profile")]
    uart.write(b"\r\nRFDBG_A5B_CONNECT_PROFILE_OK\r\n");

    halt()
}

fn write_scan_diagnostics(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, prefix: &[u8]) {
    write_snapshot(
        uart,
        prefix,
        &hisi_rf_ws63::upstream_supplicant_scan_diagnostic_snapshot(),
    );
}

#[cfg(feature = "incremental-connect-profile")]
async fn run_connect_profile(
    controller: &mut WifiController<RADIO_EVENT_DEPTH>,
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    scan_results: &[ScanResult],
) {
    let Some(result) = scan_results
        .iter()
        .find(|result| result.ssid.as_bytes() == TEST_SSID)
    else {
        uart.write(b"RFDBG_A5B_CONNECT_ERR reason=ap_not_found\r\n");
        halt()
    };
    match result.security {
        Security::Wpa3Personal => uart.write(b"W2E_AP_SECURITY mode=pure-wpa3\r\n"),
        Security::Wpa2Wpa3PersonalTransition => {
            uart.write(b"W2E_AP_SECURITY mode=transition\r\n");
        }
        _ => {}
    }
    let Some(passphrase) = Passphrase::try_from_ascii(TEST_PASSPHRASE) else {
        uart.write(b"RFDBG_A5B_CONNECT_ERR reason=invalid_credentials\r\n");
        halt()
    };
    #[cfg(feature = "wpa2-personal")]
    let config = StationConfig::wpa2_personal(result, passphrase, 60_000);
    #[cfg(feature = "wpa3-personal")]
    let config = StationConfig::wpa3_personal(result, passphrase, SaePwe::Both, 60_000);
    let Some(config) = config else {
        uart.write(b"RFDBG_A5B_CONNECT_ERR reason=security_mismatch\r\n");
        halt()
    };

    let connect_started = monotonic_ms();
    match with_timeout(Duration::from_secs(90), controller.connect(config)).await {
        Ok(Ok(_)) => {
            write_metric(
                uart,
                b"RFDBG_A5B_CONNECT_OK elapsed_ms=0x",
                monotonic_ms().wrapping_sub(connect_started),
            );
            write_connect_diagnostics(uart);
            write_heap_metrics(uart, b"RFDBG_A5U_HEAP_CONNECTED");
        }
        Ok(Err(error)) => {
            write_controller_error(uart, b"RFDBG_A5B_CONNECT_ERR", error);
            write_connect_diagnostics(uart);
            write_heap_metrics(uart, b"RFDBG_A5U_HEAP_CONNECT_FAILED");
            halt()
        }
        Err(_) => {
            uart.write(b"RFDBG_A5B_CONNECT_ERR reason=outer_timeout\r\n");
            write_connect_diagnostics(uart);
            write_heap_metrics(uart, b"RFDBG_A5U_HEAP_CONNECT_FAILED");
            halt()
        }
    }

    let disconnect_started = monotonic_ms();
    match with_timeout(Duration::from_secs(20), controller.disconnect()).await {
        Ok(Ok(())) => {
            write_metric(
                uart,
                b"RFDBG_A5B_DISCONNECT_OK elapsed_ms=0x",
                monotonic_ms().wrapping_sub(disconnect_started),
            );
            write_heap_metrics(uart, b"RFDBG_A5U_HEAP_DISCONNECTED");
        }
        Ok(Err(error)) => {
            write_controller_error(uart, b"RFDBG_A5B_DISCONNECT_ERR", error);
            halt()
        }
        Err(_) => {
            uart.write(b"RFDBG_A5B_DISCONNECT_ERR reason=outer_timeout\r\n");
            halt()
        }
    }
}

#[cfg(feature = "incremental-connect-profile")]
fn write_heap_metrics(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, prefix: &[u8]) {
    let metrics = hisi_rf_ws63::rf_heap_metrics();
    uart.write(prefix);
    uart.write(b" arena=0x");
    uart.write(&hex8(metrics.arena_bytes.min(u32::MAX as usize) as u32));
    uart.write(b" used=0x");
    uart.write(&hex8(metrics.used_bytes.min(u32::MAX as usize) as u32));
    uart.write(b" peak=0x");
    uart.write(&hex8(metrics.peak_used_bytes.min(u32::MAX as usize) as u32));
    uart.write(b" live=0x");
    uart.write(&hex8(metrics.live_allocations.min(u32::MAX as usize) as u32));
    uart.write(b" peak_live=0x");
    uart.write(&hex8(
        metrics.peak_live_allocations.min(u32::MAX as usize) as u32
    ));
    uart.write(b" alloc_fail=0x");
    uart.write(&hex8(
        metrics.allocation_failures.min(u32::MAX as usize) as u32
    ));
    uart.write(b" free_fail=0x");
    uart.write(&hex8(
        metrics.deallocation_failures.min(u32::MAX as usize) as u32
    ));
    uart.write(b"\r\n");
}

#[cfg(feature = "incremental-connect-profile")]
fn write_connect_diagnostics(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>) {
    let recovery = hisi_rf_ws63::upstream_supplicant_recovery_diagnostic_word();
    let recovery_reconnect = hisi_rf_ws63::incremental_reconnect_diagnostic_snapshot();
    let temporary_reject =
        hisi_rf_ws63::upstream_supplicant_temporary_reject_recovery_diagnostic_snapshot();
    let native = hisi_rf_ws63::upstream_supplicant_diagnostic_snapshot();
    let association_ioctl =
        hisi_rf_ws63::upstream_supplicant_association_ioctl_diagnostic_snapshot();
    let external_auth_retry =
        hisi_rf_ws63::upstream_supplicant_external_auth_retry_diagnostic_snapshot();
    let event = hisi_rf_ws63::upstream_supplicant_event_diagnostic_snapshot();
    let authentication_raw = hisi_rf_ws63::upstream_supplicant_authentication_diagnostic_snapshot();
    let authentication = hisi_rf_ws63::upstream_supplicant_authentication_progress_snapshot();
    let eapol = hisi_rf_ws63::upstream_supplicant_eapol_diagnostic_snapshot();

    uart.write(b"RFDBG_A5B_CONNECT_DIAG recovery=0x");
    uart.write(&hex8(recovery));
    uart.write(b" temp_clears=0x");
    uart.write(&hex8(temporary_reject[0]));
    uart.write(b" temp_failures=0x");
    uart.write(&hex8(temporary_reject[1]));
    uart.write(b" temp_status=0x");
    uart.write(&hex8(temporary_reject[2]));
    uart.write(b" retry=0x");
    uart.write(&hex8(temporary_reject[3]));
    uart.write(b"\r\n");
    uart.write(b"RFDBG_A5B_CONNECT_RECOVERY_RECONNECT first_eapol=0x");
    uart.write(&hex8(recovery_reconnect[0]));
    uart.write(b" external_auth=0x");
    uart.write(&hex8(recovery_reconnect[1]));
    uart.write(b"\r\n");

    write_snapshot(uart, b"RFDBG_A5B_CONNECT_NATIVE", &native);
    write_snapshot(uart, b"RFDBG_A5B_CONNECT_ASSOC_IOCTL", &association_ioctl);
    write_snapshot(
        uart,
        b"RFDBG_A5B_CONNECT_EXT_AUTH_RETRY",
        &external_auth_retry,
    );
    write_snapshot(uart, b"RFDBG_A5B_CONNECT_EVENT", &event);
    write_snapshot(uart, b"RFDBG_A5B_CONNECT_AUTH_RAW", &authentication_raw);
    write_snapshot(uart, b"RFDBG_A5B_CONNECT_AUTH", &authentication);
    write_snapshot(uart, b"RFDBG_A5B_CONNECT_EAPOL", &eapol);

    let mut attempts = [hisi_rf_ws63::AssociationAttemptDiagnostic::default(); 8];
    let count = hisi_rf_ws63::upstream_supplicant_association_attempt_diagnostics(&mut attempts);
    for attempt in &attempts[..count] {
        uart.write(b"RFDBG_A5B_CONNECT_ASSOC seq=0x");
        uart.write(&hex8(attempt.sequence));
        uart.write(b" ms=0x");
        uart.write(&hex8(attempt.timestamp_ms));
        uart.write(b" raw=0x");
        uart.write(&hex8(attempt.raw_status));
        uart.write(b" status=0x");
        uart.write(&hex8(attempt.status));
        uart.write(b" ie_len=0x");
        uart.write(&hex8(attempt.response_ie_len));
        uart.write(b" comeback_tu=0x");
        uart.write(&hex8(attempt.comeback_tu));
        uart.write(b"\r\n");
    }
}

fn write_snapshot(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    prefix: &[u8],
    values: &[u32],
) {
    uart.write(prefix);
    for value in values {
        uart.write(b" 0x");
        uart.write(&hex8(*value));
    }
    uart.write(b"\r\n");
}

fn write_controller_error(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    prefix: &[u8],
    error: hisi_rf_core::Error,
) {
    let diagnostic = error.diagnostic();
    uart.write(prefix);
    uart.write(b" code=");
    uart.write(diagnostic.code().as_str().as_bytes());
    uart.write(b" stage=");
    uart.write(diagnostic.stage().as_str().as_bytes());
    if let Some(code) = diagnostic.backend_code() {
        uart.write(b" backend=0x");
        uart.write(&hex8(code));
    }
    uart.write(b"\r\n");
    for index in 0..diagnostic.trace().len() {
        let entry = diagnostic
            .trace()
            .get(index)
            .expect("bounded diagnostic trace");
        uart.write(prefix);
        uart.write(b"_TRACE kind=");
        uart.write(entry.kind().as_str().as_bytes());
        uart.write(b" value=0x");
        uart.write(&hex8(entry.value()));
        uart.write(b"\r\n");
    }
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
    // SAFETY: hisi-rtos releases this allocation through `rtos_deallocate`.
    unsafe { InstalledRadioArena::<SelectedProfile>::allocate(size) }
}

unsafe fn rtos_deallocate(pointer: *mut u8) {
    // SAFETY: hisi-rtos returns only pointers produced by `rtos_allocate`.
    unsafe { InstalledRadioArena::<SelectedProfile>::deallocate(pointer) };
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
