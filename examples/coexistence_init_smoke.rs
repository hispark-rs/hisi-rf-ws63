use core::num::{NonZeroU32, NonZeroUsize};
#[cfg(feature = "coexistence-wifi-ble")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "coexistence-wifi-ble")]
use embassy_executor::{Executor, Spawner};
#[cfg(feature = "coexistence-wifi-ble")]
use embassy_time::{Duration, Timer, with_timeout};
use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::rf_power::RfPower;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
#[cfg(feature = "coexistence-wifi-ble")]
use hisi_rf_core::{ScanConfig, ScanResult, WifiController, WorkBudget};
use hisi_rf_ws63::declare_radio_storage;
#[cfg(feature = "coexistence-wifi-ble")]
use hisi_rf_ws63::{IncrementalRadioParts, IncrementalRadioRunner};
use hisi_riscv_rt::entry;
use static_cell::StaticCell;

const EVENT_DEPTH: usize = 8;
#[cfg(feature = "coexistence-wifi-ble")]
const SCAN_RESULT_DEPTH: usize = 32;
#[cfg(feature = "coexistence-wifi-ble")]
const COEX_SCAN_ROUNDS: u8 = 3;
#[cfg(feature = "coexistence-wifi-ble")]
const RUNNER_BUDGET: WorkBudget =
    WorkBudget::try_new(8, 10_000).expect("non-zero coexistence work budget");
#[cfg(feature = "coexistence-wifi-ble")]
static BLE_ADVERTISING_DATA: &[u8] = &[
    2, 0x01, 0x06, 9, 0x09, b'H', b'I', b'S', b'I', b'C', b'O', b'E', b'X',
];

declare_radio_storage!(static RADIO_STORAGE, events = EVENT_DEPTH);
static RTOS_STORAGE: hisi_rtos::SchedulerStorage<15> = hisi_rtos::SchedulerStorage::new();
#[cfg_attr(target_arch = "riscv32", unsafe(link_section = ".hisi.shared-arena"))]
static RTOS_ARENA: hisi_rtos::SchedulerArena<{ hisi_rf_ws63::SELECTED_RUNTIME_ARENA_BYTES }> =
    hisi_rtos::SchedulerArena::new();
static UART: StaticCell<Uart<'static, hisi_hal::peripherals::Uart0<'static>>> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-ble")]
static EXECUTOR: StaticCell<Executor> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-ble")]
static WIFI_PARTS: StaticCell<IncrementalRadioParts<EVENT_DEPTH>> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-ble")]
static BLE_CONTROLLER: StaticCell<hisi_rf_ws63::BleB1Controller> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-ble")]
static BLE_ADVERTISING_ACTIVE: AtomicBool = AtomicBool::new(false);

hisi_rtos::bind_interrupts!(struct RtosIrqs {
    TIMER_INT0 => hisi_rtos::ws63::TimerInterrupt;
    SOFT_INT0 => hisi_rtos::ws63::SoftwareInterrupt;
});

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
    uart.write(b"\r\nRFDBG_COEX_INIT_BEGIN\r\n");

    let installed_radio = RADIO_STORAGE.install().expect("install radio storage");
    let scheduler_storage = RTOS_STORAGE
        .install(&RTOS_ARENA)
        .expect("install scheduler storage");

    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();
    uart.write(b"RFDBG_COEX_RF_POWER_OK\r\n");

    let runtime = hisi_rtos::ws63::start(
        hisi_rtos::ws63::Config {
            minimum_stack_size: NonZeroUsize::new(hisi_rf_ws63::SELECTED_MINIMUM_TASK_STACK_BYTES)
                .expect("profile minimum task stack"),
            radio_task_policy: hisi_rtos::RunPolicy::Cooperative,
            max_scheduler_lock_duration: NonZeroU32::new(5_000).unwrap(),
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
    let main_task = runtime.handle().current_task().expect("adopted main task");
    runtime
        .handle()
        .set_task_run_policy(
            main_task,
            hisi_rtos::RunPolicy::Preemptive {
                time_slice: NonZeroU32::new(5).unwrap(),
            },
        )
        .expect("configure main task");
    uart.write(b"RFDBG_COEX_RTOS_OK\r\n");

    let (control, arena) = installed_radio.into_init_parts();
    let resources = hisi_rf_ws63::Resources::<hisi_rf_ws63::SelectedProfile>::coexistence(
        efuse, p.KM, p.SPACC, p.PKE, p.TRNG, arena,
    );

    #[cfg(feature = "coexistence-wifi-ble")]
    let controllers = hisi_rf_ws63::init_wifi_ble_coexistence(
        hisi_rf_core::RadioConfig::default(),
        resources,
        control,
    )
    .expect("initialize Wi-Fi plus BLE");
    #[cfg(feature = "coexistence-wifi-ble")]
    uart.write(b"RFDBG_BLE_B1_SHARED_PLATFORM_OK\r\n");
    #[cfg(feature = "coexistence-wifi-ble")]
    {
        uart.write(b"RFDBG_COEX_INIT_OK\r\n");
        run_wifi_ble_activity(controllers, uart)
    }

    #[cfg(feature = "coexistence-wifi-sle")]
    {
        let _controllers = hisi_rf_ws63::init_wifi_sle_coexistence(
            hisi_rf_core::RadioConfig::default(),
            resources,
            control,
        )
        .expect("initialize Wi-Fi plus SLE");
        uart.write(b"RFDBG_SLE_S1_SHARED_PLATFORM_OK\r\n");
        uart.write(b"RFDBG_COEX_INIT_OK\r\n");
        loop {
            let _ = hisi_rf_rtos_driver::yield_now();
        }
    }
}

#[cfg(feature = "coexistence-wifi-ble")]
#[inline(never)]
fn run_wifi_ble_activity(
    controllers: hisi_rf_ws63::WifiBleCoexistenceController<
        hisi_rf_ws63::SelectedProfile,
        EVENT_DEPTH,
    >,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) -> ! {
    let (wifi, ble) = controllers.split();
    let wifi = WIFI_PARTS.init(wifi.split(RUNNER_BUDGET));
    let ble = BLE_CONTROLLER.init(ble);
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner: Spawner| {
        spawner.spawn(radio_runner(&mut wifi.runner, uart).unwrap());
        spawner.spawn(ble_advertising_activity(ble, uart).unwrap());
        spawner.spawn(wifi_scan_while_ble_active(&mut wifi.wifi.controller, uart).unwrap());
    })
}

#[cfg(feature = "coexistence-wifi-ble")]
#[embassy_executor::task]
async fn radio_runner(
    runner: &'static mut IncrementalRadioRunner<EVENT_DEPTH>,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    loop {
        let ready = runner.wait_ready().await.expect("infallible WS63 wait");
        if runner.run_once(ready).is_err() {
            fail(uart, b"RFDBG_COEX_WIFI_RUNNER_ERR\r\n")
        }
    }
}

#[cfg(feature = "coexistence-wifi-ble")]
#[embassy_executor::task]
async fn ble_advertising_activity(
    controller: &'static mut hisi_rf_ws63::BleB1Controller,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    let mut command_started = false;
    let mut data_ready = false;
    let mut parameters_ready = false;
    let mut advertising_started = false;

    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::BleB2Event::Enabled { status: 0 } if !command_started => {
                    command_started = true;
                    if controller.start_advertising(BLE_ADVERTISING_DATA).is_err() {
                        fail(uart, b"RFDBG_COEX_BLE_ADV_ERR stage=start\r\n")
                    }
                }
                hisi_rf_ws63::BleB2Event::AdvertisingData { status: 0, .. } => {
                    data_ready = true;
                }
                hisi_rf_ws63::BleB2Event::AdvertisingParameters { status: 0, .. } => {
                    parameters_ready = true;
                }
                hisi_rf_ws63::BleB2Event::AdvertisingState { status: 1, .. } => {
                    advertising_started = true;
                }
                hisi_rf_ws63::BleB2Event::Enabled { status }
                | hisi_rf_ws63::BleB2Event::AdvertisingData { status, .. }
                | hisi_rf_ws63::BleB2Event::AdvertisingParameters { status, .. }
                | hisi_rf_ws63::BleB2Event::AdvertisingState { status, .. } => {
                    uart.write(b"RFDBG_COEX_BLE_ADV_ERR status=0x");
                    uart.write(&hex8(status));
                    uart.write(b"\r\n");
                    halt()
                }
                _ => {}
            }
        }
        if data_ready
            && parameters_ready
            && advertising_started
            && !BLE_ADVERTISING_ACTIVE.load(Ordering::Acquire)
        {
            BLE_ADVERTISING_ACTIVE.store(true, Ordering::Release);
            uart.write(b"RFDBG_COEX_BLE_ADV_ACTIVE\r\n");
        }
        if controller.dropped_events() != 0 {
            uart.write(b"RFDBG_COEX_BLE_EVENT_DROP count=0x");
            uart.write(&hex8(controller.dropped_events()));
            uart.write(b"\r\n");
            halt()
        }
        Timer::after(Duration::from_millis(5)).await;
    }
}

#[cfg(feature = "coexistence-wifi-ble")]
#[embassy_executor::task]
async fn wifi_scan_while_ble_active(
    controller: &'static mut WifiController<EVENT_DEPTH>,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    let advertising_deadline = embassy_time::Instant::now() + Duration::from_secs(15);
    while !BLE_ADVERTISING_ACTIVE.load(Ordering::Acquire) {
        if embassy_time::Instant::now() >= advertising_deadline {
            fail(uart, b"RFDBG_COEX_BLE_ADV_ERR stage=timeout\r\n")
        }
        Timer::after(Duration::from_millis(5)).await;
    }

    match with_timeout(Duration::from_secs(30), controller.initialize()).await {
        Ok(Ok(())) => uart.write(b"RFDBG_COEX_WIFI_INITIALIZE_OK\r\n"),
        _ => fail(uart, b"RFDBG_COEX_WIFI_INITIALIZE_ERR\r\n"),
    }

    let mut results = [ScanResult::empty(); SCAN_RESULT_DEPTH];
    let mut round = 0_u8;
    while round < COEX_SCAN_ROUNDS {
        if !BLE_ADVERTISING_ACTIVE.load(Ordering::Acquire) {
            fail(
                uart,
                b"RFDBG_COEX_BLE_ADV_ERR stage=inactive_during_scan\r\n",
            )
        }
        let scan = controller.scan(
            ScanConfig::new(
                hisi_rf_core::OperationTimeout::try_from_millis(15_000)
                    .expect("non-zero scan timeout"),
            ),
            &mut results,
        );
        let outcome = match with_timeout(Duration::from_secs(30), scan).await {
            Ok(Ok(outcome)) => outcome,
            _ => fail(uart, b"RFDBG_COEX_WIFI_SCAN_ERR\r\n"),
        };
        round += 1;
        uart.write(b"RFDBG_COEX_WIFI_SCAN_OK round=0x");
        uart.write(&hex8(u32::from(round)));
        uart.write(b" count=0x");
        uart.write(&hex8(u32::try_from(outcome.count).unwrap_or(u32::MAX)));
        uart.write(b"\r\n");
        Timer::after(Duration::from_millis(100)).await;
    }

    let events = controller.event_diagnostics();
    if events.dropped != 0 || !BLE_ADVERTISING_ACTIVE.load(Ordering::Acquire) {
        uart.write(b"RFDBG_COEX_EVENT_ERR wifi_dropped=0x");
        uart.write(&hex8(events.dropped));
        uart.write(b"\r\n");
        halt()
    }
    uart.write(b"RFDBG_COEX_WIFI_BLE_ACTIVITY_OK scans=0x");
    uart.write(&hex8(u32::from(COEX_SCAN_ROUNDS)));
    uart.write(b" wifi_dropped=0x00000000 ble_dropped=0x00000000\r\n");

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[cfg(feature = "coexistence-wifi-ble")]
fn fail(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, marker: &[u8]) -> ! {
    uart.write(marker);
    halt()
}

#[cfg(feature = "coexistence-wifi-ble")]
fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "coexistence-wifi-ble")]
fn hex8(value: u32) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [b'0'; 8];
    let mut index = 0;
    while index < output.len() {
        let shift = (output.len() - 1 - index) * 4;
        output[index] = HEX[((value >> shift) & 0x0f) as usize];
        index += 1;
    }
    output
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}
