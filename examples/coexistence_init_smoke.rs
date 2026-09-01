use core::num::{NonZeroU32, NonZeroUsize};
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use embassy_executor::{Executor, Spawner};
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use embassy_time::{Duration, Timer, with_timeout};
use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::rf_power::RfPower;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use hisi_hal::time::Instant as HalInstant;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use hisi_rf_core::{
    BackendErrorClass, Error as RadioError, OperationTimeout, Passphrase, ScanConfig, ScanResult,
    StationConfig, WifiController, WorkBudget,
};
use hisi_rf_ws63::declare_radio_storage;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use hisi_rf_ws63::{IncrementalRadioParts, IncrementalRadioRunner};
use hisi_riscv_rt::entry;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use smoltcp::iface::{Config as NetConfig, Interface, SocketSet, SocketStorage};
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use smoltcp::socket::udp;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use smoltcp::time::Instant as NetInstant;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use static_cell::StaticCell;

const EVENT_DEPTH: usize = 8;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const SCAN_RESULT_DEPTH: usize = 16;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_SCAN_ROUNDS: u8 = 3;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_SCAN_TIMEOUT_MS: u32 = 30_000;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_SCAN_SETTLE_MS: u64 = 1_000;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_TEST_SSID: &[u8] = b"WS63-RUST-HIL";
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_TEST_PASSPHRASE: &[u8] = b"ws63-rust-hil";
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const COEX_CONNECT_TIMEOUT: OperationTimeout =
    OperationTimeout::try_from_millis(60_000).expect("non-zero connect timeout");
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const LOCAL_ADDRESS: Ipv4Address = Ipv4Address::new(192, 168, 4, 2);
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const LOCAL_PEER: Ipv4Address = Ipv4Address::new(192, 168, 4, 1);
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const LOCAL_ECHO_PORT: u16 = 9;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const LOCAL_ECHO_ATTEMPTS: u8 = 10;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const LOCAL_ECHO_TIMEOUT_MS: u64 = 15_000;
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
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
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
static EXECUTOR: StaticCell<Executor> = StaticCell::new();
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
static WIFI_PARTS: StaticCell<IncrementalRadioParts<EVENT_DEPTH>> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-ble")]
static BLE_CONTROLLER: StaticCell<hisi_rf_ws63::BleB1Controller> = StaticCell::new();
#[cfg(feature = "coexistence-wifi-sle")]
static SLE_CONTROLLER: StaticCell<hisi_rf_ws63::SleS1Controller> = StaticCell::new();
#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
static COEX_ACTIVITY_ACTIVE: AtomicBool = AtomicBool::new(false);

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
        let controllers = hisi_rf_ws63::init_wifi_sle_coexistence(
            hisi_rf_core::RadioConfig::default(),
            resources,
            control,
        )
        .expect("initialize Wi-Fi plus SLE");
        uart.write(b"RFDBG_SLE_S1_SHARED_PLATFORM_OK\r\n");
        uart.write(b"RFDBG_COEX_INIT_OK\r\n");
        run_wifi_sle_activity(controllers, uart)
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
        spawner.spawn(
            wifi_traffic_while_protocol_active(
                &mut wifi.wifi.controller,
                &mut wifi.wifi.device,
                uart,
            )
            .unwrap(),
        );
    })
}

#[cfg(feature = "coexistence-wifi-sle")]
#[inline(never)]
fn run_wifi_sle_activity(
    controllers: hisi_rf_ws63::WifiSleCoexistenceController<
        hisi_rf_ws63::SelectedProfile,
        EVENT_DEPTH,
    >,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) -> ! {
    let (wifi, sle) = controllers.split();
    let wifi = WIFI_PARTS.init(wifi.split(RUNNER_BUDGET));
    let sle = SLE_CONTROLLER.init(sle);
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner: Spawner| {
        spawner.spawn(radio_runner(&mut wifi.runner, uart).unwrap());
        spawner.spawn(sle_announce_activity(sle, uart).unwrap());
        spawner.spawn(
            wifi_traffic_while_protocol_active(
                &mut wifi.wifi.controller,
                &mut wifi.wifi.device,
                uart,
            )
            .unwrap(),
        );
    })
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
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
            && !COEX_ACTIVITY_ACTIVE.load(Ordering::Acquire)
        {
            COEX_ACTIVITY_ACTIVE.store(true, Ordering::Release);
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

#[cfg(feature = "coexistence-wifi-sle")]
#[embassy_executor::task]
async fn sle_announce_activity(
    controller: &'static mut hisi_rf_ws63::SleS1Controller,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    let mut started = false;
    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::SleS1Event::Enabled { status: 0 } if !started => {
                    static mut ANNOUNCE_DATA: [u8; 7] = [1, 1, 1, 3, 2, 0x0b, 0x06];
                    static mut SEEK_RESPONSE_DATA: [u8; 10] =
                        [5, 8, b'H', b'I', b'S', b'I', b'S', b'L', b'E', b'1'];
                    let announce = unsafe { &mut *core::ptr::addr_of_mut!(ANNOUNCE_DATA) };
                    let response = unsafe { &mut *core::ptr::addr_of_mut!(SEEK_RESPONSE_DATA) };
                    if controller.start_announce(announce, response).is_err() {
                        fail(uart, b"RFDBG_COEX_SLE_ANNOUNCE_ERR stage=start\r\n")
                    }
                    started = true;
                }
                hisi_rf_ws63::SleS1Event::AnnounceEnabled { status: 0, .. } => {
                    if !COEX_ACTIVITY_ACTIVE.load(Ordering::Acquire) {
                        COEX_ACTIVITY_ACTIVE.store(true, Ordering::Release);
                        uart.write(b"RFDBG_COEX_SLE_ANNOUNCE_ACTIVE\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::Enabled { status }
                | hisi_rf_ws63::SleS1Event::AnnounceEnabled { status, .. } => {
                    uart.write(b"RFDBG_COEX_SLE_ANNOUNCE_ERR status=0x");
                    uart.write(&hex8(status));
                    uart.write(b"\r\n");
                    halt()
                }
                _ => {}
            }
        }
        if controller.dropped_events() != 0 {
            uart.write(b"RFDBG_COEX_SLE_EVENT_DROP count=0x");
            uart.write(&hex8(controller.dropped_events()));
            uart.write(b"\r\n");
            halt()
        }
        Timer::after(Duration::from_millis(5)).await;
    }
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
#[embassy_executor::task]
async fn wifi_traffic_while_protocol_active(
    controller: &'static mut WifiController<EVENT_DEPTH>,
    device: &'static mut hisi_rf_ws63::WifiDevice,
    uart: &'static Uart<'static, hisi_hal::peripherals::Uart0<'static>>,
) {
    let activity_deadline = embassy_time::Instant::now() + Duration::from_secs(15);
    while !COEX_ACTIVITY_ACTIVE.load(Ordering::Acquire) {
        if embassy_time::Instant::now() >= activity_deadline {
            #[cfg(feature = "coexistence-wifi-ble")]
            fail(uart, b"RFDBG_COEX_BLE_ADV_ERR stage=timeout\r\n");
            #[cfg(feature = "coexistence-wifi-sle")]
            fail(uart, b"RFDBG_COEX_SLE_ANNOUNCE_ERR stage=timeout\r\n");
        }
        Timer::after(Duration::from_millis(5)).await;
    }

    match with_timeout(Duration::from_secs(30), controller.initialize()).await {
        Ok(Ok(())) => uart.write(b"RFDBG_COEX_WIFI_INITIALIZE_OK\r\n"),
        _ => fail(uart, b"RFDBG_COEX_WIFI_INITIALIZE_ERR\r\n"),
    }

    let mut results = [ScanResult::empty(); SCAN_RESULT_DEPTH];
    let mut round = 0_u8;
    let mut selected = None;
    while round < COEX_SCAN_ROUNDS {
        if !COEX_ACTIVITY_ACTIVE.load(Ordering::Acquire) {
            #[cfg(feature = "coexistence-wifi-ble")]
            fail(
                uart,
                b"RFDBG_COEX_BLE_ADV_ERR stage=inactive_during_scan\r\n",
            );
            #[cfg(feature = "coexistence-wifi-sle")]
            fail(
                uart,
                b"RFDBG_COEX_SLE_ANNOUNCE_ERR stage=inactive_during_scan\r\n",
            );
        }
        let scan = controller.scan(
            ScanConfig::new(
                hisi_rf_core::OperationTimeout::try_from_millis(COEX_SCAN_TIMEOUT_MS)
                    .expect("non-zero scan timeout"),
            ),
            &mut results,
        );
        let outcome = match with_timeout(Duration::from_secs(45), scan).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => report_scan_error(uart, error),
            Err(_) => fail(
                uart,
                b"RFDBG_COEX_WIFI_SCAN_ERR class=0x00000003 code=0x00000000\r\n",
            ),
        };
        round += 1;
        uart.write(b"RFDBG_COEX_WIFI_SCAN_OK round=0x");
        uart.write(&hex8(u32::from(round)));
        uart.write(b" count=0x");
        uart.write(&hex8(u32::try_from(outcome.count).unwrap_or(u32::MAX)));
        uart.write(b"\r\n");
        selected = results[..outcome.count]
            .iter()
            .copied()
            .find(|result| result.ssid.as_bytes() == COEX_TEST_SSID);
        write_heap_metrics(uart, b"RFDBG_COEX_HEAP_AFTER_SCAN");
        Timer::after(Duration::from_millis(COEX_SCAN_SETTLE_MS)).await;
    }

    let Some(network) = selected else {
        fail(uart, b"RFDBG_COEX_WIFI_CONNECT_ERR stage=ssid\r\n")
    };
    let passphrase = Passphrase::try_from_ascii(COEX_TEST_PASSPHRASE)
        .expect("valid fixed dual-board passphrase");
    let station = StationConfig::wpa2_personal(&network, passphrase, COEX_CONNECT_TIMEOUT)
        .expect("fixed dual-board AP advertises WPA2-Personal");
    match with_timeout(Duration::from_secs(90), controller.connect(station)).await {
        Ok(Ok(_)) => uart.write(b"RFDBG_COEX_WIFI_CONNECT_OK\r\n"),
        _ => fail(uart, b"RFDBG_COEX_WIFI_CONNECT_ERR stage=associate\r\n"),
    }

    let (sent, received, attempts) = run_local_echo(device, uart).await;
    if sent != LOCAL_ECHO_ATTEMPTS || received != LOCAL_ECHO_ATTEMPTS {
        uart.write(b"RFDBG_COEX_LOCAL_ECHO_ERR sent=0x");
        uart.write(&hex8(u32::from(sent)));
        uart.write(b" received=0x");
        uart.write(&hex8(u32::from(received)));
        uart.write(b" attempts=0x");
        uart.write(&hex8(u32::from(attempts)));
        uart.write(b"\r\n");
        halt()
    }

    let events = controller.event_diagnostics();
    if events.dropped != 0 || !COEX_ACTIVITY_ACTIVE.load(Ordering::Acquire) {
        uart.write(b"RFDBG_COEX_EVENT_ERR wifi_dropped=0x");
        uart.write(&hex8(events.dropped));
        uart.write(b"\r\n");
        halt()
    }
    #[cfg(feature = "coexistence-wifi-ble")]
    uart.write(b"RFDBG_COEX_WIFI_BLE_TRAFFIC_OK scans=0x");
    #[cfg(feature = "coexistence-wifi-sle")]
    uart.write(b"RFDBG_COEX_WIFI_SLE_TRAFFIC_OK scans=0x");
    uart.write(&hex8(u32::from(COEX_SCAN_ROUNDS)));
    uart.write(b" echo=0x");
    uart.write(&hex8(u32::from(received)));
    #[cfg(feature = "coexistence-wifi-ble")]
    uart.write(b" wifi_dropped=0x00000000 ble_dropped=0x00000000\r\n");
    #[cfg(feature = "coexistence-wifi-sle")]
    uart.write(b" wifi_dropped=0x00000000 sle_dropped=0x00000000\r\n");

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
async fn run_local_echo(
    device: &mut hisi_rf_ws63::WifiDevice,
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
) -> (u8, u8, u8) {
    let mac = device
        .station_mac_address()
        .expect("initialized station MAC address");
    let mut config = NetConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = 0x5753_434f;
    let mut interface = Interface::new(config, device, net_now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(LOCAL_ADDRESS), 24))
            .expect("coexistence IPv4 slot");
    });

    let mut socket_storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut socket_storage[..]);
    let mut rx_metadata = [udp::PacketMetadata::EMPTY; LOCAL_ECHO_ATTEMPTS as usize];
    let mut rx_data = [0_u8; 32];
    let mut tx_metadata = [udp::PacketMetadata::EMPTY; 2];
    let mut tx_data = [0_u8; 32];
    let rx = udp::PacketBuffer::new(&mut rx_metadata[..], &mut rx_data[..]);
    let tx = udp::PacketBuffer::new(&mut tx_metadata[..], &mut tx_data[..]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(49_152).expect("bind coexistence UDP probe");
    let socket_handle = sockets.add(socket);
    let endpoint = IpEndpoint::new(IpAddress::Ipv4(LOCAL_PEER), LOCAL_ECHO_PORT);

    let started = monotonic_ms();
    let mut last_send = started.wrapping_sub(500);
    let mut sent = 0_u8;
    let mut attempts = 0_u8;
    let mut next_sequence = 0_u8;
    let mut received = 0_u8;
    let mut received_sequences = 0_u16;
    while monotonic_ms().wrapping_sub(started) < LOCAL_ECHO_TIMEOUT_MS {
        let now = net_now();
        let _ = interface.poll(now, device, &mut sockets);
        let socket = sockets.get_mut::<udp::Socket>(socket_handle);
        while socket.can_recv() {
            let Ok((payload, metadata)) = socket.recv() else {
                break;
            };
            if metadata.endpoint == endpoint && payload.len() == 1 {
                let sequence = payload[0];
                if sequence < LOCAL_ECHO_ATTEMPTS {
                    let bit = 1_u16 << sequence;
                    if received_sequences & bit == 0 {
                        received_sequences |= bit;
                        received = received.saturating_add(1);
                    }
                }
            }
        }
        let current = monotonic_ms();
        if received < LOCAL_ECHO_ATTEMPTS
            && attempts < LOCAL_ECHO_ATTEMPTS.saturating_mul(3)
            && current.wrapping_sub(last_send) >= 500
            && socket.can_send()
        {
            let mut checked = 0_u8;
            while checked < LOCAL_ECHO_ATTEMPTS {
                let sequence = next_sequence;
                next_sequence = (next_sequence + 1) % LOCAL_ECHO_ATTEMPTS;
                checked += 1;
                if received_sequences & (1_u16 << sequence) != 0 {
                    continue;
                }
                if socket.send_slice(&[sequence], endpoint).is_ok() {
                    sent = sent.max(sequence.saturating_add(1));
                    attempts = attempts.saturating_add(1);
                    last_send = current;
                }
                break;
            }
        }
        let _ = interface.poll(net_now(), device, &mut sockets);
        if received == LOCAL_ECHO_ATTEMPTS {
            break;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
    uart.write(b"RFDBG_COEX_LOCAL_ECHO sent=0x");
    uart.write(&hex8(u32::from(sent)));
    uart.write(b" received=0x");
    uart.write(&hex8(u32::from(received)));
    uart.write(b" attempts=0x");
    uart.write(&hex8(u32::from(attempts)));
    uart.write(b" bitmap=0x");
    uart.write(&hex8(u32::from(received_sequences)));
    uart.write(b"\r\n");
    (sent, received, attempts)
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn monotonic_ms() -> u64 {
    HalInstant::now().raw() / 24_000
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn net_now() -> NetInstant {
    NetInstant::from_millis(monotonic_ms().min(i64::MAX as u64) as i64)
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn fail(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, marker: &[u8]) -> ! {
    uart.write(marker);
    halt()
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn report_scan_error(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, error: RadioError) -> ! {
    let (class, code) = match error {
        RadioError::AlreadyInitialized => (1, 0),
        RadioError::Protocol => (2, 0),
        RadioError::Backend(error) => (backend_error_class_code(error.class()), error.code()),
    };
    uart.write(b"RFDBG_COEX_WIFI_SCAN_ERR class=0x");
    uart.write(&hex8(class));
    uart.write(b" code=0x");
    uart.write(&hex8(code));
    uart.write(b"\r\n");
    write_heap_metrics(uart, b"RFDBG_COEX_HEAP_SCAN_ERROR");
    halt()
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn write_heap_metrics(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>, marker: &[u8]) {
    let metrics = hisi_rf_ws63::rf_heap_metrics();
    uart.write(marker);
    uart.write(b" arena=0x");
    uart.write(&hex8(
        u32::try_from(metrics.arena_bytes).unwrap_or(u32::MAX),
    ));
    uart.write(b" used=0x");
    uart.write(&hex8(u32::try_from(metrics.used_bytes).unwrap_or(u32::MAX)));
    uart.write(b" free=0x");
    uart.write(&hex8(u32::try_from(metrics.free_bytes).unwrap_or(u32::MAX)));
    uart.write(b" peak=0x");
    uart.write(&hex8(
        u32::try_from(metrics.peak_used_bytes).unwrap_or(u32::MAX),
    ));
    uart.write(b" live=0x");
    uart.write(&hex8(
        u32::try_from(metrics.live_allocations).unwrap_or(u32::MAX),
    ));
    uart.write(b" failures=0x");
    uart.write(&hex8(
        u32::try_from(metrics.allocation_failures).unwrap_or(u32::MAX),
    ));
    uart.write(b" scan_clear=0x");
    uart.write(&hex8(
        hisi_rf_ws63::wifi::scan_results_clear_diagnostic_word(),
    ));
    uart.write(b"\r\n");
    write_heap_trace(uart);
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn write_heap_trace(uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>) {
    let mut allocations = [hisi_rf_ws63::AllocationTraceRecord::default(); 16];
    let mut frees = [hisi_rf_ws63::FreeTraceRecord::default(); 16];
    let allocation_count = hisi_rf_ws63::allocation_trace_snapshot(&mut allocations);
    let free_count = hisi_rf_ws63::free_trace_snapshot(&mut frees);

    for record in &allocations[..allocation_count] {
        uart.write(b"RFDBG_COEX_ALLOC seq=0x");
        uart.write(&hex8(record.sequence));
        uart.write(b" ptr=0x");
        uart.write(&hex8(record.pointer as u32));
        uart.write(b" size=0x");
        uart.write(&hex8(record.size as u32));
        uart.write(b" caller=0x");
        uart.write(&hex8(record.caller as u32));
        uart.write(b"\r\n");
    }
    for record in &frees[..free_count] {
        uart.write(b"RFDBG_COEX_FREE seq=0x");
        uart.write(&hex8(record.sequence));
        uart.write(b" ptr=0x");
        uart.write(&hex8(record.pointer as u32));
        uart.write(b" caller=0x");
        uart.write(&hex8(record.caller as u32));
        uart.write(b"\r\n");
    }
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
const fn backend_error_class_code(class: BackendErrorClass) -> u32 {
    match class {
        BackendErrorClass::Initialize => 0x100,
        BackendErrorClass::Busy => 0x101,
        BackendErrorClass::OperationTimeout => 0x102,
        BackendErrorClass::BackendTimeout => 0x103,
        BackendErrorClass::Cancelled => 0x104,
        BackendErrorClass::ResourceUnavailable => 0x105,
        BackendErrorClass::UnsupportedSecurity => 0x106,
        BackendErrorClass::Connect => 0x107,
        BackendErrorClass::Other => 0x1ff,
    }
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))]
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
