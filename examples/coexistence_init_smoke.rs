use core::num::{NonZeroU32, NonZeroUsize};

use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::rf_power::RfPower;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;
use hisi_panic_handler as _;
use hisi_rf_ws63::declare_radio_storage;
use hisi_riscv_rt::entry;
use static_cell::StaticCell;

const EVENT_DEPTH: usize = 8;

declare_radio_storage!(static RADIO_STORAGE, events = EVENT_DEPTH);
static RTOS_STORAGE: hisi_rtos::SchedulerStorage<15> = hisi_rtos::SchedulerStorage::new();
#[cfg_attr(target_arch = "riscv32", unsafe(link_section = ".hisi.shared-arena"))]
static RTOS_ARENA: hisi_rtos::SchedulerArena<{ hisi_rf_ws63::SELECTED_RUNTIME_ARENA_BYTES }> =
    hisi_rtos::SchedulerArena::new();
static UART: StaticCell<Uart<'static, hisi_hal::peripherals::Uart0<'static>>> = StaticCell::new();

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
    let _controllers = hisi_rf_ws63::init_wifi_ble_coexistence(
        hisi_rf_core::RadioConfig::default(),
        resources,
        control,
    )
    .expect("initialize Wi-Fi plus BLE");

    #[cfg(feature = "coexistence-wifi-sle")]
    let _controllers = hisi_rf_ws63::init_wifi_sle_coexistence(
        hisi_rf_core::RadioConfig::default(),
        resources,
        control,
    )
    .expect("initialize Wi-Fi plus SLE");

    uart.write(b"RFDBG_COEX_INIT_OK\r\n");
    loop {
        let _ = hisi_rf_rtos_driver::yield_now();
    }
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}
