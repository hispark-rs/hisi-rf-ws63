use core::num::{NonZeroU32, NonZeroUsize};

use hisi_hal::Peripherals;
use hisi_hal::delay::Delay;
use hisi_hal::interrupt;
use hisi_hal::rf_power::RfPower;
use hisi_hal::software_interrupt::SoftwareInterrupt0;
use hisi_hal::time::Instant;
use hisi_hal::timer::TimerAlarm0;
use hisi_hal::uart::{Config as UartConfig, Uart, UartClock};
use hisi_hal::wdt::Watchdog;

hisi_rf_ws63::declare_ble_b1_storage!(static BLE_STORAGE);

pub fn run(role: fn(&mut hisi_rf_ws63::BleB1Controller) -> !) -> ! {
    let p = Peripherals::take().expect("peripherals already taken");
    let uart = Uart::new_uart0(
        p.UART0,
        UartConfig {
            clock: UartClock::Boot,
            ..UartConfig::default()
        },
    );
    Watchdog::new(p.WDT).disable();
    uart.write(b"\r\nRFDBG_BLE_B3_BEGIN\r\n");
    hisi_rf_ws63::set_log_sink(log);

    let storage = BLE_STORAGE.install().expect("install BLE storage");
    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();

    let _timer = TimerAlarm0::new(p.TIMER);
    let _software_interrupt = SoftwareInterrupt0::new(p.SYS_CTL1);
    let _runtime = hisi_rtos::start_with_port(
        hisi_rtos::PortedConfig {
            minimum_stack_size: NonZeroUsize::new(hisi_rf_ws63::BLE_B1_MINIMUM_TASK_STACK_BYTES)
                .unwrap(),
            radio_task_policy: hisi_rtos::RunPolicy::Cooperative,
            max_scheduler_lock_duration: NonZeroU32::new(5_000).unwrap(),
        },
        hisi_rtos::Resources {
            allocate: rtos_allocate,
            deallocate: rtos_deallocate,
            monotonic_ms,
        },
        hisi_rtos::SchedulerPort {
            max_timer_delay: NonZeroU32::new(TimerAlarm0::MAX_DELAY_MS).unwrap(),
            arm_timer: TimerAlarm0::arm_millis,
            disarm_timer: TimerAlarm0::disarm,
            pend_reschedule: SoftwareInterrupt0::pend_interrupt,
            contract_violation: rtos_contract_violation,
        },
    )
    .expect("start BLE RTOS");

    unsafe { interrupt::enable_global() };
    hisi_rtos::request_reschedule();

    let resources = hisi_rf_ws63::BleB1Resources::new(efuse, p.KM, p.SPACC, p.PKE, p.TRNG);
    match hisi_rf_ws63::init_ble_b1(resources, storage) {
        Ok(mut controller) => {
            log(b"RFDBG_BLE_B3_INIT_OK\r\n");
            role(&mut controller)
        }
        Err(error) => {
            log(b"RFDBG_BLE_B3_INIT_ERR code=0x");
            log(&hex8(error_code(error)));
            log(b"\r\n");
            stop()
        }
    }
}

pub fn sleep() {
    let _ = hisi_rf_rtos_driver::sleep_ms(NonZeroU32::new(10).unwrap());
}

pub fn log(bytes: &[u8]) {
    const DATA: *mut u32 = 0x4401_0004 as *mut u32;
    const FIFO_STATUS: *const u32 = 0x4401_0044 as *const u32;
    for &byte in bytes {
        unsafe {
            while core::ptr::read_volatile(FIFO_STATUS) & 0x01 != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(DATA, u32::from(byte));
        }
    }
}

pub fn stop() -> ! {
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
    unsafe { hisi_rf_ws63::InstalledBleB1Storage::allocate(size) }
}

unsafe fn rtos_deallocate(pointer: *mut u8) {
    unsafe { hisi_rf_ws63::InstalledBleB1Storage::deallocate(pointer) };
}

fn monotonic_ms() -> u64 {
    Instant::now().raw() / 24_000
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}

fn error_code(error: hisi_rf_ws63::BleB1InitError) -> u32 {
    use hisi_rf_ws63::BleB1InitError;
    match error {
        BleB1InitError::StorageAlreadyInstalled => 1,
        BleB1InitError::InsufficientArena { .. } => 2,
        BleB1InitError::AllocatorInstall => 3,
        BleB1InitError::TaskPlan => 4,
        BleB1InitError::TaskAdmission => 5,
        BleB1InitError::SchedulerLock => 6,
        BleB1InitError::TaskSpawn { index } => 0x100 + index as u32,
        BleB1InitError::SchedulerUnlock => 7,
        BleB1InitError::TaskHandoff => 10,
        BleB1InitError::Crypto => 8,
        BleB1InitError::Enable(status)
        | BleB1InitError::RegisterCallbacks(status)
        | BleB1InitError::RegisterGattServerCallbacks(status)
        | BleB1InitError::RegisterGattClientCallbacks(status) => status,
        BleB1InitError::EventSinkAlreadyInstalled => 11,
        BleB1InitError::UnsupportedTarget => 9,
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
