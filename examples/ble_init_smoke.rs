//! Credential-free WS63 BLE B1 init and B2 advertising/scanning smoke.

#![no_std]
#![no_main]

#[cfg(feature = "ble-init-diag")]
use core::ffi::c_void;
use core::num::NonZeroU32;
#[cfg(feature = "ble-init-diag")]
use core::num::NonZeroUsize;

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
use hisi_riscv_rt::entry;

hisi_rf_ws63::declare_ble_b1_storage!(static BLE_STORAGE);

static B2_ADVERTISING_DATA: &[u8] = &[
    2, 0x01, 0x06, 8, 0x09, b'H', b'I', b'S', b'I', b'B', b'2', b'X',
];

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
    uart.write(b"\r\nRFDBG_BLE_B1_BEGIN\r\n");
    hisi_rf_ws63::set_log_sink(rf_log_uart0);

    let storage = BLE_STORAGE.install().expect("install BLE B1 storage");
    uart.write(b"RFDBG_BLE_B1_STORAGE_OK\r\n");

    let mut delay = Delay::new();
    let rf_ready = RfPower::new(p.CMU, p.CLDO_CRG).enable(p.EFUSE, &mut delay);
    let (_cldo_crg, efuse) = rf_ready.into_parts();
    uart.write(b"RFDBG_BLE_B1_RF_POWER_OK\r\n");

    let _timer = TimerAlarm0::new(p.TIMER);
    let _software_interrupt = SoftwareInterrupt0::new(p.SYS_CTL1);
    let _runtime = hisi_rtos::start_with_port(
        hisi_rtos::PortedConfig {
            // B1 uses the archive-derived heterogeneous stack plan. Keeping the
            // runtime floor at the profile minimum prevents the Wi-Fi-oriented
            // 24 KiB default from invalidating the smaller reservations.
            minimum_stack_size: core::num::NonZeroUsize::new(
                hisi_rf_ws63::BLE_B1_MINIMUM_TASK_STACK_BYTES,
            )
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
    .expect("start BLE B1 RTOS");
    uart.write(b"RFDBG_BLE_B1_RTOS_OK\r\n");

    unsafe { interrupt::enable_global() };
    hisi_rtos::request_reschedule();

    #[cfg(feature = "ble-init-diag")]
    start_task_diagnostics();

    let resources = hisi_rf_ws63::BleB1Resources::new(efuse, p.KM, p.SPACC, p.PKE, p.TRNG);
    match hisi_rf_ws63::init_ble_b1(resources, storage) {
        Ok(mut controller) => {
            uart.write(b"RFDBG_BLE_B1_INIT_OK\r\n");
            run_ble_b2(&uart, &mut controller)
        }
        Err(error) => {
            uart.write(b"RFDBG_BLE_B1_INIT_ERR code=0x");
            uart.write(&hex8(error_code(error)));
            uart.write(b"\r\n");
        }
    }

    loop {
        core::hint::spin_loop();
    }
}

fn run_ble_b2(
    uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>,
    controller: &mut hisi_rf_ws63::BleB1Controller,
) -> ! {
    let mut advertising_data_ok = false;
    let mut advertising_parameters_ok = false;
    let mut advertising_started = false;
    let mut commands_started = false;

    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::BleB2Event::Enabled { status: 0 } if !commands_started => {
                    commands_started = true;
                    if controller.start_advertising(B2_ADVERTISING_DATA).is_err()
                        || controller.start_scanning().is_err()
                    {
                        uart.write(b"RFDBG_BLE_B2_COMMAND_ERR\r\n");
                        loop {
                            core::hint::spin_loop();
                        }
                    }
                    uart.write(b"RFDBG_BLE_B2_COMMANDS_OK\r\n");
                }
                hisi_rf_ws63::BleB2Event::Enabled { status } => {
                    uart.write(b"RFDBG_BLE_B2_ENABLE_ERR code=0x");
                    uart.write(&hex8(status));
                    uart.write(b"\r\n");
                }
                hisi_rf_ws63::BleB2Event::AdvertisingData { status: 0, .. } => {
                    advertising_data_ok = true;
                }
                hisi_rf_ws63::BleB2Event::AdvertisingParameters { status: 0, .. } => {
                    advertising_parameters_ok = true;
                }
                hisi_rf_ws63::BleB2Event::AdvertisingState { status: 1, .. } => {
                    advertising_started = true;
                }
                hisi_rf_ws63::BleB2Event::ScanParameters { status: 0 } => {
                    uart.write(b"RFDBG_BLE_B2_SCAN_READY\r\n");
                }
                hisi_rf_ws63::BleB2Event::ScanResult { data_len, data, .. } => {
                    let data_len = usize::from(data_len).min(data.len());
                    if data[..data_len] == *B2_ADVERTISING_DATA {
                        uart.write(b"RFDBG_BLE_B2_SCAN_MATCH\r\n");
                    }
                }
                _ => uart.write(b"RFDBG_BLE_B2_ASYNC_ERR\r\n"),
            }
        }
        if advertising_data_ok && advertising_parameters_ok && advertising_started {
            uart.write(b"RFDBG_BLE_B2_ADV_OK\r\n");
            advertising_data_ok = false;
            advertising_parameters_ok = false;
            advertising_started = false;
        }
        if controller.dropped_events() != 0 {
            uart.write(b"RFDBG_BLE_B2_EVENT_DROP count=0x");
            uart.write(&hex8(controller.dropped_events()));
            uart.write(b"\r\n");
        }
        let _ = hisi_rf_rtos_driver::sleep_ms(NonZeroU32::new(10).unwrap());
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
    // SAFETY: hisi-rtos returns this allocation through `rtos_deallocate`.
    unsafe { hisi_rf_ws63::InstalledBleB1Storage::allocate(size) }
}

unsafe fn rtos_deallocate(pointer: *mut u8) {
    // SAFETY: hisi-rtos returns only pointers produced by `rtos_allocate`.
    unsafe { hisi_rf_ws63::InstalledBleB1Storage::deallocate(pointer) };
}

fn monotonic_ms() -> u64 {
    Instant::now().raw() / 24_000
}

fn rtos_contract_violation(_violation: hisi_rtos::ContractViolation) -> ! {
    panic!("hisi-rtos scheduler contract violation")
}

#[cfg(feature = "ble-init-diag")]
#[unsafe(no_mangle)]
extern "C" fn __ws63_ble_exception_diag(frame: *const u32) -> ! {
    let (mcause, mepc, mtval): (u32, u32, u32);
    // SAFETY: the runtime calls this handler in machine mode after preserving
    // the interrupted context. Reading the trap CSRs does not modify it.
    unsafe {
        core::arch::asm!("csrr {value}, mcause", value = out(reg) mcause, options(nomem, nostack));
        core::arch::asm!("csrr {value}, mepc", value = out(reg) mepc, options(nomem, nostack));
        core::arch::asm!("csrr {value}, mtval", value = out(reg) mtval, options(nomem, nostack));
    }
    rf_log_uart0(b"RFDBG_BLE_B1_EXCEPTION cause=0x");
    rf_log_uart0(&hex8(mcause));
    rf_log_uart0(b" epc=0x");
    rf_log_uart0(&hex8(mepc));
    rf_log_uart0(b" tval=0x");
    rf_log_uart0(&hex8(mtval));
    if !frame.is_null() {
        // startup.S stores ra/a0-a2 at words 35/31/29-30 of this frame.
        let (ra, a0, a1, a2) = unsafe {
            (
                frame.add(35).read_volatile(),
                frame.add(31).read_volatile(),
                frame.add(30).read_volatile(),
                frame.add(29).read_volatile(),
            )
        };
        rf_log_uart0(b" ra=0x");
        rf_log_uart0(&hex8(ra));
        rf_log_uart0(b" a0=0x");
        rf_log_uart0(&hex8(a0));
        rf_log_uart0(b" a1=0x");
        rf_log_uart0(&hex8(a1));
        rf_log_uart0(b" a2=0x");
        rf_log_uart0(&hex8(a2));
    }
    rf_log_uart0(b"\r\n");
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "ble-init-diag")]
fn start_task_diagnostics() {
    // `TaskDiagnostic` is intentionally rich (128 bytes on RV32), and the
    // 17-slot snapshot makes this task's optimized frame larger than 2 KiB.
    // Keep the diagnostic stack separate from the archive-derived vendor task
    // minima so enabling diagnostics cannot underflow into radio BSS.
    const DIAGNOSTIC_STACK_BYTES: usize = 4 * 1024;
    let config = hisi_rf_rtos_driver::TaskConfig {
        stack_size: NonZeroUsize::new(DIAGNOSTIC_STACK_BYTES).unwrap(),
        priority: hisi_rf_rtos_driver::TaskPriority::new(30).unwrap(),
    };
    match hisi_rf_rtos_driver::spawn(ble_task_diagnostics, core::ptr::null_mut(), config) {
        Ok(_) => rf_log_uart0(b"RFDBG_BLE_B1_DIAG_TASK_OK\r\n"),
        Err(_) => rf_log_uart0(b"RFDBG_BLE_B1_DIAG_TASK_ERR\r\n"),
    }
}

#[cfg(feature = "ble-init-diag")]
extern "C" fn ble_task_diagnostics(_argument: *mut c_void) -> *mut c_void {
    loop {
        let _ = hisi_rf_rtos_driver::sleep_ms(NonZeroU32::new(2_000).unwrap());
        write_task_diagnostics();
    }
}

#[cfg(feature = "ble-init-diag")]
fn write_task_diagnostics() {
    for irq in [46_u32, 47, 68] {
        let lifecycle = hisi_rf_ws63::osal::irq_lifecycle_diagnostics(irq);
        rf_log_uart0(b"RFDBG_BLE_B1_IRQ irq=0x");
        rf_log_uart0(&hex8(irq));
        rf_log_uart0(b" enable=0x");
        rf_log_uart0(&hex8(lifecycle[0]));
        rf_log_uart0(b" clear=0x");
        rf_log_uart0(&hex8(lifecycle[2]));
        rf_log_uart0(b" dispatch=0x");
        rf_log_uart0(&hex8(lifecycle[3]));
        rf_log_uart0(b" enabled=0x");
        rf_log_uart0(&hex8(lifecycle[4]));
        rf_log_uart0(b" pending=0x");
        rf_log_uart0(&hex8(lifecycle[5]));
        rf_log_uart0(b"\r\n");
    }

    let scheduler = hisi_rtos::diagnostics();
    rf_log_uart0(b"RFDBG_BLE_B1_SCHED current=0x");
    rf_log_uart0(&hex8(scheduler.current_task as u32));
    rf_log_uart0(b" ready=0x");
    rf_log_uart0(&hex8(u32::from(scheduler.ready_tasks)));
    rf_log_uart0(b" blocked=0x");
    rf_log_uart0(&hex8(u32::from(scheduler.blocked_tasks)));
    rf_log_uart0(b" sleeping=0x");
    rf_log_uart0(&hex8(u32::from(scheduler.sleeping_tasks)));
    rf_log_uart0(b" pending=0x");
    rf_log_uart0(&hex8(
        scheduler
            .switch_intents_committed
            .saturating_sub(scheduler.switch_intents_completed),
    ));
    rf_log_uart0(b"\r\n");

    let mut tasks = [hisi_rtos::TaskDiagnostic::default(); 17];
    let count = hisi_rtos::task_diagnostics(&mut tasks);
    for task in &tasks[..count] {
        if task.state == hisi_rtos::TaskState::Free {
            continue;
        }
        rf_log_uart0(b"RFDBG_BLE_B1_TASK id=0x");
        rf_log_uart0(&hex8(task.task as u32));
        rf_log_uart0(b" state=");
        rf_log_uart0(task_state_name(task.state));
        rf_log_uart0(b" entry=0x");
        rf_log_uart0(&hex8(task.entry as u32));
        rf_log_uart0(b" prio=0x");
        rf_log_uart0(&hex8(u32::from(task.priority)));
        rf_log_uart0(b" sem=0x");
        rf_log_uart0(&hex8(task.waiting_sem as u32));
        rf_log_uart0(b" mutex=0x");
        rf_log_uart0(&hex8(task.waiting_mutex as u32));
        rf_log_uart0(b" wake=0x");
        rf_log_uart0(&hex8(task.wake_at as u32));
        rf_log_uart0(b" dispatch=0x");
        rf_log_uart0(&hex8(task.dispatches));
        rf_log_uart0(b"\r\n");
    }
}

#[cfg(feature = "ble-init-diag")]
fn task_state_name(state: hisi_rtos::TaskState) -> &'static [u8] {
    match state {
        hisi_rtos::TaskState::Free => b"free",
        hisi_rtos::TaskState::Ready => b"ready",
        hisi_rtos::TaskState::Running => b"running",
        hisi_rtos::TaskState::Blocked => b"blocked",
        hisi_rtos::TaskState::Sleeping => b"sleeping",
        hisi_rtos::TaskState::Throttled => b"throttled",
    }
}

fn rf_log_uart0(bytes: &[u8]) {
    const DATA: *mut u32 = 0x4401_0004 as *mut u32;
    const FIFO_STATUS: *const u32 = 0x4401_0044 as *const u32;
    for &byte in bytes {
        // SAFETY: UART0 was configured above and remains exclusively owned by
        // this diagnostic firmware. The register layout matches the HAL/PAC.
        unsafe {
            while core::ptr::read_volatile(FIFO_STATUS) & 0x01 != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(DATA, u32::from(byte));
        }
    }
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
        BleB1InitError::Enable(status) => status,
        BleB1InitError::EventSinkAlreadyInstalled => 11,
        BleB1InitError::RegisterCallbacks(status) => status,
        BleB1InitError::RegisterGattServerCallbacks(status) => status,
        BleB1InitError::RegisterGattClientCallbacks(status) => status,
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
