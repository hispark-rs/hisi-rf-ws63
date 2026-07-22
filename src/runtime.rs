//! Thin calls into the runtime selected by the application.

use core::cell::Cell;
use core::ffi::c_void;
#[cfg(target_arch = "riscv32")]
use core::num::NonZeroU32;
use core::num::NonZeroUsize;
use critical_section::Mutex;
use hisi_rf_rtos_driver::{Error, TaskConfig, TaskEntry, TaskId, TaskPriority, TaskReservation};

static TASK_RESERVATION: Mutex<Cell<Option<&'static TaskReservation>>> =
    Mutex::new(Cell::new(None));

#[cfg(all(
    feature = "net",
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
pub(crate) fn install_task_reservation(reservation: &'static TaskReservation) -> Result<(), Error> {
    critical_section::with(|cs| {
        let installed = TASK_RESERVATION.borrow(cs);
        if installed.get().is_some() {
            Err(Error::AlreadyInstalled)
        } else {
            installed.set(Some(reservation));
            Ok(())
        }
    })
}

fn try_spawn_with_priority(
    entry: TaskEntry,
    arg: *mut c_void,
    stack_size: usize,
    priority: u8,
) -> Result<TaskId, Error> {
    let stack_size = NonZeroUsize::new(stack_size.max(1)).unwrap();
    let priority = TaskPriority::new(priority).ok_or(Error::Runtime)?;
    let config = TaskConfig {
        stack_size,
        priority,
    };
    let reservation = critical_section::with(|cs| TASK_RESERVATION.borrow(cs).get());
    match reservation {
        Some(reservation) => hisi_rf_rtos_driver::spawn_reserved(reservation, entry, arg, config),
        None => hisi_rf_rtos_driver::spawn(entry, arg, config),
    }
}

pub fn spawn(entry: TaskEntry, arg: *mut c_void, stack_size: usize) -> Option<usize> {
    spawn_with_priority(entry, arg, stack_size, 31)
}

pub fn spawn_with_priority(
    entry: TaskEntry,
    arg: *mut c_void,
    stack_size: usize,
    priority: u8,
) -> Option<usize> {
    try_spawn_with_priority(entry, arg, stack_size, priority)
        .ok()
        .map(|task| task.into_raw() as usize)
}

pub(crate) fn spawn_vendor_task(
    entry: TaskEntry,
    arg: *mut c_void,
    stack_size: usize,
    priority: u8,
) -> Result<TaskId, Error> {
    try_spawn_with_priority(entry, arg, stack_size, priority)
}

pub fn yield_now() {
    let _ = hisi_rf_rtos_driver::yield_now();
}

#[cfg(target_arch = "riscv32")]
pub fn sleep_ms(milliseconds: u32) {
    if let Some(milliseconds) = NonZeroU32::new(milliseconds) {
        let _ = hisi_rf_rtos_driver::sleep_ms(milliseconds);
    } else {
        yield_now();
    }
}

pub fn current_id() -> usize {
    hisi_rf_rtos_driver::current_task().map_or(usize::MAX, |task| {
        // The WS63 LiteOS ABI exposes a small scheduler slot as pid/tid. The
        // Rust runtime keeps a generation in the upper bits to reject stale
        // handles; that internal generation must not leak into the blob ABI.
        (task.into_raw() & 0xff) as usize
    })
}
