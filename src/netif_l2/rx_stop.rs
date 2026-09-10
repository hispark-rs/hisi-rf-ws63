//! One-shot native RX stop experiment, NOT a reusable producer fence.
//!
//! Run the existing descriptor teardown in its device worker, with a correlated
//! receipt. A disabled MAC plus empty software descriptor lists does not prove
//! DMA/queued host RX drainage. Reopening remains forbidden.

mod rebuild;
pub use rebuild::RxRebuildDiagnostics;

const CONTRACT: i32 = -0x1020;
const TIMEOUT: i32 = -0x1021;
const MAC_ENABLED: i32 = -0x1022;
const DESCRIPTORS_REMAIN: i32 = -0x1023;
const QUEUED_RX: i32 = -0x1024;
const COMMAND: [u32; 2] = [0x3058_524e, 1]; // NRX0, one non-reusable boot ticket

fn same_worker(expected: u32, current: Option<u32>) -> bool {
    expected != 0 && expected != u32::MAX && current == Some(expected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Requested,
    Executing,
    Returned,
}

/// Immediate stop observations only, not native DMA/queue quiescence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxStopDiagnostics {
    pub installed: bool,
    pub requested: bool,
    pub entered: bool,
    pub returned: bool,
    pub post_returned: bool,
    pub mac_before: u8,
    pub mac_after: u8,
    pub descriptors_empty: u8,
    pub native_status: i32,
    pub fault: i32,
    pub expected_task: u32,
    pub current_task: u32,
    pub rebuild: RxRebuildDiagnostics,
}

struct Transaction {
    phase: Phase,
    diagnostic: RxStopDiagnostics,
}

impl Transaction {
    const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            diagnostic: RxStopDiagnostics {
                installed: false,
                requested: false,
                entered: false,
                returned: false,
                post_returned: false,
                mac_before: 0xff,
                mac_after: 0xff,
                descriptors_empty: 0xff,
                native_status: 0,
                fault: 0,
                expected_task: 0,
                current_task: 0,
                rebuild: RxRebuildDiagnostics {
                    expected: [0; 3],
                    actual: [0; 3],
                    cleaned: [0; 3],
                    mac_after_init: 0xff,
                    mac_after_cleanup: 0xff,
                    attempted: false,
                    cleanup_attempted: false,
                    init_status: 0,
                    cleanup_status: 0,
                    fault: 0,
                },
            },
        }
    }

    fn fail(&mut self, status: i32) -> i32 {
        if self.diagnostic.fault == 0 {
            self.diagnostic.fault = status;
        }
        self.diagnostic.fault
    }

    fn request(&mut self) -> Result<(), i32> {
        if !self.diagnostic.installed || self.phase != Phase::Idle || self.diagnostic.fault != 0 {
            return Err(self.fail(CONTRACT));
        }
        self.phase = Phase::Requested;
        self.diagnostic.requested = true;
        Ok(())
    }

    fn enter(&mut self) -> Result<(), i32> {
        if self.phase != Phase::Requested || self.diagnostic.fault != 0 {
            return Err(self.fail(CONTRACT));
        }
        self.phase = Phase::Executing;
        self.diagnostic.entered = true;
        Ok(())
    }

    fn may_rebuild(&self) -> bool {
        self.phase == Phase::Executing && self.diagnostic.fault == 0
    }

    fn post_returned(&mut self, status: i32) {
        if self.diagnostic.post_returned || !self.diagnostic.requested {
            self.fail(CONTRACT);
        }
        self.diagnostic.post_returned = true;
        if status != 0 {
            self.fail(status);
        }
    }

    fn finish(&mut self, before: u8, after: u8, empty: u8, status: i32) {
        if self.phase != Phase::Executing {
            self.fail(CONTRACT);
            return;
        }
        self.phase = Phase::Returned;
        self.diagnostic.returned = true;
        self.diagnostic.mac_before = before;
        self.diagnostic.mac_after = after;
        self.diagnostic.descriptors_empty = empty;
        self.diagnostic.native_status = status;
        if status != 0 {
            self.fail(status);
        } else if after != 0 {
            self.fail(MAC_ENABLED);
        } else if empty != 1 {
            self.fail(DESCRIPTORS_REMAIN);
        }
    }

    fn result(&self) -> Result<bool, i32> {
        if self.diagnostic.fault != 0 {
            Err(self.diagnostic.fault)
        } else {
            Ok(self.phase == Phase::Returned && self.diagnostic.post_returned)
        }
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
mod native {
    use super::*;
    use crate::frw::FrwMsg;
    use core::{cell::RefCell, ffi::c_void, num::NonZeroU32};
    use critical_section::Mutex;

    const MESSAGE: u16 = 91; // WLAN_MSG_H2D_C_CFG_DESTROY_RX_DSCR
    type Handler = unsafe extern "C" fn(*mut c_void, *mut FrwMsg) -> i32;

    // Only the documented prefix is read. No queue/lock layout is inferred.
    #[repr(C)]
    struct ControlPrefix {
        minimum: u16,
        maximum: u16,
        table: *mut *mut c_void,
    }

    #[unsafe(export_name = "__hisi_net0_rx_stop_transaction")]
    static STATE: Mutex<RefCell<Transaction>> = Mutex::new(RefCell::new(Transaction::new()));
    const _: () = assert!(core::mem::size_of::<Mutex<RefCell<Transaction>>>() == 68);

    // Stock lld's CALL against these SHN_ABS assignments does not produce a
    // usable PC-relative call. Ordinary HI20/LO12_I veneers preserve the linker
    // symbol as truth source, without encoding any ROM address in Rust. The
    // final-ELF gate decodes every veneer and its actual call sites.
    core::arch::global_asm!(
        r#"
        .option push
        .option norvc
        .option norelax
        .macro net0_rom_veneer name, target
        .section .text.\name,"ax",@progbits
        .balign 4
        .global \name
        .type \name,@function
    \name:
        lui t0, %hi(\target)
        addi t0, t0, %lo(\target)
        jalr zero, t0, 0
        .size \name, .-\name
        .endm
        net0_rom_veneer __hisi_net0_rom_control, get_dmac_frw_ctrl
        net0_rom_veneer __hisi_net0_rom_unregister, frw_dmac_msg_hook_unregister
        net0_rom_veneer __hisi_net0_rom_register, frw_dmac_msg_hook_register
        net0_rom_veneer __hisi_net0_rom_destroy, hal_dev_fsm_destroy_rx_dscr
        net0_rom_veneer __hisi_net0_rom_init, hal_dev_fsm_init_rx_dscr
        net0_rom_veneer __hisi_net0_rom_enabled, hal_is_machw_enabled
        net0_rom_veneer __hisi_net0_rom_empty, hal_is_hw_rx_queue_empty
        .option pop
    "#
    );

    unsafe extern "C" {
        #[link_name = "__hisi_net0_rom_control"]
        fn get_dmac_frw_ctrl() -> *const ControlPrefix;
        #[link_name = "__hisi_net0_rom_unregister"]
        fn frw_dmac_msg_hook_unregister(message: u16);
        #[link_name = "__hisi_net0_rom_register"]
        fn frw_dmac_msg_hook_register(message: u16, callback: Handler) -> u32;
        fn frw_send_msg_to_device(vap: u8, message: u16, msg: *mut FrwMsg, sync: u8) -> i32;
        #[link_name = "__hisi_net0_rom_destroy"]
        fn hal_dev_fsm_destroy_rx_dscr(vap: *mut c_void, msg: *mut FrwMsg) -> i32;
        #[link_name = "__hisi_net0_rom_init"]
        fn hal_dev_fsm_init_rx_dscr(vap: *mut c_void, msg: *mut FrwMsg) -> i32;
        #[link_name = "hal_dev_fsm_destroy_rx_dscr"]
        fn original_destroy(vap: *mut c_void, msg: *mut FrwMsg) -> i32;
        fn hal_disable_machw_phy_and_pa();
        #[link_name = "__hisi_net0_rom_enabled"]
        fn hal_is_machw_enabled() -> u8;
        fn hal_chip_get_hal_device() -> *const c_void;
        #[link_name = "__hisi_net0_rom_empty"]
        fn hal_is_hw_rx_queue_empty(device: *const c_void) -> u8;
        fn hmac_is_thruput_enable(kind: u8) -> u8;
        fn frw_get_wifi_frw_task_id() -> i32;
    }

    const _: () = {
        assert!(core::mem::size_of::<ControlPrefix>() == 8);
        assert!(core::mem::offset_of!(ControlPrefix, table) == 4);
        assert!(core::mem::size_of::<FrwMsg>() == 16);
    };

    // Read-only RV32 native RAM ABI, NOT MMIO. The pinned mask ROM has six
    // 12-byte TX headers (_PRE_WLAN_DFR_STAT is absent), three 12-byte RX
    // headers and three hardware-head words. SDK hal_ops_common_rom.h and
    // ROM 0x12c75e/0x12c784/0x12c7aa independently agree on the count offsets.
    // No vendor pointer is followed, queue link written, or full struct copied.
    #[repr(C)]
    struct RxList {
        links: [u32; 2],
        count: u16,
        status: u8,
        available: u8,
    }

    #[repr(C)]
    struct DevicePrefix {
        capability: u32,
        rx: [RxList; 3],
        tx_headers: [[u32; 3]; 6],
        hardware_heads: [u32; 3],
        normal: u16,
        small: u16,
        high: u16,
    }

    const _: () = {
        assert!(core::mem::size_of::<RxList>() == 12);
        assert!(core::mem::offset_of!(RxList, count) == 8);
        assert!(core::mem::offset_of!(DevicePrefix, rx) == 4);
        assert!(core::mem::offset_of!(DevicePrefix, normal) == 124);
        assert!(core::mem::offset_of!(DevicePrefix, small) == 126);
        assert!(core::mem::offset_of!(DevicePrefix, high) == 128);
        assert!(core::mem::size_of::<DevicePrefix>() == 132);
    };

    struct NativeDescriptors {
        device: *const DevicePrefix,
        vap: *mut c_void,
        msg: *mut FrwMsg,
    }

    impl rebuild::DescriptorOps for NativeDescriptors {
        #[inline(always)]
        fn counts(&self) -> rebuild::Counts {
            // SAFETY: the initialized device's fixed prefix remains alive for
            // this device-worker callback. Only six aligned u16 fields are
            // sampled, with no Rust reference/borrow over native mutations.
            unsafe {
                let device = self.device;
                rebuild::Counts {
                    actual: [
                        core::ptr::addr_of!((*device).rx[0].count).read_volatile(),
                        core::ptr::addr_of!((*device).rx[1].count).read_volatile(),
                        core::ptr::addr_of!((*device).rx[2].count).read_volatile(),
                    ],
                    expected: [
                        core::ptr::addr_of!((*device).normal).read_volatile(),
                        core::ptr::addr_of!((*device).high).read_volatile(),
                        core::ptr::addr_of!((*device).small).read_volatile(),
                    ],
                }
            }
        }

        #[inline(always)]
        fn mac_enabled(&self) -> u8 {
            // SAFETY: existing no-argument ROM getter, no borrowed pointers.
            unsafe { hal_is_machw_enabled() }
        }

        #[inline(always)]
        fn initialize(&mut self) -> i32 {
            // SAFETY: original handler ABI on the device worker with disabled
            // MAC and empty lists. Its zero return does not mean full allocation.
            unsafe { hal_dev_fsm_init_rx_dscr(self.vap, self.msg) }
        }

        #[inline(always)]
        fn disable(&mut self) {
            // SAFETY: same native helper used before the terminal teardown.
            unsafe { hal_disable_machw_phy_and_pa() }
        }

        #[inline(always)]
        fn destroy(&mut self) -> i32 {
            // SAFETY: probe rechecks disabled MAC before this cleanup call.
            unsafe { hal_dev_fsm_destroy_rx_dscr(self.vap, self.msg) }
        }
    }

    #[inline(never)]
    #[unsafe(export_name = "__hisi_net0_rx_rebuild_probe")]
    fn rebuild_probe(ops: &mut NativeDescriptors) -> RxRebuildDiagnostics {
        rebuild::probe(ops)
    }

    unsafe fn installed_handler() -> Result<*mut c_void, i32> {
        // SAFETY: caller holds the initialized framework's registration CS.
        let control = unsafe { get_dmac_frw_ctrl().as_ref() }.ok_or(CONTRACT)?;
        if MESSAGE < control.minimum || MESSAGE >= control.maximum || control.table.is_null() {
            return Err(CONTRACT);
        }
        // SAFETY: range and table checked against ROM control metadata. Table
        // elements are opaque function addresses, never transmuted/invoked.
        Ok(unsafe {
            control
                .table
                .add(usize::from(MESSAGE - control.minimum))
                .read()
        })
    }

    pub(crate) fn install() -> Result<(), u32> {
        let result = critical_section::with(|cs| {
            let original = original_destroy as *const () as *mut c_void;
            let replacement = handler as *const () as *mut c_void;
            // SAFETY: these ROM helpers only check/update the RAM callback
            // table (ROM 0x128716/0x12874e); no allocator, wait, or MMIO.
            unsafe {
                if installed_handler()? != original {
                    return Err(CONTRACT);
                }
                frw_dmac_msg_hook_unregister(MESSAGE);
                let status = frw_dmac_msg_hook_register(MESSAGE, handler);
                if status != 0 || installed_handler()? != replacement {
                    return Err(CONTRACT);
                }
            }
            STATE.borrow_ref_mut(cs).diagnostic.installed = true;
            Ok(())
        });
        result.map_err(|status| status as u32)
    }

    pub(crate) fn diagnostics() -> RxStopDiagnostics {
        critical_section::with(|cs| STATE.borrow_ref(cs).diagnostic)
    }

    pub(crate) fn stop_once() -> Result<(), i32> {
        let result = stop_and_wait();
        if let Err(status) = result {
            critical_section::with(|cs| STATE.borrow_ref_mut(cs).fail(status));
        }
        result
    }

    fn stop_and_wait() -> Result<(), i32> {
        // This branch has an additional native host queue; never call the
        // direct-path observation a complete drain in this experiment.
        if super::super::rx_mode::rejected() || unsafe { hmac_is_thruput_enable(18) } != 0 {
            return Err(QUEUED_RX);
        }
        let started = crate::uapi::try_monotonic_ms().ok_or(CONTRACT)?;
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).request())?;
        let mut payload = COMMAND;
        let mut msg = FrwMsg {
            data: payload.as_mut_ptr().cast(),
            rsp: core::ptr::null_mut(),
            data_len: 8,
            rsp_buf_len: 0,
            rsp_len: 0,
            flags: 0,
        };
        // SAFETY: the asynchronous FRW adapter copies the input bytes before
        // returning; it owns the copied node. No response buffer is borrowed.
        // Receipt state has static lifetime even after timeout. Native device
        // processing (and its ROM IRQ-masked teardown) runs in the FRW worker.
        let status = unsafe { frw_send_msg_to_device(0, MESSAGE, &mut msg, 0) };
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).post_returned(status));
        loop {
            if critical_section::with(|cs| STATE.borrow_ref(cs).result())? {
                return Ok(());
            }
            let now = crate::uapi::try_monotonic_ms().ok_or(CONTRACT)?;
            if now < started || now - started >= 1_000 {
                return Err(TIMEOUT);
            }
            hisi_rf_rtos_driver::sleep_ms(NonZeroU32::new(1).unwrap()).map_err(|_| CONTRACT)?;
        }
    }

    #[unsafe(export_name = "__hisi_net0_rx_stop_handler")]
    unsafe extern "C" fn handler(vap: *mut c_void, msg: *mut FrwMsg) -> i32 {
        // SAFETY: FRW supplies a live message/payload for this callback only.
        // Nonmatching native calls retain the original ABI and behavior.
        let matches = unsafe {
            !msg.is_null()
                && (*msg).data_len == 8
                && !(*msg).data.is_null()
                && (*msg).data.cast::<[u32; 2]>().read_unaligned() == COMMAND
        };
        if !matches {
            return unsafe { hal_dev_fsm_destroy_rx_dscr(vap, msg) };
        }
        if let Err(status) = critical_section::with(|cs| STATE.borrow_ref_mut(cs).enter()) {
            return status;
        }
        // Do not run a destructive stop from an unexpected host/ISR context.
        // The getter dereferences OsalTask.task, which our adapter stores as a
        // generation-tagged handle. osal_get_current_tid() is only the slot and
        // is deliberately not the identity to compare here.
        let device_task = unsafe { frw_get_wifi_frw_task_id() } as u32;
        let current = hisi_rf_rtos_driver::current_task()
            .ok()
            .map(hisi_rf_rtos_driver::TaskId::into_raw);
        critical_section::with(|cs| {
            let mut state = STATE.borrow_ref_mut(cs);
            state.diagnostic.expected_task = device_task;
            state.diagnostic.current_task = current.unwrap_or(u32::MAX);
        });
        if !same_worker(device_task, current) {
            return critical_section::with(|cs| STATE.borrow_ref_mut(cs).fail(CONTRACT));
        }
        if super::super::rx_mode::rejected() || unsafe { hmac_is_thruput_enable(18) } != 0 {
            return critical_section::with(|cs| STATE.borrow_ref_mut(cs).fail(QUEUED_RX));
        }
        // SAFETY: exact SDK void()/u8() ABI; called by the device worker with
        // closed application admission and completed HMAC user cleanup. The
        // original destroy deliberately skips work while MAC is enabled.
        let before = unsafe { hal_is_machw_enabled() };
        unsafe { hal_disable_machw_phy_and_pa() };
        let disabled = unsafe { hal_is_machw_enabled() };
        let status = if disabled == 0 {
            unsafe { hal_dev_fsm_destroy_rx_dscr(vap, msg) }
        } else {
            MAC_ENABLED
        };
        let after = unsafe { hal_is_machw_enabled() };
        let device = unsafe { hal_chip_get_hal_device() };
        if device.is_null() {
            return critical_section::with(|cs| STATE.borrow_ref_mut(cs).fail(CONTRACT));
        }
        let empty = unsafe { hal_is_hw_rx_queue_empty(device) };
        // This is a closed-admission allocation round-trip, not restart. Native
        // init may leave partially populated queues despite returning zero.
        let rebuild = if status == 0
            && after == 0
            && empty == 1
            && critical_section::with(|cs| STATE.borrow_ref(cs).may_rebuild())
        {
            Some(rebuild_probe(&mut NativeDescriptors {
                device: device.cast(),
                vap,
                msg,
            }))
        } else {
            None
        };
        critical_section::with(|cs| {
            let mut state = STATE.borrow_ref_mut(cs);
            if let Some(report) = rebuild {
                state.diagnostic.rebuild = report;
                if report.fault != 0 {
                    state.fail(report.fault);
                }
            }
            state.finish(before, after, empty, status);
            state.diagnostic.fault
        })
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) use native::{diagnostics, install, stop_once};

#[cfg(test)]
mod tests {
    use super::*;

    fn installed() -> Transaction {
        let mut t = Transaction::new();
        t.diagnostic.installed = true;
        t
    }

    #[test]
    fn both_post_return_and_device_receipt_are_required() {
        for post_first in [true, false] {
            let mut t = installed();
            t.request().unwrap();
            if post_first {
                t.post_returned(0);
            }
            assert_eq!(t.result(), Ok(false));
            t.enter().unwrap();
            t.finish(1, 0, 1, 0);
            assert_eq!(t.result(), Ok(post_first));
            if !post_first {
                t.post_returned(0);
            }
            assert_eq!(t.result(), Ok(true));
            assert_eq!(t.request(), Err(CONTRACT));
        }
    }

    #[test]
    fn timeout_before_dispatch_rejects_late_destructive_work() {
        let mut t = installed();
        t.request().unwrap();
        t.post_returned(0);
        t.fail(TIMEOUT);
        assert_eq!(t.enter(), Err(TIMEOUT));
        assert!(!t.diagnostic.entered);
    }

    #[test]
    fn timeout_during_native_execution_cannot_become_success() {
        let mut t = installed();
        t.request().unwrap();
        t.enter().unwrap();
        assert!(t.may_rebuild());
        t.fail(TIMEOUT);
        assert!(!t.may_rebuild());
        t.finish(1, 0, 1, 0);
        t.post_returned(0);
        assert_eq!(t.result(), Err(TIMEOUT));
    }

    #[test]
    fn zero_native_return_does_not_prove_stop() {
        for (after, empty, status, expected) in [
            (1, 1, 0, MAC_ENABLED),
            (0, 0, 0, DESCRIPTORS_REMAIN),
            (0, 2, 0, DESCRIPTORS_REMAIN),
            (0, 1, 100, 100),
        ] {
            let mut t = installed();
            t.request().unwrap();
            t.enter().unwrap();
            t.finish(1, after, empty, status);
            t.post_returned(0);
            assert_eq!(t.result(), Err(expected));
        }
    }

    #[test]
    fn duplicate_callback_and_enqueue_error_fail_closed() {
        let mut t = installed();
        t.request().unwrap();
        t.enter().unwrap();
        assert_eq!(t.enter(), Err(CONTRACT));
        t.finish(1, 0, 1, 0);
        t.post_returned(0);
        assert_eq!(t.result(), Err(CONTRACT));
        let mut t = installed();
        t.request().unwrap();
        t.post_returned(109);
        assert_eq!(t.enter(), Err(109));
        assert_eq!(Transaction::new().request(), Err(CONTRACT));
    }

    #[test]
    fn wire_identity_and_errors_are_distinct() {
        assert_eq!(core::mem::size_of_val(&COMMAND), 8);
        assert_ne!(COMMAND, [0, 0]);
        assert_ne!(QUEUED_RX, TIMEOUT);
    }

    #[test]
    fn worker_identity_preserves_generation_not_just_slot() {
        assert!(same_worker(0x107, Some(0x107)));
        assert!(!same_worker(0x107, Some(7)));
        assert!(!same_worker(0x107, Some(0x207)));
        assert!(!same_worker(0x107, Some(0x108)));
        assert!(!same_worker(0x107, None));
        assert!(!same_worker(u32::MAX, Some(u32::MAX)));
        assert!(!same_worker(0, Some(0)));
    }
}
