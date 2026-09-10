//! Experimental descriptor-to-host provenance census, not packet admission.
//!
//! The pinned hh503_rx_alloc_netbuf_and_dscr_patch calls set_ctrl_dscr before
//! publishing the descriptor to its native list. Observe that binding without
//! reading either pointer. The callback may deliver a different/copied buffer;
//! missing coverage is counted, never guessed or repaired by current epoch.
//! Native buffer allocation/free, DMA and management delivery are unchanged.

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
use super::AllocationEpoch;

/// Observation only. A matched address is not yet a proven native lifetime,
/// DMA fence, or permission to reuse a connection generation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxOriginDiagnostics {
    pub bindings: u64,
    pub failed_bindings: u64,
    pub replaced: u64,
    /// Observations retired before a native free attempt, not a free receipt.
    pub retired_on_free_attempt: u64,
    pub free_calls: u64,
    pub capacity_failures: u64,
    pub matched: u64,
    pub unmatched: u64,
    pub closed_origin: u64,
    pub current_origin: u64,
    pub stale_origin: u64,
    pub occupied: usize,
    pub peak: usize,
    pub exhausted: bool,
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
struct Tracker<const N: usize> {
    // Columns avoid per-entry u64/Option padding on RV32. netbuf == 0 is
    // unused; open distinguishes a closed origin from every valid u64 epoch.
    descriptors: [usize; N],
    netbufs: [usize; N],
    revisions: [u64; N],
    open: [bool; N],
    diagnostic: RxOriginDiagnostics,
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
fn increment(value: &mut u64, exhausted: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *exhausted = true,
    }
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
fn free_route_valid(current: usize, expected: usize, pbuf: usize) -> bool {
    expected != 0 && current == expected && pbuf == 0
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
impl<const N: usize> Tracker<N> {
    const fn new() -> Self {
        Self {
            descriptors: [0; N],
            netbufs: [0; N],
            revisions: [0; N],
            open: [false; N],
            diagnostic: RxOriginDiagnostics {
                bindings: 0,
                failed_bindings: 0,
                replaced: 0,
                retired_on_free_attempt: 0,
                free_calls: 0,
                capacity_failures: 0,
                matched: 0,
                unmatched: 0,
                closed_origin: 0,
                current_origin: 0,
                stale_origin: 0,
                occupied: 0,
                peak: 0,
                exhausted: false,
            },
        }
    }

    fn bind(&mut self, descriptor: usize, netbuf: usize, epoch: AllocationEpoch, status: u32) {
        // Native frees need not cross a flash wrapper. A new exclusive native
        // binding supersedes the old observation of either identity. This is
        // deliberately a census, not an assertion that the old owner drained.
        for slot in 0..N {
            if self.netbufs[slot] != 0
                && (self.netbufs[slot] == netbuf || self.descriptors[slot] == descriptor)
            {
                self.netbufs[slot] = 0;
                self.diagnostic.occupied -= 1;
                increment(
                    &mut self.diagnostic.replaced,
                    &mut self.diagnostic.exhausted,
                );
            }
        }
        if status != 0 || descriptor == 0 || netbuf == 0 {
            increment(
                &mut self.diagnostic.failed_bindings,
                &mut self.diagnostic.exhausted,
            );
            return;
        }
        let Some(slot) = self.netbufs.iter().position(|entry| *entry == 0) else {
            increment(
                &mut self.diagnostic.capacity_failures,
                &mut self.diagnostic.exhausted,
            );
            return;
        };
        self.descriptors[slot] = descriptor;
        self.netbufs[slot] = netbuf;
        self.open[slot] = epoch.revision.is_some();
        self.revisions[slot] = epoch.revision.unwrap_or(0);
        increment(
            &mut self.diagnostic.bindings,
            &mut self.diagnostic.exhausted,
        );
        self.diagnostic.occupied += 1;
        self.diagnostic.peak = self.diagnostic.peak.max(self.diagnostic.occupied);
    }

    fn delivered(&mut self, netbuf: usize, current: AllocationEpoch) {
        let Some(slot) = self
            .netbufs
            .iter()
            .position(|entry| netbuf != 0 && *entry == netbuf)
        else {
            increment(
                &mut self.diagnostic.unmatched,
                &mut self.diagnostic.exhausted,
            );
            return;
        };
        let revision = self.open[slot].then_some(self.revisions[slot]);
        self.netbufs[slot] = 0;
        self.diagnostic.occupied -= 1;
        increment(&mut self.diagnostic.matched, &mut self.diagnostic.exhausted);
        let counter = match revision {
            None => &mut self.diagnostic.closed_origin,
            Some(revision) if current.revision == Some(revision) => {
                &mut self.diagnostic.current_origin
            }
            Some(_) => &mut self.diagnostic.stale_origin,
        };
        increment(counter, &mut self.diagnostic.exhausted);
    }

    fn before_free(&mut self, netbuf: usize) {
        increment(
            &mut self.diagnostic.free_calls,
            &mut self.diagnostic.exhausted,
        );
        for slot in 0..N {
            if netbuf != 0 && self.netbufs[slot] == netbuf {
                self.netbufs[slot] = 0;
                self.diagnostic.occupied -= 1;
                increment(
                    &mut self.diagnostic.retired_on_free_attempt,
                    &mut self.diagnostic.exhausted,
                );
            }
        }
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(super) mod native {
    use super::*;
    use core::{
        cell::{Cell, RefCell},
        ffi::c_void,
    };
    use critical_section::Mutex;

    // The current allocation receipt counts 4 normal + 4 small + 8 high-prio
    // descriptors, but the native pool has 35 controls on the observed rigs.
    // This experiment tests whether free observations bound the live census;
    // overflow is still failure, never justification to guess an epoch.
    // Fixed metadata only; no packet payload or native ownership lives here.
    #[unsafe(export_name = "__hisi_net0_rx_origins")]
    static TRACKER: Mutex<RefCell<Tracker<16>>> = Mutex::new(RefCell::new(Tracker::new()));
    const _: () = assert!(core::mem::size_of::<Mutex<RefCell<Tracker<16>>>>() == 384);

    #[link(kind = "link-arg", name = "--wrap=hh503_rx_set_ctrl_dscr")]
    unsafe extern "C" {
        #[link_name = "__hisi_net0_rom_rx_set_ctrl"]
        fn set_ctrl(descriptor: *mut c_void, netbuf: *mut c_void) -> u32;
    }

    type NativeFree = unsafe extern "C" fn(*mut c_void) -> u32;
    // The vendor free function is STB_LOCAL. Capture its typed callback at
    // registration instead of manufacturing a global/absolute symbol for it.
    #[unsafe(export_name = "__hisi_net0_original_free")]
    static ORIGINAL_FREE: Mutex<Cell<Option<NativeFree>>> = Mutex::new(Cell::new(None));

    #[link(kind = "link-arg", name = "--wrap=frw_rom_cb_register")]
    unsafe extern "C" {
        #[link_name = "__hisi_net0_rom_register_callback"]
        fn register_callback(id: u32, callback: *mut c_void);
    }

    pub(crate) fn validate_free_route(
        cs: critical_section::CriticalSection<'_>,
    ) -> Result<(), u32> {
        // ROM oal_mem_netbuf_free consults callback 250 before 249. A foreign
        // pbuf-free callback could bypass this observation entirely. Registration
        // is read-only here; native init must already have installed our wrapper.
        // SAFETY: initialized, bounded ROM callback table, under the caller's CS.
        let (free, pbuf) = unsafe {
            (
                ws63_radio_sys::frw::frw_get_rom_cb(249),
                ws63_radio_sys::frw::frw_get_rom_cb(250),
            )
        };
        if !free_route_valid(free.addr(), observe_free as *const () as usize, pbuf.addr())
            || ORIGINAL_FREE.borrow(cs).get().is_none()
        {
            return Err(0x1000_0012);
        }
        Ok(())
    }

    #[unsafe(export_name = "__wrap_frw_rom_cb_register")]
    unsafe extern "C" fn observe_registration(id: u32, callback: *mut c_void) {
        if id != 249 || callback == observe_free as *const () as *mut c_void {
            // SAFETY: preserve every unrelated registration and repeated
            // observer registration, using the audited ROM table-store ABI.
            unsafe { register_callback(id, callback) };
            return;
        }
        critical_section::with(|cs| {
            let original = if callback.is_null() {
                None
            } else {
                // SAFETY: callback 249 is the pinned native netbuf-free ABI.
                // The final-ELF gate checks the initializer's actual argument
                // and registration edge, not just the wrapper symbol.
                Some(unsafe { core::mem::transmute::<*mut c_void, NativeFree>(callback) })
            };
            ORIGINAL_FREE.borrow(cs).set(original);
            let routed = if original.is_some() {
                observe_free as *const () as *mut c_void
            } else {
                callback
            };
            // SAFETY: the ROM operation is only a bounded RAM table store.
            // Publishing the original and route in one CS excludes an IRQ
            // callback observing a route without its original function.
            unsafe { register_callback(id, routed) };
        });
    }

    #[unsafe(export_name = "__hisi_net0_observe_free")]
    unsafe extern "C" fn observe_free(netbuf: *mut c_void) -> u32 {
        let original = critical_section::with(|cs| {
            TRACKER.borrow_ref_mut(cs).before_free(netbuf.addr());
            ORIGINAL_FREE.borrow(cs).get()
        });
        // SAFETY: oal_net_pkt_rom.h defines callback 249 with this ABI. ROM
        // calls it for pool and RAM buffers. Forward once, outside Rust CS,
        // without accessing the allocation. In particular preserve status 2
        // (not RAM, continue to the ROM pool-free path) and every error code.
        match original {
            Some(free) => unsafe { free(netbuf) },
            // Only unsafe/foreign table corruption can violate publication.
            // Do not claim RAM freed (0) or continue pool freeing (2).
            None => 0x1000_0013,
        }
    }

    // SHN_ABS ROM symbol, resolved by standard HI20/LO12 relocations. Calling
    // __real directly with CALL is not a valid absolute-ROM veneer on this LLD.
    core::arch::global_asm!(
        r#"
        .option push
        .option norvc
        .option norelax
        .section .text.__hisi_net0_rom_rx_set_ctrl,"ax",@progbits
        .balign 4
        .global __hisi_net0_rom_rx_set_ctrl
        .type __hisi_net0_rom_rx_set_ctrl,@function
    __hisi_net0_rom_rx_set_ctrl:
        lui t0, %hi(__real_hh503_rx_set_ctrl_dscr)
        addi t0, t0, %lo(__real_hh503_rx_set_ctrl_dscr)
        jalr zero, t0, 0
        .size __hisi_net0_rom_rx_set_ctrl, .-__hisi_net0_rom_rx_set_ctrl
        .section .text.__hisi_net0_rom_register_callback,"ax",@progbits
        .balign 4
        .global __hisi_net0_rom_register_callback
        .type __hisi_net0_rom_register_callback,@function
    __hisi_net0_rom_register_callback:
        lui t0, %hi(__real_frw_rom_cb_register)
        addi t0, t0, %lo(__real_frw_rom_cb_register)
        jalr zero, t0, 0
        .size __hisi_net0_rom_register_callback, .-__hisi_net0_rom_register_callback
        .option pop
    "#
    );

    #[unsafe(export_name = "__wrap_hh503_rx_set_ctrl_dscr")]
    unsafe extern "C" fn bind(descriptor: *mut c_void, netbuf: *mut c_void) -> u32 {
        let epoch = super::super::NATIVE_RX_ROUTE.allocation_epoch();
        // SAFETY: pinned hal_dscr_rom.h declares this exact two-pointer/u32
        // ABI. Forward once without accessing either native allocation. The
        // native call and its descriptor writes execute outside Rust CS.
        let status = unsafe { set_ctrl(descriptor, netbuf) };
        critical_section::with(|cs| {
            TRACKER
                .borrow_ref_mut(cs)
                .bind(descriptor.addr(), netbuf.addr(), epoch, status)
        });
        status
    }

    pub(crate) fn observe_delivery(netbuf: *mut c_void) {
        let epoch = super::super::NATIVE_RX_ROUTE.allocation_epoch();
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).delivered(netbuf.addr(), epoch));
    }

    pub(crate) fn diagnostics() -> RxOriginDiagnostics {
        critical_section::with(|cs| TRACKER.borrow_ref(cs).diagnostic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(revision: u64) -> AllocationEpoch {
        AllocationEpoch {
            revision: Some(revision),
        }
    }

    #[test]
    fn free_route_rejects_a_foreign_or_bypassing_callback() {
        assert!(free_route_valid(10, 10, 0));
        for (current, expected, pbuf) in [(0, 10, 0), (11, 10, 0), (10, 10, 1), (0, 0, 0)] {
            assert!(!free_route_valid(current, expected, pbuf));
        }
    }

    fn conserved<const N: usize>(tracker: &Tracker<N>) {
        let d = tracker.diagnostic;
        assert!(!d.exhausted);
        assert_eq!(
            d.bindings,
            d.matched + d.replaced + d.retired_on_free_attempt + d.occupied as u64
        );
        assert_eq!(
            d.matched,
            d.closed_origin + d.current_origin + d.stale_origin
        );
        assert_eq!(
            d.occupied,
            tracker.netbufs.iter().filter(|entry| **entry != 0).count()
        );
    }

    #[test]
    fn origin_is_not_retagged_when_delivery_crosses_close() {
        let mut t = Tracker::<2>::new();
        t.bind(1, 11, epoch(1), 0);
        t.bind(2, 22, AllocationEpoch::CLOSED, 0);
        t.delivered(11, epoch(2));
        t.delivered(22, epoch(2));
        assert_eq!(t.diagnostic.stale_origin, 1);
        assert_eq!(t.diagnostic.closed_origin, 1);
        assert_eq!(t.diagnostic.current_origin, 0);
        conserved(&t);
    }

    #[test]
    fn undelivered_native_frees_do_not_accumulate_live_observations() {
        let mut t = Tracker::<1>::new();
        for identity in 1..100 {
            t.bind(identity, identity + 100, epoch(1), 0);
            t.before_free(identity + 100);
            conserved(&t);
        }
        assert_eq!(t.diagnostic.capacity_failures, 0);
        assert_eq!(t.diagnostic.retired_on_free_attempt, 99);
        assert_eq!(t.diagnostic.free_calls, 99);
        assert_eq!(t.diagnostic.occupied, 0);
    }

    #[test]
    fn free_attempt_cannot_certify_delivery_or_retag_a_reused_buffer() {
        let mut t = Tracker::<2>::new();
        t.bind(1, 11, epoch(1), 0);
        t.bind(2, 22, epoch(1), 0);
        for pointer in [0, 99, 11, 11] {
            t.before_free(pointer);
        }
        assert_eq!(t.diagnostic.retired_on_free_attempt, 1);
        assert_eq!(t.diagnostic.occupied, 1);
        t.delivered(11, epoch(2));
        assert_eq!(t.diagnostic.unmatched, 1);
        t.bind(3, 11, epoch(2), 0);
        t.delivered(11, epoch(2));
        t.delivered(22, epoch(2));
        assert_eq!(t.diagnostic.current_origin, 1);
        assert_eq!(t.diagnostic.stale_origin, 1);
        conserved(&t);
    }

    #[test]
    fn duplicate_or_unknown_delivery_never_fabricates_an_origin() {
        let mut t = Tracker::<1>::new();
        t.bind(1, 11, epoch(1), 0);
        t.delivered(11, epoch(1));
        for value in [11, 12, 0] {
            t.delivered(value, epoch(1));
        }
        assert_eq!(t.diagnostic.current_origin, 1);
        assert_eq!(t.diagnostic.unmatched, 3);
        conserved(&t);
    }

    #[test]
    fn reused_descriptor_and_buffer_remove_both_old_observations() {
        let mut t = Tracker::<2>::new();
        t.bind(1, 11, epoch(1), 0);
        t.bind(2, 22, epoch(1), 0);
        t.bind(1, 22, epoch(2), 0);
        assert_eq!(t.diagnostic.replaced, 2);
        t.delivered(11, epoch(2));
        t.delivered(22, epoch(2));
        assert_eq!(t.diagnostic.current_origin, 1);
        assert_eq!(t.diagnostic.unmatched, 1);
        conserved(&t);
    }

    #[test]
    fn failed_binding_invalidates_previous_observation_but_does_not_insert() {
        let mut t = Tracker::<1>::new();
        t.bind(1, 11, epoch(1), 0);
        t.bind(1, 11, epoch(2), 100);
        for (descriptor, netbuf) in [(0, 1), (1, 0), (0, 0)] {
            t.bind(descriptor, netbuf, epoch(2), 0);
        }
        t.delivered(11, epoch(2));
        assert_eq!(t.diagnostic.failed_bindings, 4);
        assert_eq!(t.diagnostic.unmatched, 1);
        conserved(&t);
    }

    #[test]
    fn capacity_exhaustion_does_not_evict_an_unrelated_binding() {
        let mut t = Tracker::<1>::new();
        t.bind(1, 11, epoch(1), 0);
        t.bind(2, 22, epoch(2), 0);
        t.delivered(11, epoch(2));
        t.delivered(22, epoch(2));
        assert_eq!(t.diagnostic.capacity_failures, 1);
        assert_eq!(t.diagnostic.stale_origin, 1);
        assert_eq!(t.diagnostic.unmatched, 1);
        conserved(&t);
    }

    #[test]
    fn saturation_invalidates_the_census_without_wrapping() {
        let mut t = Tracker::<0>::new();
        t.diagnostic.unmatched = u64::MAX;
        t.delivered(1, epoch(1));
        assert!(t.diagnostic.exhausted);
        assert_eq!(t.diagnostic.unmatched, u64::MAX);
    }
}
