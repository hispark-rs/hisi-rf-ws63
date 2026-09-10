//! Checked allocation round-trip with application admission still sealed.
//!
//! Counts describe native software lists, not DMA ownership. In particular,
//! successful reconstruction is not permission to reopen the network device.

const PRECONDITION: i32 = -0x1025;
const INCOMPLETE: i32 = -0x1026;
const CONFIG_CHANGED: i32 = -0x1027;
const CLEANUP: i32 = -0x1028;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Counts {
    /// Native queue order: normal, high, small (not the configuration order).
    pub actual: [u16; 3],
    pub expected: [u16; 3],
}

/// Immediate descriptor allocation/cleanup observations, never a DMA fence.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxRebuildDiagnostics {
    pub expected: [u16; 3],
    pub actual: [u16; 3],
    pub cleaned: [u16; 3],
    pub mac_after_init: u8,
    pub mac_after_cleanup: u8,
    pub attempted: bool,
    pub cleanup_attempted: bool,
    pub init_status: i32,
    pub cleanup_status: i32,
    pub fault: i32,
}

const _: () = assert!(core::mem::size_of::<RxRebuildDiagnostics>() == 36);

pub(super) trait DescriptorOps {
    fn counts(&self) -> Counts;
    fn mac_enabled(&self) -> u8;
    fn initialize(&mut self) -> i32;
    fn disable(&mut self);
    fn destroy(&mut self) -> i32;
}

/// The caller has established the device-worker identity and sealed admission.
/// No callback/operation below runs under a Rust critical section. Always try
/// cleanup after an attempted initialization, including partial native failure.
pub(super) fn probe(ops: &mut impl DescriptorOps) -> RxRebuildDiagnostics {
    let before = ops.counts();
    let mut result = RxRebuildDiagnostics {
        expected: before.expected,
        mac_after_init: 0xff,
        mac_after_cleanup: 0xff,
        ..RxRebuildDiagnostics::default()
    };
    if before.actual != [0; 3] || before.expected == [0; 3] || ops.mac_enabled() != 0 {
        result.fault = PRECONDITION;
        return result;
    }
    result.attempted = true;
    result.init_status = ops.initialize();
    result.mac_after_init = ops.mac_enabled();
    let after = ops.counts();
    result.actual = after.actual;
    result.fault = if result.init_status != 0 {
        result.init_status
    } else if result.mac_after_init != 0 {
        super::MAC_ENABLED
    } else if after.expected != before.expected {
        CONFIG_CHANGED
    } else if after.actual != before.expected {
        INCOMPLETE
    } else {
        0
    };

    // A native re-enable is a failed experiment, not permission to free active
    // lists. Keep the first error, but also report cleanup status separately.
    ops.disable();
    if ops.mac_enabled() == 0 {
        result.cleanup_attempted = true;
        result.cleanup_status = ops.destroy();
    } else {
        result.cleanup_status = super::MAC_ENABLED;
    }
    result.mac_after_cleanup = ops.mac_enabled();
    let final_counts = ops.counts();
    result.cleaned = final_counts.actual;
    if result.fault == 0 {
        result.fault = if result.cleanup_status != 0 {
            result.cleanup_status
        } else if result.mac_after_cleanup != 0 || result.cleaned != [0; 3] {
            CLEANUP
        } else if final_counts.expected != before.expected {
            CONFIG_CHANGED
        } else {
            0
        };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        snapshots: [Counts; 3],
        phase: usize,
        status: i32,
        cleanup_status: i32,
        mac: u8,
        init_mac: u8,
        disable_works: bool,
        calls: [u8; 3],
    }

    impl Fake {
        fn complete() -> Self {
            let expected = [48, 8, 16];
            Self {
                snapshots: [
                    Counts {
                        actual: [0; 3],
                        expected,
                    },
                    Counts {
                        actual: expected,
                        expected,
                    },
                    Counts {
                        actual: [0; 3],
                        expected,
                    },
                ],
                phase: 0,
                status: 0,
                cleanup_status: 0,
                mac: 0,
                init_mac: 0,
                disable_works: true,
                calls: [0; 3],
            }
        }
    }

    impl DescriptorOps for Fake {
        fn counts(&self) -> Counts {
            self.snapshots[self.phase]
        }
        fn mac_enabled(&self) -> u8 {
            self.mac
        }
        fn initialize(&mut self) -> i32 {
            self.calls[0] += 1;
            self.phase = 1;
            self.mac = self.init_mac;
            self.status
        }
        fn disable(&mut self) {
            self.calls[1] += 1;
            if self.disable_works {
                self.mac = 0;
            }
        }
        fn destroy(&mut self) -> i32 {
            assert_eq!(self.mac, 0);
            self.calls[2] += 1;
            self.phase = 2;
            self.cleanup_status
        }
    }

    #[test]
    fn complete_roundtrip_still_destroys_rebuilt_descriptors() {
        let mut ops = Fake::complete();
        let report = probe(&mut ops);
        assert_eq!(report.fault, 0);
        assert_eq!(report.expected, report.actual);
        assert_eq!(report.cleaned, [0; 3]);
        assert_eq!(ops.calls, [1, 1, 1]);
    }

    #[test]
    fn zero_success_status_and_nonempty_are_not_allocation_success() {
        for queue in 0..3 {
            for missing in [1, Fake::complete().snapshots[1].actual[queue]] {
                let mut ops = Fake::complete();
                ops.snapshots[1].actual[queue] -= missing;
                let report = probe(&mut ops);
                assert_eq!(report.init_status, 0);
                assert_eq!(report.fault, INCOMPLETE);
                assert_eq!(ops.calls, [1, 1, 1]);
                assert_eq!(report.cleaned, [0; 3]);
            }
        }
    }

    #[test]
    fn configuration_drift_and_count_permutation_are_rejected() {
        let mut ops = Fake::complete();
        ops.snapshots[1].expected[0] -= 1;
        assert_eq!(probe(&mut ops).fault, CONFIG_CHANGED);
        let mut ops = Fake::complete();
        ops.snapshots[1].actual.swap(1, 2);
        assert_eq!(probe(&mut ops).fault, INCOMPLETE);
        let mut ops = Fake::complete();
        ops.snapshots[2].expected[0] -= 1;
        assert_eq!(probe(&mut ops).fault, CONFIG_CHANGED);
    }

    #[test]
    fn invalid_preconditions_never_invoke_native_mutation() {
        for mode in 0..3 {
            let mut ops = Fake::complete();
            match mode {
                0 => ops.mac = 1,
                1 => ops.snapshots[0].actual[0] = 1,
                _ => ops.snapshots[0].expected = [0; 3],
            }
            assert_eq!(probe(&mut ops).fault, PRECONDITION);
            assert_eq!(ops.calls, [0; 3]);
        }
    }

    #[test]
    fn native_error_always_cleans_up_but_preserves_first_failure() {
        let mut ops = Fake::complete();
        ops.status = 51;
        ops.cleanup_status = 52;
        let report = probe(&mut ops);
        assert_eq!(report.fault, 51);
        assert_eq!(report.cleanup_status, 52);
        assert_eq!(ops.calls, [1, 1, 1]);
    }

    #[test]
    fn reenable_is_rejected_and_cannot_free_while_enabled() {
        for disable_works in [false, true] {
            let mut ops = Fake::complete();
            ops.init_mac = 1;
            ops.disable_works = disable_works;
            let report = probe(&mut ops);
            assert_eq!(report.fault, super::super::MAC_ENABLED);
            assert_eq!(report.cleanup_attempted, disable_works);
            assert_eq!(ops.calls, [1, 1, u8::from(disable_works)]);
        }
    }

    #[test]
    fn cleanup_return_alone_cannot_hide_remaining_descriptors() {
        let mut ops = Fake::complete();
        ops.snapshots[2].actual[2] = 1;
        assert_eq!(probe(&mut ops).fault, CLEANUP);
        let mut ops = Fake::complete();
        ops.cleanup_status = 52;
        assert_eq!(probe(&mut ops).fault, 52);
    }
}
