//! OAL allocation hooks not supplied by the WS63 mask ROM.
//!
//! The packet-RAM pool itself is owned by the original mask-ROM OAL
//! implementation. In particular, `oal_memory_init(start, end, cfg, count)`,
//! `oal_mem_rsv`, netbuf allocation/free, and the netbuf accessors must resolve
//! to `ws63_acore_rom.lds`: the Wi-Fi closure passes the vendor sub-pool table
//! and the ROM carves the RX/TX descriptor buffers exactly as silicon expects.
//! This module only supplies the general heap hooks that the application OS is
//! required to implement.

use core::ffi::c_void;

// ── General OAL allocation (driver structures, not packet RAM) ───────────────
// The generic OSAL ABI uses the bare one-argument functions below. The Wi-Fi
// driver's three-argument `oal_mem_alloc(pool_id, len, lock)` spelling is a C
// macro that expands to the separately owned `oal_mem_alloc_etc(...)` symbol.
// These ABIs must not be conflated: the Bluetooth archive calls the bare symbol
// with only `a0` initialized.

/// Allocate `size` bytes from the general heap.
#[unsafe(no_mangle)]
pub extern "C" fn oal_mem_alloc(size: core::ffi::c_uint) -> *mut c_void {
    crate::alloc::osal_kmalloc(size as usize)
}

/// Free a block from [`oal_mem_alloc`].
#[unsafe(no_mangle)]
pub extern "C" fn oal_mem_free(ptr: *mut c_void) -> core::ffi::c_uint {
    crate::alloc::osal_kfree(ptr);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_oal_allocator_uses_the_single_argument_abi() {
        const LIST_NODE_HEADER_BYTES: usize = 8;
        const PAYLOAD_BYTES: usize = 8;
        const ALLOCATION_BYTES: usize = LIST_NODE_HEADER_BYTES + PAYLOAD_BYTES;

        let ptr = oal_mem_alloc(ALLOCATION_BYTES as u32).cast::<u8>();
        assert!(!ptr.is_null());
        // SAFETY: the OAL adapter returned a live allocation of this length.
        assert!(
            unsafe { core::slice::from_raw_parts(ptr, ALLOCATION_BYTES) }
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(oal_mem_free(ptr.cast()), 0);
    }
}
