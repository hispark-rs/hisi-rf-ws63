//! WS63 BGLE Secure Connections crypto compatibility.

use core::ptr;

use hisi_crypto::p256::P256PrivateKey;
use hisi_crypto::sae::P256AffinePoint;
use portable_atomic::{AtomicU32, Ordering};

#[unsafe(no_mangle)]
pub static RFDBG_BLE_SC_ECDH_CALLS: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static RFDBG_BLE_SC_ECDH_FAILURES: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static RFDBG_BLE_SC_KEYGEN_CALLS: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static RFDBG_BLE_SC_KEYGEN_FAILURES: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    fn __real_smp_ecdh_public_key_reserv(private_key: *mut u8, public_key: *mut u8);
    fn __real_smp_ecdh_dh_key_reserv(
        private_key: *const u8,
        peer_public_key: *const u8,
        output: *mut u8,
    );
}

fn crypto_fatal(marker: &[u8]) -> ! {
    crate::log_emit(marker);
    crate::libc::panic()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_smp_ecdh_public_key_reserv(
    private_key: *mut u8,
    public_key: *mut u8,
) {
    RFDBG_BLE_SC_KEYGEN_CALLS.fetch_add(1, Ordering::Relaxed);
    if private_key.is_null() || public_key.is_null() {
        RFDBG_BLE_SC_KEYGEN_FAILURES.fetch_add(1, Ordering::Relaxed);
        crypto_fatal(b"RFDBG_BLE_SC_KEYGEN_ABI_ERR\r\n");
    }

    let pair = match crate::crypto::p256_generate_keypair_hardware() {
        Ok(pair) => pair,
        Err(_) => {
            RFDBG_BLE_SC_KEYGEN_FAILURES.fetch_add(1, Ordering::Relaxed);
            crypto_fatal(b"RFDBG_BLE_SC_KEYGEN_HW_ERR\r\n");
        }
    };
    let mut scalar = *pair.private().expose_secret();
    let mut public_x = pair.public().x;
    let mut public_y = pair.public().y;
    scalar.reverse();
    public_x.reverse();
    public_y.reverse();

    // Preserve the vendor mpint scratch init/free lifecycle, then replace the
    // generated pair atomically from the protocol's perspective.
    unsafe { __real_smp_ecdh_public_key_reserv(private_key, public_key) };
    unsafe {
        ptr::copy_nonoverlapping(scalar.as_ptr(), private_key, 32);
        ptr::copy_nonoverlapping(public_x.as_ptr(), public_key, 32);
        ptr::copy_nonoverlapping(public_y.as_ptr(), public_key.add(32), 32);
    }
    scalar.fill(0);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_smp_ecdh_dh_key_reserv(
    private_key: *const u8,
    peer_public_key: *const u8,
    output: *mut u8,
) {
    RFDBG_BLE_SC_ECDH_CALLS.fetch_add(1, Ordering::Relaxed);
    if private_key.is_null() || peer_public_key.is_null() || output.is_null() {
        RFDBG_BLE_SC_ECDH_FAILURES.fetch_add(1, Ordering::Relaxed);
        crypto_fatal(b"RFDBG_BLE_SC_ECDH_ABI_ERR\r\n");
    }

    let mut scalar = [0_u8; 32];
    let mut peer_x = [0_u8; 32];
    let mut peer_y = [0_u8; 32];
    // SAFETY: the vendor SMP ABI supplies fixed 32-byte private, X, and Y
    // fields for the duration of this synchronous call.
    unsafe {
        ptr::copy_nonoverlapping(private_key, scalar.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(peer_public_key, peer_x.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(peer_public_key.add(32), peer_y.as_mut_ptr(), 32);
    }

    // The vendor mpint scratch ABI stores each 256-bit value least-significant
    // byte first. A ROM differential on both WS63 peers proved this exact
    // conversion for the private scalar, peer coordinates, and output DHKey.
    scalar.reverse();
    peer_x.reverse();
    peer_y.reverse();
    let result = P256PrivateKey::try_from_be_bytes(scalar).and_then(|private| {
        crate::crypto::p256_ecdh_hardware(private, &P256AffinePoint::new(peer_x, peer_y))
    });

    match result {
        Ok(secret) => {
            let mut bytes = *secret.expose_secret();
            bytes.reverse();
            // Preserve the vendor mpint scratch init/free lifecycle. Its DHKey
            // result is deliberately overwritten by the already-completed
            // Rust PKE result, so this is not a crypto fallback.
            unsafe { __real_smp_ecdh_dh_key_reserv(private_key, peer_public_key, output) };
            // SAFETY: the vendor ABI provides a writable 32-byte output.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, 32) };
            bytes.fill(0);
        }
        Err(_) => {
            RFDBG_BLE_SC_ECDH_FAILURES.fetch_add(1, Ordering::Relaxed);
            crypto_fatal(b"RFDBG_BLE_SC_ECDH_HW_ERR\r\n");
        }
    }
    scalar.fill(0);
}
