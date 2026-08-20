//! UAPI platform services (ws63-RF `port_uapi.h`).
//!
//! Timekeeping delegates to the WS63 mask-ROM systick/TCXO drivers using the
//! vendor platform ROM-data initializer linked at its fixed DTCM ABI.
//! `uapi_nv_read` is backed by the official WS63 ACPU KV partition and validates
//! its page/key metadata and CRC. `uapi_tsensor_get_current_temp` remains a fixed
//! conservative value until the HAL sensor path is wired into the RF adapter.

// C-ABI entry points: the blob passes valid pointers; the safety contract is
// the C signature, not a Rust `unsafe` marker.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;
#[cfg(target_arch = "riscv32")]
use hisi_nvs::{NvConfig, NvError, NvKey, NvReader, NvWriter};
#[cfg(target_arch = "riscv32")]
use hisi_storage::{EraseStorage, MemoryMappedStorage, ReadStorage, WriteStorage};
use portable_atomic::{AtomicBool, Ordering};

static EFUSE_READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "riscv32")]
static TIMEBASE_READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "riscv32")]
static NV_WRITE_CLAIMED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "riscv32")]
pub(crate) fn enable_efuse_reads() {
    EFUSE_READY.store(true, Ordering::Release);
}

fn trace_nv(key: u16, max_len: u16, actual_len: u16, result: u32) {
    #[cfg(feature = "rf-init-diag")]
    crate::rf_init_diag::trace_nv(key, max_len, actual_len, result);
    #[cfg(not(feature = "rf-init-diag"))]
    let _ = (key, max_len, actual_len, result);
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    #[link_name = "uapi_systick_get_ms"]
    fn rom_systick_get_ms() -> u64;
    #[link_name = "uapi_systick_get_count"]
    fn rom_systick_get_count() -> u64;
    #[link_name = "uapi_tcxo_get_us"]
    fn rom_tcxo_get_us() -> u64;
    #[link_name = "uapi_tcxo_delay_us"]
    fn rom_tcxo_delay_us(usec: u32) -> u32;
    fn uapi_systick_init();
    fn uapi_tcxo_init() -> u32;
    static mut g_systick_clock: u32;
    static g_sfc_v150_funcs: u8;
    static mut g_flash_ctrl: FlashControl;
    static mut g_sfc_inited: u8;
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct FlashControl {
    chip_size: u32,
    read_operation: u32,
    erase_command_count: u32,
    write_operation: u32,
    erase_commands: *const u32,
    quad_mode: *const FlashCommand,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct FlashCommand {
    command_type: u32,
    command_length: u8,
    command: [u8; 4],
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct FlashInfo {
    chip_id: u32,
    chip_size: u32,
    erase_command_count: u32,
    read_commands: *const u32,
    write_commands: *const u32,
    erase_commands: *const u32,
    quad_mode: *const FlashCommand,
}

// SAFETY: every pointer targets an immutable static table for the complete
// firmware lifetime. The ROM consumes the descriptor synchronously/read-only.
#[cfg(target_arch = "riscv32")]
unsafe impl Sync for FlashInfo {}

#[cfg(target_arch = "riscv32")]
const fn flash_operation(command: u8, size: u32) -> u32 {
    1 | ((command as u32) << 3) | (size << 14)
}

#[cfg(target_arch = "riscv32")]
static DEFAULT_READ_COMMANDS: [u32; 1] = [flash_operation(0x03, 0)];
#[cfg(target_arch = "riscv32")]
static DEFAULT_WRITE_COMMANDS: [u32; 2] = [flash_operation(0, 0), flash_operation(0x02, 0)];
#[cfg(target_arch = "riscv32")]
static DEFAULT_ERASE_COMMANDS: [u32; 3] = [
    flash_operation(0xc7, 0x3ffff),
    flash_operation(0xd8, 0x10000),
    flash_operation(0x20, 0x1000),
];
#[cfg(target_arch = "riscv32")]
static DEFAULT_QUAD_MODE: [FlashCommand; 1] = [FlashCommand {
    command_type: 2, // FLASH_CMD_TYPE_END
    command_length: 0,
    command: [0; 4],
}];
#[cfg(target_arch = "riscv32")]
static DEFAULT_FLASH_INFO: FlashInfo = FlashInfo {
    chip_id: 0x00ff_ffff,
    chip_size: 0x0008_0000,
    erase_command_count: 3,
    read_commands: DEFAULT_READ_COMMANDS.as_ptr(),
    write_commands: DEFAULT_WRITE_COMMANDS.as_ptr(),
    erase_commands: DEFAULT_ERASE_COMMANDS.as_ptr(),
    quad_mode: DEFAULT_QUAD_MODE.as_ptr(),
};

// These callbacks are part of the public WS63 ROM port ABI. The values mirror
// the Apache-2.0 SDK SFC port and are deliberately kept narrower than a second
// SFC driver implementation.
#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_get_sfc_start_addr() -> usize {
    0x0020_0000
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_get_sfc_end_addr() -> usize {
    0x009f_ffff
}

macro_rules! sfc_register_base_callback {
    ($name:ident, $address:expr) => {
        #[cfg(target_arch = "riscv32")]
        #[unsafe(no_mangle)]
        extern "C" fn $name() -> usize {
            $address
        }
    };
}

sfc_register_base_callback!(sfc_port_get_sfc_global_conf_base_addr, 0x4800_0100);
sfc_register_base_callback!(sfc_port_get_sfc_bus_regs_base_addr, 0x4800_0200);
sfc_register_base_callback!(sfc_port_get_sfc_bus_dma_regs_base_addr, 0x4800_0240);
sfc_register_base_callback!(sfc_port_get_sfc_cmd_regs_base_addr, 0x4800_0300);
sfc_register_base_callback!(sfc_port_get_sfc_cmd_databuf_base_addr, 0x4800_0400);

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_get_delay_once_time() -> u32 {
    100
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_get_delay_times() -> u32 {
    50_000
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_get_unknown_flash_info() -> *const FlashInfo {
    &raw const DEFAULT_FLASH_INFO
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_lock() -> u32 {
    crate::osal::osal_irq_lock()
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn sfc_port_unlock(state: u32) {
    crate::osal::osal_irq_restore(state);
}

#[cfg(target_arch = "riscv32")]
unsafe fn sfc_set_volatile_status(command: u8, value: u8) -> bool {
    let register = match command {
        0x01 => hisi_hal::sfc::FlashStatusRegister::One,
        0x31 => hisi_hal::sfc::FlashStatusRegister::Two,
        _ => return false,
    };
    // SAFETY: `NvWriteClaim` gives the RF composition root exclusive runtime
    // SFC command ownership. Flashboot's XIP configuration is retained; this
    // driver instance only emits the status-register command sequence.
    let mut sfc = hisi_hal::sfc::SfcDriver::new(unsafe { hisi_hal::peripherals::SfcCfg::steal() });
    sfc.write_volatile_status(register, value).is_ok()
}

#[cfg(target_arch = "riscv32")]
struct NvFlashWriteGuard {
    irq_state: u32,
}

#[cfg(target_arch = "riscv32")]
struct NvFlashReadGuard {
    irq_state: u32,
}

#[cfg(target_arch = "riscv32")]
impl NvFlashReadGuard {
    fn acquire() -> Self {
        Self {
            irq_state: crate::osal::osal_irq_lock(),
        }
    }
}

#[cfg(target_arch = "riscv32")]
impl Drop for NvFlashReadGuard {
    fn drop(&mut self) {
        crate::osal::osal_irq_restore(self.irq_state);
    }
}

#[cfg(target_arch = "riscv32")]
impl NvFlashWriteGuard {
    fn acquire() -> Option<Self> {
        // APP protection profile: expose only [0x3fc000, 0x400000), which is
        // the linker-owned NV partition. The mask-ROM SFC UAPI predates the
        // SDK's `sfc_port_write_lock` hook, so the storage backend must own this
        // protection window explicitly.
        let irq_state = crate::osal::osal_irq_lock();
        if unsafe { sfc_set_volatile_status(0x01, 0x4c) }
            && unsafe { sfc_set_volatile_status(0x31, 0x42) }
        {
            Some(Self { irq_state })
        } else {
            // A failure after SR1 succeeded must not leave a partially opened
            // protection window behind.
            let _ = unsafe { sfc_set_volatile_status(0x01, 0x1c) };
            let _ = unsafe { sfc_set_volatile_status(0x31, 0x02) };
            crate::osal::osal_irq_restore(irq_state);
            None
        }
    }
}

#[cfg(target_arch = "riscv32")]
impl Drop for NvFlashWriteGuard {
    fn drop(&mut self) {
        let _ = unsafe { sfc_set_volatile_status(0x01, 0x1c) };
        let _ = unsafe { sfc_set_volatile_status(0x31, 0x02) };
        // Unlike a debugger flash algorithm, the running application resumes
        // XIP immediately after this guard. Do not issue RSTEN/RST here: a NOR
        // reset may clear volatile bus-mode state established by flashboot.
        // The bounded status writes already wait for WIP and leave command mode
        // idle before interrupts are restored.
        crate::osal::osal_irq_restore(self.irq_state);
    }
}

#[cfg(target_arch = "riscv32")]
pub(crate) fn initialize_rom_sfc() -> u32 {
    // Flashboot has already configured the SFC bus used to execute this XIP
    // image. Re-running `uapi_sfc_init[_rom]` here rewrites that live mapping
    // and faults before returning. Adopt the existing hardware state by
    // populating only the mask-ROM driver's software control block.
    // The ROM helpers at 0x109ab8/0x109508 contain vendor-only `l.li`
    // instructions that stock rustc cannot emit and this core cannot execute.
    // Their complete behavior is to return `g_sfc_v150_funcs` at 0x180000.
    // The mask-ROM SFC UAPI reads the active vtable from 0x1803f8
    // (0x1092e6/0x109328 in the mask ROM). The public HAL registration helper
    // uses a separate slot at 0x180400.
    const ROM_SFC_FUNCS_SLOT: *mut *const u8 = 0x0018_03f8 as *mut *const u8;
    const ROM_SFC_BUS_DMA_REGS: *mut usize = 0x0018_0404 as *mut usize;
    const ROM_SFC_BUS_REGS: *mut usize = 0x0018_0408 as *mut usize;
    const ROM_SFC_CMD_DATABUF: *mut usize = 0x0018_040c as *mut usize;
    const ROM_SFC_CMD_REGS: *mut usize = 0x0018_0410 as *mut usize;
    const ROM_SFC_GLOBAL_CONF_REGS: *mut usize = 0x0018_0414 as *mut usize;
    let irq_state = crate::osal::osal_irq_lock();
    // SAFETY: called once before vendor tasks start. These fixed RAM symbols
    // are the documented WS63 ROM ABI and the pointed-to tables are immutable
    // for the firmware lifetime.
    unsafe {
        core::ptr::write_volatile(ROM_SFC_FUNCS_SLOT, &raw const g_sfc_v150_funcs);
        // Mirror `hal_sfc_regs_init`: initialize only the ROM driver's cached
        // MMIO pointers. This does not write the SFC controller or disturb the
        // flashboot-established XIP mapping.
        core::ptr::write_volatile(ROM_SFC_GLOBAL_CONF_REGS, 0x4800_0100);
        core::ptr::write_volatile(ROM_SFC_BUS_REGS, 0x4800_0200);
        core::ptr::write_volatile(ROM_SFC_BUS_DMA_REGS, 0x4800_0240);
        core::ptr::write_volatile(ROM_SFC_CMD_REGS, 0x4800_0300);
        core::ptr::write_volatile(ROM_SFC_CMD_DATABUF, 0x4800_0400);
        core::ptr::write_volatile(
            &raw mut g_flash_ctrl,
            FlashControl {
                chip_size: 0x0040_0000,
                read_operation: flash_operation(0x03, 0),
                erase_command_count: DEFAULT_ERASE_COMMANDS.len() as u32,
                write_operation: flash_operation(0x02, 0),
                erase_commands: DEFAULT_ERASE_COMMANDS.as_ptr(),
                quad_mode: DEFAULT_QUAD_MODE.as_ptr(),
            },
        );
        core::ptr::write_volatile(&raw mut g_sfc_inited, 1);
    }
    crate::osal::osal_irq_restore(irq_state);
    crate::log_emit(b"RFDBG_BLE_B1_SFC_REGISTER_DONE\r\n");
    0
}

#[cfg(target_arch = "riscv32")]
const WS63_FLASH_BASE: usize = 0x0020_0000;

#[cfg(target_arch = "riscv32")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RomNvStorageError {
    OutOfBounds,
    Rom(u32),
}

#[cfg(target_arch = "riscv32")]
struct RomNvStorage {
    flash_offset: u32,
    length: usize,
}

#[cfg(target_arch = "riscv32")]
impl RomNvStorage {
    fn from_linker_region() -> Option<Self> {
        unsafe extern "C" {
            static __nv_storage_start: u8;
            static __nv_storage_length: u8;
        }

        let start = &raw const __nv_storage_start as usize;
        let length = &raw const __nv_storage_length as usize;
        let flash_offset = start.checked_sub(WS63_FLASH_BASE)?.try_into().ok()?;
        Some(Self {
            flash_offset,
            length,
        })
    }

    fn checked_range(&self, offset: u32, length: usize) -> Result<u32, RomNvStorageError> {
        let relative = usize::try_from(offset).map_err(|_| RomNvStorageError::OutOfBounds)?;
        relative
            .checked_add(length)
            .filter(|end| *end <= self.length)
            .ok_or(RomNvStorageError::OutOfBounds)?;
        self.flash_offset
            .checked_add(offset)
            .ok_or(RomNvStorageError::OutOfBounds)
    }
}

#[cfg(target_arch = "riscv32")]
impl ReadStorage for RomNvStorage {
    type Error = RomNvStorageError;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let mut absolute = self.checked_range(offset, bytes.len())?;
        // XIP reads can retain stale prefetched data after a command-mode
        // program or erase. The writer therefore reads through the SRAM SFC
        // command path so its verify and GC decisions observe the transaction
        // it just committed. Interrupts stay disabled while the controller is
        // borrowed because handlers execute from the same XIP mapping.
        let _command = NvFlashReadGuard::acquire();
        let mut sfc =
            hisi_hal::sfc::SfcDriver::new(unsafe { hisi_hal::peripherals::SfcCfg::steal() });
        for chunk in bytes.chunks_mut(64) {
            sfc.read_chunk(absolute, chunk)
                .map_err(|_| RomNvStorageError::Rom(1))?;
            absolute = absolute
                .checked_add(chunk.len() as u32)
                .ok_or(RomNvStorageError::OutOfBounds)?;
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.length
    }
}

#[cfg(target_arch = "riscv32")]
impl WriteStorage for RomNvStorage {
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        crate::log_emit(b"RFDBG_SFC_WRITE_BEGIN\r\n");
        let _protection = NvFlashWriteGuard::acquire().ok_or(RomNvStorageError::Rom(1))?;
        let mut absolute = self.checked_range(offset, bytes.len())?;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let command_boundary = 64 - (absolute as usize & 63);
            let page_boundary = 256 - (absolute as usize & 255);
            let chunk_len = remaining.len().min(command_boundary).min(page_boundary);
            let (chunk, rest) = remaining.split_at(chunk_len);
            crate::log_emit(b"RFDBG_SFC_WRITE_CHUNK_BEGIN\r\n");

            // The mask-ROM writer has an unbounded post-program WIP poll on
            // this silicon revision. Use the HAL's bounded command sequence.
            // `NvWriteClaim` serializes runtime writers. The protection guard
            // also keeps interrupts disabled because interrupt handlers execute
            // from the same SFC-backed XIP mapping.
            let mut sfc =
                hisi_hal::sfc::SfcDriver::new(unsafe { hisi_hal::peripherals::SfcCfg::steal() });
            let result = sfc.program_chunk(absolute, chunk);
            crate::log_emit(b"RFDBG_SFC_WRITE_CHUNK_DONE\r\n");
            if result.is_err() {
                return Err(RomNvStorageError::Rom(1));
            }
            let mut readback = [0_u8; 64];
            if sfc
                .read_chunk(absolute, &mut readback[..chunk_len])
                .is_err()
                || readback[..chunk_len] != *chunk
            {
                return Err(RomNvStorageError::Rom(1));
            }

            absolute = absolute
                .checked_add(chunk_len as u32)
                .ok_or(RomNvStorageError::OutOfBounds)?;
            remaining = rest;
        }
        crate::log_emit(b"RFDBG_SFC_WRITE_DONE\r\n");
        Ok(())
    }
}

#[cfg(target_arch = "riscv32")]
impl EraseStorage for RomNvStorage {
    fn erase_size(&self) -> usize {
        hisi_nvs::WS63_PAGE_SIZE
    }

    fn erase(&mut self, offset: u32, length: usize) -> Result<(), Self::Error> {
        let erase_size = self.erase_size();
        if length != erase_size || (offset as usize).checked_rem(erase_size) != Some(0) {
            return Err(RomNvStorageError::OutOfBounds);
        }
        let absolute = self.checked_range(offset, length)?;
        crate::log_emit(b"RFDBG_NV_GC_ERASE_BEGIN\r\n");
        let _protection = NvFlashWriteGuard::acquire().ok_or(RomNvStorageError::Rom(1))?;
        let mut sfc =
            hisi_hal::sfc::SfcDriver::new(unsafe { hisi_hal::peripherals::SfcCfg::steal() });
        sfc.erase_sector_4k(absolute)
            .map_err(|_| RomNvStorageError::Rom(1))?;

        let mut readback = [0_u8; 64];
        for checked in (0..length).step_by(readback.len()) {
            sfc.read_chunk(absolute + checked as u32, &mut readback)
                .map_err(|_| RomNvStorageError::Rom(1))?;
            if readback.iter().any(|byte| *byte != 0xff) {
                return Err(RomNvStorageError::Rom(1));
            }
        }
        crate::log_emit(b"RFDBG_NV_GC_ERASE_DONE\r\n");
        Ok(())
    }
}

#[cfg(target_arch = "riscv32")]
struct NvWriteClaim;

#[cfg(target_arch = "riscv32")]
impl NvWriteClaim {
    fn try_acquire() -> Option<Self> {
        NV_WRITE_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

#[cfg(target_arch = "riscv32")]
impl Drop for NvWriteClaim {
    fn drop(&mut self) {
        NV_WRITE_CLAIMED.store(false, Ordering::Release);
    }
}

#[cfg(target_arch = "riscv32")]
unsafe fn calibrate_systick_clock() {
    const CALIBRATION_US: u32 = 100_000;

    trace_timebase_detail(b"systick_count_start", b"begin");
    let systick_start = unsafe { rom_systick_get_count() };
    trace_timebase_detail(b"systick_count_start", b"completed");
    trace_timebase_detail(b"tcxo_count_start", b"begin");
    let tcxo_start = unsafe { rom_tcxo_get_us() };
    trace_timebase_detail(b"tcxo_count_start", b"completed");
    trace_timebase_detail(b"tcxo_delay", b"begin");
    let _ = unsafe { rom_tcxo_delay_us(CALIBRATION_US) };
    trace_timebase_detail(b"tcxo_delay", b"completed");
    trace_timebase_detail(b"systick_count_end", b"begin");
    let systick_delta = unsafe { rom_systick_get_count() }.wrapping_sub(systick_start);
    trace_timebase_detail(b"systick_count_end", b"completed");
    trace_timebase_detail(b"tcxo_count_end", b"begin");
    let tcxo_delta = unsafe { rom_tcxo_get_us() }.wrapping_sub(tcxo_start);
    trace_timebase_detail(b"tcxo_count_end", b"completed");
    if tcxo_delta == 0 {
        return;
    }

    let calibrated = systick_delta
        .saturating_mul(1_000_000)
        .saturating_add(tcxo_delta / 2)
        / tcxo_delta;
    if let Ok(clock) = u32::try_from(calibrated)
        && (1_000..=100_000).contains(&clock)
    {
        // SAFETY: this is the vendor ROM-data conversion word used by
        // `uapi_systick_get_ms`. The official LiteOS startup performs the same
        // RTC-vs-TCXO calibration before normal application work.
        unsafe { (&raw mut g_systick_clock).write_volatile(clock) };
    }
}

#[cfg(target_arch = "riscv32")]
pub(crate) fn initialize_rom_timebases() -> u32 {
    unsafe {
        // SAFETY: these are the same mask-ROM initialization calls used by the
        // vendor `hw_init`. hisi-riscv-rt has already copied the original
        // platform ROM-data initializer, including both HAL function tables and
        // the 32 kHz / 24 MHz conversion values, to their fixed DTCM ABI slots.
        trace_timebase_detail(b"systick_init", b"begin");
        uapi_systick_init();
        trace_timebase_detail(b"systick_init", b"completed");
        trace_timebase_detail(b"tcxo_init", b"begin");
        let result = uapi_tcxo_init();
        trace_timebase_detail(b"tcxo_init", b"completed");
        trace_timebase_detail(b"systick_calibration", b"begin");
        calibrate_systick_clock();
        trace_timebase_detail(b"systick_calibration", b"completed");
        if result == 0 {
            TIMEBASE_READY.store(true, Ordering::Release);
        }
        result
    }
}

#[cfg(target_arch = "riscv32")]
fn trace_timebase_detail(name: &[u8], event: &[u8]) {
    #[cfg(all(feature = "bootstrap-stage-diag", target_arch = "riscv32"))]
    crate::blocking_diagnostics::trace_bootstrap_detail(name, event);
    #[cfg(not(all(feature = "bootstrap-stage-diag", target_arch = "riscv32")))]
    let _ = (name, event);
}

#[cfg(any(
    target_arch = "riscv32",
    feature = "wifi-personal",
    feature = "upstream-supplicant-port"
))]
pub(crate) fn try_monotonic_ms() -> Option<u64> {
    #[cfg(target_arch = "riscv32")]
    {
        TIMEBASE_READY.load(Ordering::Acquire).then(monotonic_ms)
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        Some(monotonic_ms())
    }
}

/// Monotonic milliseconds from the mask-ROM 32 kHz systick implementation.
///
/// This hidden callback is exported only so the application can inject the
/// chip time source into `hisi-rtos`; it is not a general RF control API. The
/// runtime must not call it before `Wifi::initialize` initializes ROM timebases.
#[doc(hidden)]
pub fn monotonic_ms() -> u64 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        // SAFETY: initialized once by `Wifi::initialize`; the ROM function only
        // reads its registered WS63 systick controller.
        rom_systick_get_ms()
    }
    #[cfg(not(target_arch = "riscv32"))]
    0
}

/// Monotonic microseconds from the mask-ROM TCXO implementation.
pub(crate) fn monotonic_us() -> u64 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        // SAFETY: same initialized ROM timebase contract as `monotonic_ms`.
        rom_tcxo_get_us()
    }
    #[cfg(not(target_arch = "riscv32"))]
    0
}

pub(crate) fn delay_us(usec: u32) {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        // SAFETY: same initialized ROM TCXO contract as `monotonic_us`.
        let _ = rom_tcxo_delay_us(usec);
    }
    #[cfg(not(target_arch = "riscv32"))]
    let _ = usec;
}

/// Current chip temperature in °C.
///
/// SCAFFOLD: writes a conservative 25 °C. The pointer/result ABI matches the
/// vendor SDK; a real reading still needs the hisi-hal tsensor (RF2/RF3).
#[unsafe(no_mangle)]
pub extern "C" fn uapi_tsensor_get_current_temp(temp: *mut i8) -> u32 {
    if temp.is_null() {
        return crate::OSAL_NOK as u32;
    }
    // SAFETY: the SDK ABI defines `temp` as a writable one-byte out-parameter.
    unsafe { *temp = 25 };
    crate::OSAL_OK as u32
}

/// Read a plaintext item from the official WS63 ACPU KV partition.
///
/// Encrypted records are rejected until the device crypto-key path is wired.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_nv_read(
    key: u16,
    max_len: u16,
    actual_len: *mut u16,
    value: *mut u8,
) -> u32 {
    #[cfg(not(target_arch = "riscv32"))]
    let _ = value;
    if !actual_len.is_null() {
        // SAFETY: the SDK ABI defines this as a writable out-parameter.
        unsafe { *actual_len = 0 };
    }

    #[cfg(target_arch = "riscv32")]
    unsafe {
        unsafe extern "C" {
            static __nv_storage_start: u8;
            static __nv_storage_length: u8;
        }

        let storage_len = &raw const __nv_storage_length as usize;
        // SAFETY: the linker-provided region is the flashboot-initialized,
        // read-only WS63 NV partition and remains mapped for the firmware life.
        let storage =
            MemoryMappedStorage::from_raw_parts(&raw const __nv_storage_start, storage_len);
        let Ok(mut reader) = NvReader::try_new(storage, NvConfig::WS63_ACPU) else {
            trace_nv(key, max_len, 0, crate::OSAL_NOK as u32);
            return crate::OSAL_NOK as u32;
        };
        let output = if value.is_null() {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(value, max_len as usize)
        };
        match reader.read(NvKey::from_raw(key), output) {
            Ok(length) => {
                let length = length as u16;
                if !actual_len.is_null() {
                    *actual_len = length;
                }
                trace_nv(key, max_len, length, crate::OSAL_OK as u32);
                return crate::OSAL_OK as u32;
            }
            Err(NvError::BufferTooSmall { required }) => {
                let required = u16::try_from(required).unwrap_or(u16::MAX);
                if !actual_len.is_null() {
                    *actual_len = required;
                }
                trace_nv(key, max_len, required, crate::OSAL_NOK as u32);
                return crate::OSAL_NOK as u32;
            }
            Err(_) => {}
        }
    }

    trace_nv(key, max_len, 0, crate::OSAL_NOK as u32);
    crate::OSAL_NOK as u32
}

/// Append and commit one plaintext item to the WS63 ACPU KV store.
///
/// The format layer verifies the new record before invalidating an older
/// version. When an append exhausts one logical page, the NVS format layer
/// compacts it through the linker-bounded 4 KiB erase capability before
/// retrying.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_nv_write(key: u16, value: *const u8, len: u16) -> u32 {
    #[cfg(not(target_arch = "riscv32"))]
    let _ = (key, value, len);

    #[cfg(target_arch = "riscv32")]
    {
        crate::log_emit(b"RFDBG_NV_WRITE_BEGIN\r\n");
        if value.is_null() && len != 0 {
            return crate::OSAL_NOK as u32;
        }
        let Some(_claim) = NvWriteClaim::try_acquire() else {
            trace_nv(key, len, 0, crate::OSAL_NOK as u32);
            return crate::OSAL_NOK as u32;
        };
        if initialize_rom_sfc() != 0 {
            trace_nv(key, len, 0, crate::OSAL_NOK as u32);
            return crate::OSAL_NOK as u32;
        }
        crate::log_emit(b"RFDBG_NV_WRITE_SFC_OK\r\n");
        let Some(storage) = RomNvStorage::from_linker_region() else {
            trace_nv(key, len, 0, crate::OSAL_NOK as u32);
            return crate::OSAL_NOK as u32;
        };
        let Ok(mut writer) = NvWriter::try_new(storage, NvConfig::WS63_ACPU) else {
            trace_nv(key, len, 0, crate::OSAL_NOK as u32);
            return crate::OSAL_NOK as u32;
        };
        crate::log_emit(b"RFDBG_NV_WRITE_READY\r\n");
        // SAFETY: the C ABI requires `value` to reference `len` readable bytes;
        // the null/zero case is represented by an empty slice.
        let input = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(value, len as usize) }
        };
        if writer.write_with_gc(NvKey::from_raw(key), input).is_ok() {
            crate::log_emit(b"RFDBG_NV_WRITE_DONE\r\n");
            trace_nv(key, len, len, crate::OSAL_OK as u32);
            return crate::OSAL_OK as u32;
        }
        crate::log_emit(b"RFDBG_NV_WRITE_ERR\r\n");
        trace_nv(key, len, 0, crate::OSAL_NOK as u32);
    }
    crate::OSAL_NOK as u32
}

// ── eFuse / TRNG / device identity ───────────────────────────────────────────
// These feed RF calibration, the MAC address and crypto seeding. eFuse reads
// use the HAL while the `Wifi` handle owns its unique peripheral token. TRNG and
// device-address policy remain separate follow-up work.

/// Read one eFuse bit through the HAL-owned WS63 controller.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_efuse_read_bit(value: *mut u8, byte: u32, bit: u8) -> u32 {
    if value.is_null() || bit >= 8 || !EFUSE_READY.load(Ordering::Acquire) {
        return crate::OSAL_NOK as u32;
    }
    let Some(address) = u16::try_from(byte)
        .ok()
        .and_then(hisi_hal::efuse::EfuseByteAddress::from_byte)
    else {
        return crate::OSAL_NOK as u32;
    };
    // SAFETY: `Wifi` keeps the unique eFuse token alive after enabling reads;
    // the HAL serializes the complete read transaction.
    let byte = unsafe { hisi_hal::efuse::EfuseDriver::read_byte_unchecked(address) };
    // SAFETY: the SDK ABI defines `value` as a writable one-byte output.
    unsafe { value.write((byte >> bit) & 1) };
    crate::OSAL_OK as u32
}

/// Read consecutive eFuse bytes through the HAL-owned WS63 controller.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_efuse_read_buffer(buffer: *mut u8, byte: u32, length: u16) -> u32 {
    if (buffer.is_null() && length != 0) || !EFUSE_READY.load(Ordering::Acquire) {
        return crate::OSAL_NOK as u32;
    }
    let Some(start) = u16::try_from(byte).ok() else {
        return crate::OSAL_NOK as u32;
    };
    for offset in 0..length {
        let Some(address) = start
            .checked_add(offset)
            .and_then(hisi_hal::efuse::EfuseByteAddress::from_byte)
        else {
            return crate::OSAL_NOK as u32;
        };
        // SAFETY: `Wifi` holds the unique eFuse token and HAL serializes reads.
        let value = unsafe { hisi_hal::efuse::EfuseDriver::read_byte_unchecked(address) };
        // SAFETY: the SDK ABI guarantees a writable `length`-byte buffer.
        unsafe { buffer.add(offset as usize).write(value) };
    }
    crate::OSAL_OK as u32
}

/// Fill one 32-bit word through the uniquely owned WS63 hardware TRNG.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_trng_get_random(randnum: *mut u32) -> u32 {
    if randnum.is_null() {
        return crate::OSAL_NOK as u32;
    }
    uapi_drv_cipher_trng_get_random_bytes(randnum.cast(), core::mem::size_of::<u32>() as u32)
}

/// Fill random bytes through the uniquely owned WS63 hardware TRNG.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_trng_get_random_bytes(randnum: *mut u8, size: u32) -> u32 {
    if randnum.is_null() && size != 0 {
        return crate::OSAL_NOK as u32;
    }
    if size == 0 {
        return crate::OSAL_OK as u32;
    }
    // SAFETY: null was rejected and the C ABI promises `size` writable bytes.
    let output = unsafe { core::slice::from_raw_parts_mut(randnum, size as usize) };
    #[cfg(any(
        feature = "ble-init",
        feature = "sle-init",
        feature = "wifi-wpa2-personal",
        feature = "upstream-supplicant-port"
    ))]
    {
        crate::crypto::fill_hardware_entropy(output)
            .map(|()| crate::OSAL_OK as u32)
            .unwrap_or(crate::OSAL_NOK as u32)
    }
    #[cfg(not(any(
        feature = "ble-init",
        feature = "sle-init",
        feature = "wifi-wpa2-personal",
        feature = "upstream-supplicant-port"
    )))]
    {
        let _ = output;
        crate::OSAL_NOK as u32
    }
}

const NV_ID_SYSTEM_FACTORY_MAC: u16 = 0x0005;
static mut WIFI_BASE_MAC: [u8; 6] = [0; 6];
static WIFI_BASE_MAC_READY: portable_atomic::AtomicBool = portable_atomic::AtomicBool::new(false);

fn valid_unicast_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 0 && *mac != [0; 6] && *mac != [0xff; 6]
}

fn wifi_base_mac() -> [u8; 6] {
    critical_section::with(|_| {
        if !WIFI_BASE_MAC_READY.load(Ordering::Relaxed) {
            let mut mac = [0; 6];
            let mut actual = 0_u16;
            if uapi_nv_read(
                NV_ID_SYSTEM_FACTORY_MAC,
                mac.len() as u16,
                &mut actual,
                mac.as_mut_ptr(),
            ) != crate::OSAL_OK as u32
                || actual != mac.len() as u16
                || !valid_unicast_mac(&mac)
            {
                let mut found = false;
                // SDK efuse items 12..9: 48-bit MAC slots at bit
                // 1728, 1680, 1632 and 1584, newest slot first.
                for byte_offset in [216_u32, 210, 204, 198] {
                    if uapi_efuse_read_buffer(mac.as_mut_ptr(), byte_offset, mac.len() as u16)
                        == crate::OSAL_OK as u32
                        && valid_unicast_mac(&mac)
                    {
                        found = true;
                        break;
                    }
                }
                if !found {
                    let _ =
                        uapi_drv_cipher_trng_get_random_bytes(mac.as_mut_ptr(), mac.len() as u32);
                    mac[0] = (mac[0] & 0xfc) | 0x02;
                    mac[1] = 0x00;
                    mac[2] = 0x73;
                }
            }
            // SAFETY: all accesses are serialized by the single-hart critical
            // section and readiness is published only after the full copy.
            unsafe { core::ptr::write(&raw mut WIFI_BASE_MAC, mac) };
            WIFI_BASE_MAC_READY.store(true, Ordering::Relaxed);
        }
        // SAFETY: initialized before READY and read under the same lock.
        unsafe { core::ptr::read(&raw const WIFI_BASE_MAC) }
    })
}

/// Device address following the WS63 SDK's base-MAC and interface derivation
/// rules. The base Wi-Fi MAC comes from factory KV key `0x0005`; an ephemeral
/// locally-administered unicast address is used only when factory data is
/// unavailable or invalid.
#[unsafe(no_mangle)]
pub extern "C" fn get_dev_addr(pc_addr: *mut u8, addr_len: u8, interface_type: u8) -> u32 {
    if pc_addr.is_null() || addr_len != 6 {
        return crate::OSAL_NOK as u32;
    }
    let mut mac = wifi_base_mac();
    let derive = match interface_type {
        2 => 0_u16,      // station
        3 => 2_u16,      // AP
        7..=10 => 3_u16, // mesh / P2P
        _ => return crate::OSAL_NOK as u32,
    };
    let mut carry = derive;
    for byte in mac.iter_mut().rev() {
        carry += *byte as u16;
        *byte = carry as u8;
        carry >>= 8;
    }
    mac[0] &= 0xfe;
    // SAFETY: caller guarantees `addr_len` bytes.
    unsafe { core::ptr::copy_nonoverlapping(mac.as_ptr(), pc_addr, mac.len()) };
    crate::OSAL_OK as u32
}

const CLK40M_TCXO: u32 = 0;
const CLK24M_TCXO: u32 = 1;

const fn tcxo_vendor_id(freq: hisi_hal::clock_init::TcxoFreq) -> u32 {
    match freq {
        hisi_hal::clock_init::TcxoFreq::MHz40 => CLK40M_TCXO,
        hisi_hal::clock_init::TcxoFreq::MHz24 => CLK24M_TCXO,
    }
}

/// Return the SDK's TCXO selector (`0` = 40 MHz, `1` = 24 MHz).
///
/// This ABI deliberately does not return Hertz. The ROM/blob code compares the
/// result with `CLK40M_TCXO`/`CLK24M_TCXO`; returning `24_000_000` would select
/// neither valid clock path. The hardware strap is decoded by the HAL so this
/// adapter remains a conversion at the vendor boundary, not a second raw-MMIO
/// implementation.
#[unsafe(no_mangle)]
pub extern "C" fn get_tcxo_freq() -> u32 {
    #[cfg(target_arch = "riscv32")]
    let freq = hisi_hal::clock_init::TcxoFreq::detect();
    #[cfg(not(target_arch = "riscv32"))]
    let freq = hisi_hal::clock_init::TcxoFreq::MHz40;

    tcxo_vendor_id(freq)
}

// ── AT command console (not wired — the runtime owns the console) ────────────

/// Register a BT AT command table. STUB: ignored.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_at_bt_register_cmd(_table: *const c_void, _num: u16) -> u32 {
    crate::OSAL_OK as u32
}

/// AT console print. STUB: ignored (the runtime owns the console).
#[unsafe(no_mangle)]
pub extern "C" fn uapi_at_print(_fmt: *const core::ffi::c_char) -> u32 {
    crate::OSAL_OK as u32
}

// ── Wi-Fi service entry points referenced internally ─────────────────────────

/// Stop the SoftAP. STUB.
#[cfg(not(feature = "wifi-personal"))]
#[unsafe(no_mangle)]
pub extern "C" fn uapi_wifi_softap_stop() -> i32 {
    crate::OSAL_OK
}

/// Stop the station. STUB.
#[cfg(not(feature = "wifi-personal"))]
#[unsafe(no_mangle)]
pub extern "C" fn uapi_wifi_sta_stop() -> i32 {
    crate::OSAL_OK
}

#[cfg(test)]
mod uapi_tests {
    use super::{tcxo_vendor_id, uapi_tsensor_get_current_temp};
    use hisi_hal::clock_init::TcxoFreq;

    #[test]
    fn tsensor_contract_writes_output_and_returns_status() {
        let mut temp = 0_i8;
        assert_eq!(uapi_tsensor_get_current_temp(&mut temp), 0);
        assert_eq!(temp, 25);
        assert_ne!(uapi_tsensor_get_current_temp(core::ptr::null_mut()), 0);
    }

    #[test]
    fn tcxo_contract_uses_vendor_enum_not_hertz() {
        assert_eq!(tcxo_vendor_id(TcxoFreq::MHz40), 0);
        assert_eq!(tcxo_vendor_id(TcxoFreq::MHz24), 1);
    }
}
