//! Shared physical storage declaration for the NET0 bootstrap and traffic fixtures.

use hisi_rf_ws63::SelectedProfile;

const EVENT_DEPTH: usize = super::RADIO_EVENT_DEPTH;

#[unsafe(no_mangle)]
static NET0_CONTROL: hisi_rf_ws63::Storage<SelectedProfile, EVENT_DEPTH> =
    hisi_rf_ws63::Storage::new();
#[unsafe(no_mangle)]
#[unsafe(link_section = ".hisi.shared-arena")]
static NET0_RF_ARENA: hisi_rf_ws63::RadioArenaStorage<{ hisi_rf_ws63::SELECTED_RF_ARENA_BYTES }> =
    hisi_rf_ws63::RadioArenaStorage::new();
#[unsafe(no_mangle)]
#[unsafe(link_section = ".hisi.shared-arena")]
pub(super) static NET0_RTOS_ARENA: hisi_rtos::SchedulerArena<
    { hisi_rf_ws63::SELECTED_RUNTIME_ARENA_BYTES },
> = hisi_rtos::SchedulerArena::new();

pub(super) static RADIO_STORAGE: hisi_rf_ws63::RadioStorage<
    SelectedProfile,
    EVENT_DEPTH,
    { hisi_rf_ws63::SELECTED_RF_ARENA_BYTES },
> = hisi_rf_ws63::RadioStorage::from_parts(&NET0_CONTROL, &NET0_RF_ARENA);

// Target-sized fields, not a host's differently sized usize/waker layout.
// Schema v2 also compares each physical arena, not just their aggregate size.
#[unsafe(no_mangle)]
static NET0_STORAGE_LAYOUT: [u32; 15] = {
    let report = hisi_rf_ws63::resource_report::<SelectedProfile, EVENT_DEPTH>();
    [
        u32::from_le_bytes(*b"NET0"),
        2,
        report.control_storage_bytes as u32,
        report.l2_storage_offset as u32,
        report.l2_storage.total_bytes as u32,
        report.l2_storage.payload_bytes as u32,
        report.l2_storage.metadata_bytes as u32,
        report.l2_storage.rx_slots as u32,
        report.l2_storage.tx_slots as u32,
        report.l2_storage.mtu as u32,
        (report.arena_storage_bytes + report.runtime_arena_bytes.unwrap()) as u32,
        report.main_stack_bytes_required as u32,
        report.linker_packet_ram_bytes as u32,
        report.arena_storage_bytes as u32,
        report.runtime_arena_bytes.unwrap() as u32,
    ]
};

pub(super) fn retain_layout() {
    core::hint::black_box(&NET0_STORAGE_LAYOUT);
}
