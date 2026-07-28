#![no_std]
#![no_main]

use hisi_riscv_rt::entry;

static RADIO_STORAGE: hisi_rf_ws63::Storage<hisi_rf_ws63::SelectedProfile, 4> =
    hisi_rf_ws63::Storage::new();
hisi_rf_ws63::declare_radio_arena!(static RADIO_ARENA);

#[entry]
fn main() -> ! {
    let peripherals = unsafe { hisi_hal::peripherals::Peripherals::steal() };
    let arena = RADIO_ARENA
        .claim_for::<hisi_rf_ws63::SelectedProfile>()
        .and_then(|arena| arena.install())
        .expect("install shared RF arena");
    let resources =
        hisi_rf_ws63::Resources::<hisi_rf_ws63::SelectedProfile>::builder(peripherals.EFUSE, arena)
            .crypto(peripherals.KM, peripherals.SPACC, peripherals.TRNG);
    #[cfg(feature = "wpa2-personal")]
    let resources = resources.build();
    #[cfg(feature = "wpa3-personal")]
    let resources = resources.pke(peripherals.PKE).build();
    let _radio = hisi_rf_ws63::init(
        hisi_rf_core::RadioConfig::default(),
        resources,
        &RADIO_STORAGE,
    )
    .expect("fresh static radio state");

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
