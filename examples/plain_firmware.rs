#![no_std]
#![no_main]

use hisi_riscv_rt::entry;

hisi_rf_ws63::declare_radio_storage!(static RADIO_STORAGE, events = 4);

#[entry]
fn main() -> ! {
    let peripherals = unsafe { hisi_hal::peripherals::Peripherals::steal() };
    let (control, arena) = RADIO_STORAGE
        .install()
        .expect("install caller-owned radio storage")
        .into_init_parts();
    let resources =
        hisi_rf_ws63::Resources::<hisi_rf_ws63::SelectedProfile>::builder(peripherals.EFUSE, arena)
            .crypto(peripherals.KM, peripherals.SPACC, peripherals.TRNG);
    #[cfg(feature = "wpa2-personal")]
    let resources = resources.build();
    #[cfg(feature = "wpa3-personal")]
    let resources = resources.pke(peripherals.PKE).build();
    let _radio = hisi_rf_ws63::init(hisi_rf_core::RadioConfig::default(), resources, control)
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
