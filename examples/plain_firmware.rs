#![no_std]
#![no_main]

use hisi_riscv_rt::entry;

static RADIO_STATE: hisi_rf_core::RadioState<4> = hisi_rf_core::RadioState::new();

#[entry]
fn main() -> ! {
    let peripherals = unsafe { hisi_hal::peripherals::Peripherals::steal() };
    let resources = hisi_rf_ws63::Resources::new(
        peripherals.EFUSE,
        peripherals.KM,
        peripherals.SPACC,
        peripherals.PKE,
        peripherals.TRNG,
    );
    let _radio = hisi_rf_ws63::init(
        hisi_rf_core::RadioConfig::default(),
        resources,
        &RADIO_STATE,
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
