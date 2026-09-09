use core::task::Context;

use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState};
use hisi_rf_core::l2::{ReceiveToken, TransmitToken};

use super::{NATIVE_MTU, NATIVE_RX_SLOTS, NATIVE_TX_SLOTS, NativeDevice};

/// Exclusive caller-owned NET0 device. It remains Down until the native
/// lifecycle owner proves quiescence and authorizes a session.
pub struct WifiDevice(pub(crate) NativeDevice);

impl WifiDevice {
    pub fn l2_capabilities(&self) -> Option<hisi_rf_core::WifiL2Capabilities> {
        let HardwareAddress::Ethernet(address) = self.0.hardware_address() else {
            return None;
        };
        hisi_rf_core::WifiL2Capabilities::try_new(address)
    }

    pub fn station_mac_address(&self) -> Option<[u8; 6]> {
        self.l2_capabilities()
            .map(hisi_rf_core::WifiL2Capabilities::station_mac_address)
    }
}

/// A unique RX borrow; its payload never escapes through a backend accessor.
pub struct WifiRxToken<'a>(ReceiveToken<'a, NATIVE_RX_SLOTS, NATIVE_MTU>);
/// A reservation of real TX capacity, held until consume or drop.
pub struct WifiTxToken<'a>(TransmitToken<'a, NATIVE_TX_SLOTS, NATIVE_MTU>);

impl embassy_net_driver::RxToken for WifiRxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        embassy_net_driver::RxToken::consume(self.0, f)
    }
}

impl embassy_net_driver::TxToken for WifiTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        embassy_net_driver::TxToken::consume(self.0, len, f)
    }
}

impl Driver for WifiDevice {
    type RxToken<'a> = WifiRxToken<'a>;
    type TxToken<'a> = WifiTxToken<'a>;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        Driver::receive(&mut self.0, cx).map(|(rx, tx)| (WifiRxToken(rx), WifiTxToken(tx)))
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        Driver::transmit(&mut self.0, cx).map(WifiTxToken)
    }

    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        self.0.link_state(cx)
    }

    fn capabilities(&self) -> Capabilities {
        Driver::capabilities(&self.0)
    }

    fn hardware_address(&self) -> HardwareAddress {
        self.0.hardware_address()
    }
}

#[cfg(feature = "net")]
impl smoltcp::phy::RxToken for WifiRxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        smoltcp::phy::RxToken::consume(self.0, f)
    }
}

#[cfg(feature = "net")]
impl smoltcp::phy::TxToken for WifiTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        smoltcp::phy::TxToken::consume(self.0, len, f)
    }
}

#[cfg(feature = "net")]
impl smoltcp::phy::Device for WifiDevice {
    type RxToken<'a> = WifiRxToken<'a>;
    type TxToken<'a> = WifiTxToken<'a>;

    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        smoltcp::phy::Device::receive(&mut self.0, timestamp)
            .map(|(rx, tx)| (WifiRxToken(rx), WifiTxToken(tx)))
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        smoltcp::phy::Device::transmit(&mut self.0, timestamp).map(WifiTxToken)
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        smoltcp::phy::Device::capabilities(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif_l2::{CallbackRoute, NativeLink, NativeStorage};
    use core::task::{Poll, Waker};
    use embassy_net_driver::{RxToken, TxToken};

    #[test]
    fn opaque_device_delegates_real_capacity_identity_and_closed_state() {
        static STORAGE: NativeStorage = NativeStorage::new();
        let address = hisi_rf_core::WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 9]).unwrap();
        let parts = STORAGE.claim(address).unwrap();
        let route = CallbackRoute::new();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        let mut device = WifiDevice(parts.device);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(device.l2_capabilities(), Some(address));
        assert_eq!(device.station_mac_address(), Some([2, 0, 0, 0, 0, 9]));
        assert!(Driver::link_state(&mut device, &mut cx) == LinkState::Down);
        assert!(Driver::transmit(&mut device, &mut cx).is_none());
        assert_eq!(
            Driver::capabilities(&device).max_transmission_unit,
            NATIVE_MTU
        );
        link.begin_after_native_quiescence().unwrap(); // Host producer is controlled here.
        for byte in 0..NATIVE_TX_SLOTS {
            Driver::transmit(&mut device, &mut cx)
                .unwrap()
                .consume(1, |b| b[0] = byte as u8);
        }
        assert!(Driver::transmit(&mut device, &mut cx).is_none());
        for byte in 0..NATIVE_TX_SLOTS {
            assert_eq!(
                link.poll_transmit(&mut cx, |b| {
                    assert_eq!(b, &[byte as u8]);
                    Ok::<_, ()>(())
                }),
                Poll::Ready(Ok(()))
            );
        }
        route.enter().unwrap().receive(&[1, 2, 3]).unwrap();
        let (rx, reply) = Driver::receive(&mut device, &mut cx).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[1, 2, 3]));
        drop(reply);
        link.close().unwrap();
        assert!(Driver::link_state(&mut device, &mut cx) == LinkState::Down);
        assert_eq!(link.rx_diagnostics().delivered, 1);
        assert_eq!(link.tx_diagnostics().delivered, NATIVE_TX_SLOTS as u64);
    }

    #[test]
    #[cfg(feature = "net")]
    fn smoltcp_adapter_uses_the_same_instance_without_a_legacy_queue() {
        static STORAGE: NativeStorage = NativeStorage::new();
        let address = hisi_rf_core::WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 10]).unwrap();
        let parts = STORAGE.claim(address).unwrap();
        let route = CallbackRoute::new();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        let mut device = WifiDevice(parts.device);
        link.begin_after_native_quiescence().unwrap();
        route.enter().unwrap().receive(&[7, 8]).unwrap();
        let (rx, tx) =
            smoltcp::phy::Device::receive(&mut device, smoltcp::time::Instant::ZERO).unwrap();
        smoltcp::phy::RxToken::consume(rx, |bytes| assert_eq!(bytes, &[7, 8]));
        drop(tx);
        assert_eq!(link.rx_diagnostics().delivered, 1);
    }
}
