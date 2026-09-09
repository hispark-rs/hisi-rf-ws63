//! NET0 data-plane bring-up only, not the NET1 Embassy Net application.
//! Static paired-AP addressing deliberately isolates L2/ARP/UDP from DHCP.

use embassy_net_driver::{Driver, LinkState};
use embassy_time::{Duration, Timer};
use hisi_hal::uart::Uart;
use hisi_rf_ws63::netif_l2::WifiDevice;
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    socket::udp,
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

const ATTEMPTS: usize = 10;
const PAYLOAD_BYTES: usize = 32;
const INTERVAL_MS: u64 = 500;
const DEADLINE_MS: u64 = 15_000;

pub async fn run(device: &mut WifiDevice, uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>) {
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    if device.link_state(&mut cx) != LinkState::Up {
        uart.write(b"RFDBG_NET0_PAYLOAD_ERR reason=closed\r\n");
        super::halt();
    }
    let mac = device
        .station_mac_address()
        .expect("initialized station address");
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    // Diagnostic static-IPv4 UDP probe, not a production network entropy source.
    config.random_seed = super::monotonic_ms();
    let mut interface = Interface::new(config, device, now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(192, 168, 4, 2)),
                24,
            ))
            .unwrap();
    });
    let endpoint = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(192, 168, 4, 1)), 9);
    let mut socket_storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut socket_storage[..]);
    // Interface::poll can consume an RX burst before the application runs.
    // Both metadata and bytes cover all replies, not merely one datagram.
    let mut rx_metadata = [udp::PacketMetadata::EMPTY; ATTEMPTS];
    let mut rx_data = [0; ATTEMPTS * PAYLOAD_BYTES];
    let mut tx_metadata = [udp::PacketMetadata::EMPTY; 2];
    let mut tx_data = [0; 2 * PAYLOAD_BYTES];
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(&mut rx_metadata[..], &mut rx_data[..]),
        udp::PacketBuffer::new(&mut tx_metadata[..], &mut tx_data[..]),
    );
    socket.bind(49_152).unwrap();
    let handle = sockets.add(socket);
    let started = super::monotonic_ms();
    let mut sent = 0;
    let mut bitmap = 0u16;
    let mut invalid = 0u32;
    let mut duplicate = 0u32;
    while super::monotonic_ms().wrapping_sub(started) < DEADLINE_MS {
        if device.link_state(&mut cx) != LinkState::Up {
            uart.write(b"RFDBG_NET0_PAYLOAD_ERR reason=link_down\r\n");
            super::halt();
        }
        interface.poll(now(), device, &mut sockets);
        let socket = sockets.get_mut::<udp::Socket>(handle);
        while let Ok((payload, metadata)) = socket.recv() {
            let sequence = payload.first().copied().unwrap_or(u8::MAX) as usize;
            if metadata.endpoint != endpoint || sequence >= sent || payload != frame(sequence) {
                invalid += 1;
            } else if bitmap & (1 << sequence) != 0 {
                duplicate += 1;
            } else {
                bitmap |= 1 << sequence;
            }
        }
        if sent < ATTEMPTS
            && super::monotonic_ms().wrapping_sub(started) >= sent as u64 * INTERVAL_MS
            && socket.can_send()
            && socket.send_slice(&frame(sent), endpoint).is_ok()
        {
            sent += 1;
        }
        interface.poll(now(), device, &mut sockets);
        if bitmap.count_ones() as usize == ATTEMPTS {
            break;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
    uart.write(b"RFDBG_NET0_PAYLOAD sent=0x");
    uart.write(&super::hex8(sent as u32));
    uart.write(b" received=0x");
    uart.write(&super::hex8(bitmap.count_ones()));
    uart.write(b" bitmap=0x");
    uart.write(&super::hex8(u32::from(bitmap)));
    uart.write(b" invalid=0x");
    uart.write(&super::hex8(invalid));
    uart.write(b" duplicate=0x");
    uart.write(&super::hex8(duplicate));
    uart.write(b"\r\n");
    if sent != ATTEMPTS || bitmap.count_ones() as usize != ATTEMPTS || invalid != 0 {
        uart.write(b"RFDBG_NET0_PAYLOAD_ERR reason=echo_contract\r\n");
        super::halt();
    }
    uart.write(b"RFDBG_NET0_PAYLOAD_OK\r\n");
}

fn now() -> Instant {
    Instant::from_millis(super::monotonic_ms().min(i64::MAX as u64) as i64)
}

fn frame(sequence: usize) -> [u8; PAYLOAD_BYTES] {
    let mut frame = [0u8; PAYLOAD_BYTES];
    for (index, byte) in frame.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(sequence as u8);
    }
    frame
}
