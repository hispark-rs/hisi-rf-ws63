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
    wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
        IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket,
    },
};

const ATTEMPTS: usize = 10;
const PAYLOAD_BYTES: usize = 32;
const INTERVAL_MS: u64 = 500;
const DEADLINE_MS: u64 = 15_000;

pub async fn run(device: &mut WifiDevice, uart: &Uart<'_, hisi_hal::peripherals::Uart0<'_>>) {
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    use hisi_rf_ws63::netif_l2::{LinkError, RouteError};
    let result: &[u8] = match hisi_rf_ws63::netif_l2::native_initial_open_result() {
        None => b"not-attempted",
        Some(Ok(())) => b"open",
        Some(Err(LinkError::Route(RouteError::InitialSessionRejected))) => b"initial-rejected",
        Some(Err(LinkError::Route(RouteError::CallbacksInFlight))) => b"callbacks-in-flight",
        Some(Err(LinkError::Route(RouteError::OpenInterrupted))) => b"open-interrupted",
        Some(Err(LinkError::Queue(_))) => b"queue-error",
        Some(Err(_)) => b"route-error",
    };
    uart.write(b"RFDBG_NET0_INITIAL_RESULT result=");
    uart.write(result);
    uart.write(b"\r\n");
    if device.link_state(&mut cx) != LinkState::Up {
        uart.write(b"RFDBG_NET0_INITIAL_SESSION_REJECTED\r\n");
        uart.write(b"RFDBG_NET0_PAYLOAD_ERR reason=closed\r\n");
        super::halt();
    }
    uart.write(b"RFDBG_NET0_INITIAL_SESSION_OPEN\r\n");
    let mac = device
        .station_mac_address()
        .expect("initialized station address");
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    // Diagnostic static-IPv4 UDP probe, not a production network entropy source.
    config.random_seed = super::monotonic_ms();
    let mut observed = ObservedDevice {
        device,
        counters: RxCounters::default(),
    };
    let mut interface = Interface::new(config, &mut observed, now());
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
        if observed.device.link_state(&mut cx) != LinkState::Up {
            uart.write(b"RFDBG_NET0_PAYLOAD_ERR reason=link_down\r\n");
            super::halt();
        }
        interface.poll(now(), &mut observed, &mut sockets);
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
        interface.poll(now(), &mut observed, &mut sockets);
        if bitmap.count_ones() as usize == ATTEMPTS {
            break;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
    let route = hisi_rf_ws63::netif_l2::native_route_diagnostics();
    super::write_native_host_delivery(uart, b"payload");
    uart.write(b"RFDBG_NET0_ROUTE");
    for (name, value) in [
        (b" entered=".as_slice(), route.entered),
        (b" queued=".as_slice(), route.queued),
        (b" dropped=".as_slice(), route.dropped),
        (b" closed=".as_slice(), route.closed_drops),
        (b" abandoned=".as_slice(), route.abandoned),
        (b" in_flight=".as_slice(), route.in_flight as u64),
    ] {
        uart.write(name);
        uart.write(&super::hex8((value >> 32) as u32));
        uart.write(&super::hex8(value as u32));
    }
    uart.write(b"\r\nRFDBG_NET0_RX");
    let c = observed.counters;
    for (name, value) in [
        (b" frames=".as_slice(), c.frames),
        (b" arp=".as_slice(), c.arp),
        (b" ipv4=".as_slice(), c.ipv4),
        (b" udp=".as_slice(), c.udp),
        (b" malformed=".as_slice(), c.malformed),
        (b" ip_checksum_bad=".as_slice(), c.ip_checksum_bad),
        (b" udp_checksum_bad=".as_slice(), c.udp_checksum_bad),
        (b" probe_endpoint=".as_slice(), c.probe_endpoint),
    ] {
        uart.write(name);
        uart.write(&super::hex8(value));
    }
    uart.write(b"\r\nRFDBG_NET0_PAYLOAD sent=0x");
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

#[derive(Default, Clone, Copy)]
struct RxCounters {
    frames: u32,
    arp: u32,
    ipv4: u32,
    udp: u32,
    malformed: u32,
    ip_checksum_bad: u32,
    udp_checksum_bad: u32,
    probe_endpoint: u32,
}

impl RxCounters {
    fn observe(&mut self, bytes: &[u8]) {
        self.frames += 1;
        let Ok(frame) = EthernetFrame::new_checked(bytes) else {
            self.malformed += 1;
            return;
        };
        match frame.ethertype() {
            EthernetProtocol::Arp => self.arp += 1,
            EthernetProtocol::Ipv4 => {
                self.ipv4 += 1;
                let Ok(ip) = Ipv4Packet::new_checked(frame.payload()) else {
                    self.malformed += 1;
                    return;
                };
                self.ip_checksum_bad += u32::from(!ip.verify_checksum());
                if ip.next_header() == IpProtocol::Udp {
                    self.udp += 1;
                    let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
                        self.malformed += 1;
                        return;
                    };
                    self.udp_checksum_bad += u32::from(
                        udp.checksum() != 0
                            && !udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()),
                    );
                    self.probe_endpoint += u32::from(
                        ip.src_addr() == Ipv4Address::new(192, 168, 4, 1)
                            && ip.dst_addr() == Ipv4Address::new(192, 168, 4, 2)
                            && udp.src_port() == 9
                            && udp.dst_port() == 49_152,
                    );
                }
            }
            _ => {}
        }
    }
}

// Observe only the frames the real driver hands to smoltcp; never inject,
// rewrite, filter or retain packet bytes in this diagnostic wrapper.
struct ObservedDevice<'a> {
    device: &'a mut WifiDevice,
    counters: RxCounters,
}

struct ObservedRx<'a> {
    token: hisi_rf_ws63::netif_l2::WifiRxToken<'a>,
    counters: &'a mut RxCounters,
}

impl smoltcp::phy::RxToken for ObservedRx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        smoltcp::phy::RxToken::consume(self.token, |bytes| {
            self.counters.observe(bytes);
            f(bytes)
        })
    }
}

impl smoltcp::phy::Device for ObservedDevice<'_> {
    type RxToken<'a>
        = ObservedRx<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = hisi_rf_ws63::netif_l2::WifiTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (token, tx) = smoltcp::phy::Device::receive(self.device, timestamp)?;
        Some((
            ObservedRx {
                token,
                counters: &mut self.counters,
            },
            tx,
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        smoltcp::phy::Device::transmit(self.device, timestamp)
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        smoltcp::phy::Device::capabilities(self.device)
    }
}
