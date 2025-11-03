use alloc::vec;
use alloc::vec::Vec;
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    task::Context,
};

use axerrno::{AxError, AxResult, ax_bail, ax_err_type};
use axio::{Buf, BufMut};
use axpoll::{IoEvents, Pollable};
use axsync::Mutex;
use smoltcp::{
    iface::SocketHandle,
    phy::PacketMeta,
    socket::udp::{self as smol, UdpMetadata},
    storage::PacketMetadata,
    wire::{IpAddress, IpEndpoint, IpListenEndpoint},
};
use spin::RwLock;

use crate::{
    RecvFlags, RecvOptions, SERVICE, SOCKET_SET, SendOptions, Shutdown, SocketAddrEx, SocketOps,
    consts::{UDP_RX_BUF_LEN, UDP_TX_BUF_LEN},
    general::GeneralOptions,
    options::{Configurable, GetSocketOption, SetSocketOption},
    poll_interfaces,
};

pub(crate) fn new_udp_socket(rx_buf_len: Option<usize>, tx_buf_len: Option<usize>) -> smol::Socket<'static> {
    smol::Socket::new(
        smol::PacketBuffer::new(vec![PacketMetadata::EMPTY; 256], vec![0; rx_buf_len.unwrap_or(UDP_RX_BUF_LEN)]),
        smol::PacketBuffer::new(vec![PacketMetadata::EMPTY; 256], vec![0; tx_buf_len.unwrap_or(UDP_TX_BUF_LEN)]),
    )
}

/// A UDP socket that provides POSIX-like APIs.
pub struct UdpSocket {
    handle: SocketHandle,
    local_addr: RwLock<Option<IpEndpoint>>,
    peer_addr: RwLock<Option<(IpEndpoint, IpAddress)>>,

    general: GeneralOptions,

    ttl: RwLock<u8>,
    multicast_ttl: RwLock<u8>,
    multicast_loop: RwLock<bool>,
    multicast_if: RwLock<Option<IpAddress>>,
    multi_groups: RwLock<Vec<(IpAddress, IpAddress)>>,
}

impl UdpSocket {
    /// Creates a new UDP socket.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let socket = new_udp_socket(None, None);
        let handle = SOCKET_SET.add(socket);

        Self {
            handle,
            local_addr: RwLock::new(None),
            peer_addr: RwLock::new(None),

            general: GeneralOptions::new(),

            ttl: RwLock::new(64),
            multicast_ttl: RwLock::new(64),
            multicast_loop: RwLock::new(false),
            multicast_if: RwLock::new(None),
            multi_groups: RwLock::new(Vec::new()),
        }
    }

    fn with_smol_socket<R>(&self, f: impl FnOnce(&mut smol::Socket) -> R) -> R {
        SOCKET_SET.with_socket_mut::<smol::Socket, _, _>(self.handle, f)
    }

    fn remote_endpoint(&self) -> AxResult<(IpEndpoint, IpAddress)> {
        match self.peer_addr.try_read() {
            Some(addr) => addr.ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }
}

impl Configurable for UdpSocket {
    fn get_option_inner(&self, option: &mut GetSocketOption) -> AxResult<bool> {
        use GetSocketOption as O;

        if self.general.get_option_inner(option)? {
            return Ok(true);
        }
        match option {
            O::Ttl(ttl) => {
                **ttl = *self.ttl.read();
            }
            O::SendBuffer(size) => {
                self.with_smol_socket(|socket| {
                    **size = socket.payload_send_capacity();
                });
            }
            O::ReceiveBuffer(size) => {
                self.with_smol_socket(|socket| {
                    **size = socket.payload_recv_capacity();
                });
            }
            O::MulticastTtl(ttl) => {
                **ttl = *self.multicast_ttl.read();
            }
            O::MulticastLoop(loopback) => {
                **loopback = *self.multicast_loop.read();
            }
            O::MulticastIf(addr) => {
                **addr = self.multicast_if.read().clone().unwrap_or(IpAddress::Ipv4(Ipv4Addr::UNSPECIFIED)).into();
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn set_option_inner(&self, option: SetSocketOption) -> AxResult<bool> {
        use SetSocketOption as O;

        if self.general.set_option_inner(option)? && !matches!(option, O::SendBuffer(_) | O::ReceiveBuffer(_)) {
            return Ok(true);
        }
        match option {
            O::Ttl(ttl) => {
                *self.ttl.write() = *ttl;
            }
            O::SendBuffer(size) => {
                self.with_smol_socket(|socket| {
                    let mut new_socket = new_udp_socket(Some(socket.payload_recv_capacity()), Some(*size * 2));
                    core::mem::swap(socket, &mut new_socket);
                });
            }
            O::ReceiveBuffer(size) => {
                self.with_smol_socket(|socket| {
                    let mut new_socket = new_udp_socket(Some(*size * 2), Some(socket.payload_send_capacity()));
                    core::mem::swap(socket, &mut new_socket);
                });
            }
            O::MulticastTtl(ttl) => {
                *self.multicast_ttl.write() = *ttl;
            }
            O::MulticastLoop(loopback) => {
                *self.multicast_loop.write() = *loopback;
            }
            O::MulticastIf(addr) => {
                let addr: IpAddress = (*addr).into();
                *self.multicast_if.write() = Some(addr);
            }
            O::AddMembership((multi_addr, interface_addr)) => {
                let multi_addr: IpAddress = (*multi_addr).into();
                let interface_addr: IpAddress = (*interface_addr).into();
                self.multi_groups.write().push((multi_addr, interface_addr));

                SERVICE.lock().iface.join_multicast_group(multi_addr).ok();
                
                let mut mask = 0u32;
                if interface_addr.is_unspecified() {
                    mask = u32::MAX;
                } else if let Some(idx) = SERVICE.lock().lookup_device(&interface_addr) {
                    mask = 1u32 << idx;
                }
                if mask != 0 {
                    let new_mask = self.general.device_mask() | mask;
                    self.general.set_device_mask(new_mask);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
impl SocketOps for UdpSocket {
    fn bind(&self, local_addr: SocketAddrEx) -> AxResult {
        let mut local_addr = local_addr.into_ip()?;
        let mut guard = self.local_addr.write();

        if local_addr.port() == 0 {
            local_addr.set_port(get_ephemeral_port()?);
        }
        if guard.is_some() {
            ax_bail!(InvalidInput, "already bound");
        }

        let local_endpoint = IpEndpoint::from(local_addr);
        let endpoint = IpListenEndpoint {
            addr: (!local_endpoint.addr.is_unspecified()).then_some(local_endpoint.addr),
            port: local_endpoint.port,
        };

        if !self.general.reuse_address() {
            // Check if the address is already in use
            SOCKET_SET.bind_check(local_endpoint.addr, local_endpoint.port)?;
        }

        self.with_smol_socket(|socket| {
            socket.bind(endpoint).map_err(|e| match e {
                smol::BindError::InvalidState => ax_err_type!(InvalidInput, "already bound"),
                smol::BindError::Unaddressable => ax_err_type!(ConnectionRefused, "unaddressable"),
            })
        })?;
        self.general
            .set_device_mask(SERVICE.lock().device_mask_for(&endpoint));

        *guard = Some(local_endpoint);
        info!("UDP socket {}: bound on {}", self.handle, endpoint);
        Ok(())
    }

    fn connect(&self, remote_addr: SocketAddrEx) -> AxResult {
        let remote_addr = remote_addr.into_ip()?;
        let mut guard = self.peer_addr.write();
        if self.local_addr.read().is_none() {
            self.bind(SocketAddrEx::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )))?;
        }

        let remote_addr = IpEndpoint::from(remote_addr);
        let src = SERVICE.lock().get_source_address(&remote_addr.addr);
        *guard = Some((remote_addr, src));
        debug!("UDP socket {}: connected to {}", self.handle, remote_addr);
        Ok(())
    }

    fn send(&self, src: &mut impl Buf, options: SendOptions) -> AxResult<usize> {
        let (remote_addr, source_addr) = match options.to {
            Some(addr) => {
                let addr = IpEndpoint::from(addr.into_ip()?);
                let src = SERVICE.lock().get_source_address(&addr.addr);
                (addr, src)
            }
            None => self.remote_endpoint()?,
        };
        if remote_addr.port == 0 || remote_addr.addr.is_unspecified() {
            ax_bail!(InvalidInput, "invalid address");
        }

        if self.local_addr.read().is_none() {
            self.bind(SocketAddrEx::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )))?;
        }
        self.general.send_poller(self).poll(|| {
            poll_interfaces();
            self.with_smol_socket(|socket| {
                if !socket.is_open() {
                    // not connected
                    Err(ax_err_type!(NotConnected))
                } else if !socket.can_send() {
                    Err(AxError::WouldBlock)
                } else {
                    let mut local_addr = source_addr;
                    let mut ttl = *self.ttl.read();
                    if remote_addr.addr.is_multicast() {
                        if let Some(ifaddr) = self.multicast_if.read().clone() {
                            if !ifaddr.is_unspecified() {
                                local_addr = ifaddr;
                            }
                        }
                        ttl = *self.multicast_ttl.read();
                    }

                    socket.set_hop_limit(Some(ttl));

                    let buf = socket
                        .send(
                            src.remaining(),
                            UdpMetadata {
                                endpoint: remote_addr,
                                local_address: Some(local_addr),
                                meta: PacketMeta::default(),
                            },
                        )
                        .map_err(|e| match e {
                            smol::SendError::BufferFull => AxError::WouldBlock,
                            smol::SendError::Unaddressable => {
                                ax_err_type!(ConnectionRefused, "unaddressable")
                            }
                        })?;
                    let read = src.read(buf)?;
                    assert_eq!(read, buf.len());
                    Ok(read)
                }
            })
        })
    }

    fn recv(&self, dst: &mut impl BufMut, options: RecvOptions) -> AxResult<usize> {
        if self.local_addr.read().is_none() {
            ax_bail!(NotConnected);
        }

        enum ExpectedRemote<'a> {
            Any(&'a mut SocketAddrEx),
            Expecting(IpEndpoint),
        }
        let mut expected_remote = match options.from {
            Some(addr) => ExpectedRemote::Any(addr),
            None => ExpectedRemote::Expecting(self.remote_endpoint()?.0),
        };

        self.general.recv_poller(self).poll(|| {
            poll_interfaces();
            self.with_smol_socket(|socket| {
                if !socket.is_open() {
                    // not bound
                    Err(ax_err_type!(NotConnected))
                } else if !socket.can_recv() {
                    Err(AxError::WouldBlock)
                } else {
                    let result = if options.flags.contains(RecvFlags::PEEK) {
                        socket.peek().map(|(data, meta)| (data, *meta))
                    } else {
                        socket.recv()
                    };
                    match result {
                        Ok((src, meta)) => {
                            if let Some(local_addr) = meta.local_address {
                                if local_addr.is_multicast() {
                                    let groups = self.multi_groups.read();
                                    if !groups.iter().any(|(m, _if)| m == &local_addr) {
                                        return Err(AxError::WouldBlock);
                                    }
                                }
                            }

                            match &mut expected_remote {
                                ExpectedRemote::Any(remote_addr) => {
                                    **remote_addr = SocketAddrEx::Ip(meta.endpoint.into());
                                }
                                ExpectedRemote::Expecting(expected) => {
                                    if (!expected.addr.is_unspecified()
                                        && expected.addr != meta.endpoint.addr)
                                        || (expected.port != 0
                                            && expected.port != meta.endpoint.port)
                                    {
                                        return Err(AxError::WouldBlock);
                                    }
                                }
                            }

                            let read = dst.write(src)?;
                            if read < src.len() {
                                warn!("UDP message truncated: {} -> {} bytes", src.len(), read);
                            }

                            Ok(if options.flags.contains(RecvFlags::TRUNCATE) {
                                src.len()
                            } else {
                                read
                            })
                        }
                        Err(smol::RecvError::Exhausted) => Err(AxError::WouldBlock),
                        Err(smol::RecvError::Truncated) => {
                            unreachable!("UDP socket recv never returns Err(Truncated)")
                        }
                    }
                }
            })
        })
    }

    fn local_addr(&self) -> AxResult<SocketAddrEx> {
        match self.local_addr.try_read() {
            Some(addr) => addr
                .map(Into::into)
                .map(SocketAddrEx::Ip)
                .ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    fn peer_addr(&self) -> AxResult<SocketAddrEx> {
        self.remote_endpoint()
            .map(|it| it.0.into())
            .map(SocketAddrEx::Ip)
    }

    fn shutdown(&self, _how: Shutdown) -> AxResult {
        // TODO(mivik): shutdown
        poll_interfaces();

        self.with_smol_socket(|socket| {
            debug!("UDP socket {}: shutting down", self.handle);
            socket.close();
        });
        Ok(())
    }
}

impl Pollable for UdpSocket {
    fn poll(&self) -> IoEvents {
        poll_interfaces();
        if self.local_addr.read().is_none() {
            return IoEvents::empty();
        }

        let mut events = IoEvents::empty();
        self.with_smol_socket(|socket| {
            events.set(IoEvents::IN, socket.can_recv());
            events.set(IoEvents::OUT, socket.can_send());
        });
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::OUT) {
            self.general.register_waker(context.waker());
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shutdown(Shutdown::Both).ok();
        SOCKET_SET.remove(self.handle);
    }
}

fn get_ephemeral_port() -> AxResult<u16> {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);
    let mut curr = CURR.lock();

    let port = *curr;
    if *curr == PORT_END {
        *curr = PORT_START;
    } else {
        *curr += 1;
    }
    Ok(port)
}
