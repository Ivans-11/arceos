use core::task::Context;

use alloc::vec;
use axerrno::{AxError, AxResult, LinuxError, ax_bail};
use axio::{Buf, BufMut};
use axpoll::{IoEvents, Pollable};
use ringbuf::{
    HeapCons, HeapProd, 
    traits::{Consumer, Observer, Producer, Split}
};
use spin::RwLock;

const NLM_F_MULTI: u16 = 2;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_DONE: u16 = 3;

const IFF_UP: u32 = 1;
const IFF_BROADCAST: u32 = 2;
const IFF_LOOPBACK: u32 = 8;
const IFF_RUNNING: u32 = 64;
const IFF_MULTICAST: u32 = 4096;
const IFF_LOWER_UP: u32 = 65536;


const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const AF_INET: u8 = 2;

const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;

use crate::{
    RecvOptions, SendOptions, Shutdown, SocketAddrEx, SocketOps,
    general::GeneralOptions, consts::NETLINK_BUFFER_SIZE,
    options::{Configurable, GetSocketOption, SetSocketOption},
    device::{EthernetDevice, LoopbackDevice},
};

trait NetLinkMsg {
    fn from_buf(buf: &mut impl Buf) -> AxResult<Self> where Self: Sized;
    fn to_buf(&self, buf: &mut impl BufMut) -> AxResult<usize>;
}

#[derive(Default, Clone, Debug, Copy)]
pub struct NetlinkAddr {
    pub nl_pid: u32,
    pub nl_groups: u32,
}

pub struct NetlinkBuffer {
    size: usize,
    tx: HeapProd<u8>,
    rx: HeapCons<u8>,
}
impl NetlinkBuffer {
    pub fn new(buf_size: usize) -> Self {
        let rb = ringbuf::HeapRb::<u8>::new(buf_size);
        let (tx, rx) = rb.split();
        Self { size: buf_size, tx, rx }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn send_buffer(&mut self, src: &mut impl Buf) -> AxResult<usize> {
        let (left, right) = self.tx.vacant_slices_mut();
        let mut count = src.read(unsafe{ left.assume_init_mut() })?;
        if count >= left.len() {
            count += src.read(unsafe{ right.assume_init_mut() })?;
        }
        unsafe { self.tx.advance_write_index(count) };
        Ok(count)
    }

    pub fn recv_buffer(&self, dst: &mut impl BufMut) -> AxResult<usize> {
        let (left, right) = self.rx.as_slices();
        let mut count = dst.write(left)?;
        if count >= left.len() {
            count += dst.write(right)?;
        }
        unsafe { self.rx.advance_read_index(count) };
        Ok(count)
    }

    pub fn can_send(&self) -> bool {
        self.tx.vacant_len() > 0
    }

    pub fn can_recv(&self) -> bool {
        self.rx.occupied_len() > 0
    }
}
unsafe impl Sync for NetlinkBuffer {}

#[repr(C)]
#[derive(Debug)]
struct NlMsgHeader {
    len: u32,
    msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}
impl NetLinkMsg for NlMsgHeader {
    fn from_buf(buf: &mut impl Buf) -> AxResult<NlMsgHeader> {
        if buf.remaining() < core::mem::size_of::<NlMsgHeader>() {
            ax_bail!(InvalidInput, "buffer too small for nlmsghdr");
        }

        let mut len = vec![0u8; 4];
        let mut msg_type = vec![0u8; 2];
        let mut flags = vec![0u8; 2];
        let mut seq = vec![0u8; 4];
        let mut pid = vec![0u8; 4];

        buf.read(&mut len[..])?;
        buf.read(&mut msg_type[..])?;
        buf.read(&mut flags[..])?;
        buf.read(&mut seq[..])?;
        buf.read(&mut pid[..])?;

        Ok(NlMsgHeader {
            len: u32::from_le_bytes(len.try_into().unwrap()),
            msg_type: u16::from_le_bytes(msg_type.try_into().unwrap()),
            flags: u16::from_le_bytes(flags.try_into().unwrap()),
            seq: u32::from_le_bytes(seq.try_into().unwrap()),
            pid: u32::from_le_bytes(pid.try_into().unwrap()),
        })
    }
    fn to_buf(&self, buf: &mut impl BufMut) -> AxResult<usize> {
        if buf.remaining_mut() < core::mem::size_of::<NlMsgHeader>() {
            return Err(AxError::InvalidInput);
        }
        let mut written = 0;
        written += buf.write(&self.len.to_le_bytes())?;
        written += buf.write(&self.msg_type.to_le_bytes())?;
        written += buf.write(&self.flags.to_le_bytes())?;
        written += buf.write(&self.seq.to_le_bytes())?;
        written += buf.write(&self.pid.to_le_bytes())?;
        Ok(written)
    }
}

#[repr(C)]
#[derive(Debug)]
struct IfInfoMsg {
    family: u8,
    pad: u8,
    if_type: u16,
    index: i32,
    flags: u32,
    change: u32,
}
impl NetLinkMsg for IfInfoMsg {
    fn from_buf(buf: &mut impl Buf) -> AxResult<IfInfoMsg> {
        if buf.remaining() < core::mem::size_of::<IfInfoMsg>() {
            ax_bail!(InvalidInput, "buffer too small for ifinfomsg");
        }

        let mut family = vec![0u8; 1];
        let mut pad = vec![0u8; 1];
        let mut if_type = vec![0u8; 2];
        let mut index = vec![0u8; 4];
        let mut flags = vec![0u8; 4];
        let mut change = vec![0u8; 4];

        buf.read(&mut family[..])?;
        buf.read(&mut pad[..])?;
        buf.read(&mut if_type[..])?;
        buf.read(&mut index[..])?;
        buf.read(&mut flags[..])?;
        buf.read(&mut change[..])?;

        Ok(IfInfoMsg {
            family: family[0],
            pad: pad[0],
            if_type: u16::from_le_bytes(if_type.try_into().unwrap()),
            index: i32::from_le_bytes(index.try_into().unwrap()),
            flags: u32::from_le_bytes(flags.try_into().unwrap()),
            change: u32::from_le_bytes(change.try_into().unwrap()),
        })
    }
    fn to_buf(&self, buf: &mut impl BufMut) -> AxResult<usize> {
        if buf.remaining_mut() < core::mem::size_of::<IfInfoMsg>() {
            return Err(AxError::InvalidInput);
        }
        let mut written = 0;
        written += buf.write(&[self.family])?;
        written += buf.write(&[self.pad])?;
        written += buf.write(&self.if_type.to_le_bytes())?;
        written += buf.write(&self.index.to_le_bytes())?;
        written += buf.write(&self.flags.to_le_bytes())?;
        written += buf.write(&self.change.to_le_bytes())?;
        Ok(written)
    }
}

#[repr(C)]
#[derive(Debug)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}
impl NetLinkMsg for NlAttr {
    fn from_buf(buf: &mut impl Buf) -> AxResult<NlAttr> {
        if buf.remaining() < core::mem::size_of::<NlAttr>() {
            ax_bail!(InvalidInput, "buffer too small for nlattr");
        }

        let mut nla_len = vec![0u8; 2];
        let mut nla_type = vec![0u8; 2];

        buf.read(&mut nla_len[..])?;
        buf.read(&mut nla_type[..])?;

        Ok(NlAttr {
            nla_len: u16::from_le_bytes(nla_len.try_into().unwrap()),
            nla_type: u16::from_le_bytes(nla_type.try_into().unwrap()),
        })
    }
    fn to_buf(&self, buf: &mut impl BufMut) -> AxResult<usize> {
        if buf.remaining_mut() < core::mem::size_of::<NlAttr>() {
            return Err(AxError::InvalidInput);
        }
        let mut written = 0;
        written += buf.write(&self.nla_len.to_le_bytes())?;
        written += buf.write(&self.nla_type.to_le_bytes())?;
        Ok(written)
    }
}

#[repr(C)]
#[derive(Debug)]
struct IfAddrMsg {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
}
impl NetLinkMsg for IfAddrMsg {
    fn from_buf(buf: &mut impl Buf) -> AxResult<IfAddrMsg> {
        if buf.remaining() < core::mem::size_of::<IfAddrMsg>() {
            ax_bail!(InvalidInput, "buffer too small for ifaddrmsg");
        }

        let mut family = vec![0u8; 1];
        let mut prefix_len = vec![0u8; 1];
        let mut flags = vec![0u8; 1];
        let mut scope = vec![0u8; 1];
        let mut index = vec![0u8; 4];

        buf.read(&mut family[..])?;
        buf.read(&mut prefix_len[..])?;
        buf.read(&mut flags[..])?;
        buf.read(&mut scope[..])?;
        buf.read(&mut index[..])?;

        Ok(IfAddrMsg {
            family: family[0],
            prefix_len: prefix_len[0],
            flags: flags[0],
            scope: scope[0],
            index: u32::from_le_bytes(index.try_into().unwrap()),
        })
    }
    fn to_buf(&self, buf: &mut impl BufMut) -> AxResult<usize> {
        if buf.remaining_mut() < core::mem::size_of::<IfAddrMsg>() {
            return Err(AxError::InvalidInput);
        }
        let mut written = 0;
        written += buf.write(&[self.family])?;
        written += buf.write(&[self.prefix_len])?;
        written += buf.write(&[self.flags])?;
        written += buf.write(&[self.scope])?;
        written += buf.write(&self.index.to_le_bytes())?;
        Ok(written)
    }
}

pub struct NetlinkSocket {
    _protocol: u32,

    local_addr: RwLock<NetlinkAddr>,
    peer_addr: RwLock<NetlinkAddr>,

    buffer: RwLock<NetlinkBuffer>,

    general: GeneralOptions
}

impl NetlinkSocket {
    pub fn new(protocol: u32) -> Self {
        Self {
            _protocol: protocol,
            local_addr: RwLock::new(NetlinkAddr::default()),
            peer_addr: RwLock::new(NetlinkAddr::default()),
            buffer: RwLock::new(NetlinkBuffer::new(NETLINK_BUFFER_SIZE)),
            general: GeneralOptions::new(),
        }
    }

    fn send_done(&self, header: &NlMsgHeader) -> AxResult<()> {
        let done_header = NlMsgHeader {
            len: core::mem::size_of::<NlMsgHeader>() as u32,
            msg_type: NLMSG_DONE,
            flags: 0,
            seq: header.seq,
            pid: header.pid,
        };
        let mut buffer = self.buffer.write();
        let mut temp_buf = vec![0u8; core::mem::size_of::<NlMsgHeader>()];
        done_header.to_buf(&mut temp_buf.as_mut_slice())?;
        buffer.send_buffer(&mut temp_buf.as_slice())?;
        Ok(())
    }

    fn handle_msg(&self, header: &NlMsgHeader, _payload: &[u8]) -> AxResult<()> {
        match header.msg_type {
            RTM_GETLINK => {
                info!("Handling RTM_GETLINK");
                match self.handle_getlink(&header) {
                    Ok(_) => {
                        self.send_done(header)?;
                    }
                    Err(e) => {
                        warn!("Failed to handle RTM_GETLINK: {:?}", e);
                        return Err(e);
                    }
                }
            }
            RTM_GETADDR => {
                info!("Handling RTM_GETADDR");
                match self.handle_getaddr(&header) {
                    Ok(_) => {
                        self.send_done(header)?;
                    }
                    Err(e) => {
                        warn!("Failed to handle RTM_GETADDR: {:?}", e);
                        return Err(e);
                    }
                }
            }
            _ => {
                warn!("Not implemented netlink message type: {}", header.msg_type);
                return Err(AxError::Other(LinuxError::EINVAL));
            }
        }
        Ok(())
    }

    fn handle_getlink(&self, header: &NlMsgHeader) -> AxResult<()> {
        use crate::SERVICE;

        let service = SERVICE.lock();
        let devs = service.devices();

        for (i, dev) in devs.iter().enumerate() {
            let name = dev.name();
            let type_id = dev.as_ref().type_id();
            let (if_type, flags) = if type_id == core::any::TypeId::of::<EthernetDevice>() {
                (ARPHRD_ETHER, IFF_UP | IFF_BROADCAST | IFF_MULTICAST | IFF_RUNNING | IFF_LOWER_UP)
            } else if type_id == core::any::TypeId::of::<LoopbackDevice>() {
                (ARPHRD_LOOPBACK, IFF_UP | IFF_RUNNING | IFF_LOOPBACK)
            } else {
                warn!("Unknown device type for netlink GETLINK: {}", name);
                (ARPHRD_ETHER, IFF_UP)
            };

            let ifmsg = IfInfoMsg {
                family: AF_INET,
                pad: 0,
                if_type: if_type,
                index: i as i32,
                flags: flags,
                change: 0,
            };

            let name_bytes = name.as_bytes();
            let nla_len = core::mem::size_of::<NlAttr>() + name_bytes.len() + 1;
            let pad = (4 - (nla_len % 4)) % 4;
            let total_nla_size = nla_len + pad;

            let msg_len = core::mem::size_of::<NlMsgHeader>()
                + core::mem::size_of::<IfInfoMsg>()
                + total_nla_size;
            
            let attr = NlAttr {
                nla_len: (nla_len as u16),
                nla_type: IFLA_IFNAME,
            };

            let nl_hdr = NlMsgHeader {
                len: msg_len as u32,
                msg_type: RTM_NEWLINK,
                flags: NLM_F_MULTI,
                seq: header.seq,
                pid: header.pid,
            };

            let mut temp = vec![0u8; msg_len];
            {
                let mut pos = 0usize;
                let written = nl_hdr.to_buf(&mut &mut temp[pos..])?;
                pos += written;

                let written = ifmsg.to_buf(&mut &mut temp[pos..])?;
                pos += written;
                
                let written = attr.to_buf(&mut &mut temp[pos..])?;
                pos += written;

                let end = pos + name_bytes.len();
                temp[pos..end].copy_from_slice(name_bytes);
                pos = end;
                temp[pos] = 0u8;
                pos += 1;

                if pad > 0 {
                    let end = pos + pad;
                    for b in &mut temp[pos..end] {
                        *b = 0u8;
                    }
                }
            }

            let mut buffer = self.buffer.write();
            buffer.send_buffer(&mut temp.as_slice())?;
        }
        Ok(())
    }

    fn handle_getaddr(&self, header: &NlMsgHeader) -> AxResult<()> {
        use crate::SERVICE;

        let service = SERVICE.lock();
        let addrs = service.iface.ip_addrs();

        for addr in addrs {
            let device_index = service.lookup_device(&addr.address())
                .ok_or(AxError::NoSuchDevice)?;
            let device = &service.devices()[device_index];
            let type_id = device.as_ref().type_id();
            let scope = if type_id == core::any::TypeId::of::<LoopbackDevice>() {
                RT_SCOPE_HOST
            } else {
                RT_SCOPE_UNIVERSE
            };
            let ifaddrmsg = IfAddrMsg {
                family: AF_INET,
                prefix_len: addr.prefix_len(),
                flags: 0,
                scope: scope,
                index: device_index as u32,
            };

            let ip_bytes = match addr.address() {
                smoltcp::wire::IpAddress::Ipv4(ipv4) => {
                    let octets = ipv4.octets();
                    octets.to_vec()
                },
                smoltcp::wire::IpAddress::Ipv6(ipv6) => {
                    let octets = ipv6.octets();
                    octets.to_vec()
                }
            };

            let nla_len = core::mem::size_of::<NlAttr>() + ip_bytes.len();
            let pad = (4 - (nla_len % 4)) % 4;
            let total_nla_size = nla_len + pad;

            let msg_len = core::mem::size_of::<NlMsgHeader>()
                + core::mem::size_of::<IfAddrMsg>()
                + total_nla_size;
            
            let attr = NlAttr {
                nla_len: (nla_len as u16),
                nla_type: IFLA_ADDRESS,
            };

            let nl_hdr = NlMsgHeader {
                len: msg_len as u32,
                msg_type: RTM_NEWADDR,
                flags: NLM_F_MULTI,
                seq: header.seq,
                pid: header.pid,
            };

            let mut temp = vec![0u8; msg_len];
            {
                let mut pos = 0usize;
                let written = nl_hdr.to_buf(&mut &mut temp[pos..])?;
                pos += written;

                let written = ifaddrmsg.to_buf(&mut &mut temp[pos..])?;
                pos += written;
                
                let written = attr.to_buf(&mut &mut temp[pos..])?;
                pos += written;

                let end = pos + ip_bytes.len();
                temp[pos..end].copy_from_slice(&ip_bytes);
                pos = end;

                if pad > 0 {
                    let end = pos + pad;
                    for b in &mut temp[pos..end] {
                        *b = 0u8;
                    }
                }
            }

            let mut buffer = self.buffer.write();
            buffer.send_buffer(&mut temp.as_slice())?;
        }        
        Ok(())
    }
}

impl Configurable for NetlinkSocket {
    fn get_option_inner(&self, opt: &mut GetSocketOption) -> AxResult<bool> {
        self.general.get_option_inner(opt)
    }

    fn set_option_inner(&self, opt: SetSocketOption) -> AxResult<bool> {
        self.general.set_option_inner(opt)
    }
}

impl SocketOps for NetlinkSocket {
    fn bind(&self, local_addr: SocketAddrEx) -> AxResult {
        let local_addr = local_addr.into_netlink()?;
        let mut guard = self.local_addr.write();

        *guard = local_addr;
        debug!("Netlink socket bound to {:?}", local_addr);
        Ok(())
    }

    fn connect(&self, remote_addr: SocketAddrEx) -> AxResult {
        let remote_addr = remote_addr.into_netlink()?;
        let mut guard = self.peer_addr.write();

        *guard = remote_addr;
        debug!("Netlink socket connected to {:?}", remote_addr);
        Ok(())
    }

    fn send(&self, src: &mut impl Buf, _options: SendOptions) -> AxResult<usize> {
        let header = NlMsgHeader::from_buf(src)?;
        let payload_len = header.len as usize - core::mem::size_of::<NlMsgHeader>();

        if src.remaining() < payload_len {
            ax_bail!(InvalidInput, "buffer too small for payload");
        }

        let mut payload = vec![0u8; payload_len];
        let read = src.read(&mut payload)?;

        self.handle_msg(&header, &payload[..read])?;
        Ok(header.len as usize + read)
    }

    fn recv(&self, dst: &mut impl BufMut, _options: RecvOptions<'_>) -> AxResult<usize> {
        let buffer = self.buffer.read();
        let count = buffer.recv_buffer(dst)?;
        if count > 0 {
            Ok(count)
        } else {
            Err(AxError::WouldBlock)
        }
    }

    fn local_addr(&self) -> AxResult<SocketAddrEx> {
        let guard = self.local_addr.read();
        Ok(SocketAddrEx::Netlink(*guard))
    }

    fn peer_addr(&self) -> AxResult<SocketAddrEx> {
        let guard = self.peer_addr.read();
        Ok(SocketAddrEx::Netlink(*guard))
    }

    fn shutdown(&self, _how: Shutdown) -> AxResult {
        Ok(())
    }
}

impl Pollable for NetlinkSocket {
    fn poll(&self) -> IoEvents {
        let mut events = IoEvents::empty();

        events.set(IoEvents::IN, self.buffer.read().can_recv());
        events.set(IoEvents::OUT, self.buffer.read().can_send());
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::OUT) {
            self.general.register_waker(context.waker());
        }
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        self.shutdown(Shutdown::Both).ok();
    }
}