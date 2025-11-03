use core::time::Duration;

use axerrno::{AxError, AxResult, LinuxError};
use enum_dispatch::enum_dispatch;
use smoltcp::wire::IpAddress;

macro_rules! define_options {
    ($($name:ident($value:ty),)*) => {
        /// Operation to get a socket option.
        ///
        /// See [`Configurable::get_option`].
        pub enum GetSocketOption<'a> {
            $(
                $name(&'a mut $value),
            )*
        }

        /// Operation to set a socket option.
        ///
        /// See [`Configurable::set_option`].
        #[derive(Clone, Copy)]
        pub enum SetSocketOption<'a> {
            $(
                $name(&'a $value),
            )*
        }
    };
}

/// Corresponds to `struct ucred` in Linux.
#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct UnixCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}
impl UnixCredentials {
    pub fn new(pid: u32) -> Self {
        UnixCredentials {
            pid,
            uid: 0,
            gid: 0,
        }
    }
}

/// Ip address for IP_MULTICAST_IF option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4(core::net::Ipv4Addr),
    V6(core::net::Ipv6Addr),
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED)
    }
}

impl From<IpAddress> for IpAddr {
    fn from(addr: IpAddress) -> Self {
        match addr {
            IpAddress::Ipv4(a) => IpAddr::V4(a),
            IpAddress::Ipv6(a) => IpAddr::V6(a),
        }
    }
}

impl Into<IpAddress> for IpAddr {
    fn into(self) -> IpAddress {
        match self {
            IpAddr::V4(a) => IpAddress::Ipv4(a),
            IpAddr::V6(a) => IpAddress::Ipv6(a),
        }
    }
}

define_options! {
    // ---- Socket level options (SO_*) ----
    ReuseAddress(bool),
    Error(i32),
    DontRoute(bool),
    SendBuffer(usize),
    ReceiveBuffer(usize),
    KeepAlive(bool),
    SendTimeout(Duration),
    ReceiveTimeout(Duration),
    SendBufferForce(usize),
    PassCredentials(bool),
    PeerCredentials(UnixCredentials),

    // --- TCP level options (TCP_*) ----
    NoDelay(bool),
    MaxSegment(usize),
    TcpInfo(()),

    // ---- IP level options (IP_*) ----
    Ttl(u8),
    MulticastTtl(u8),
    MulticastLoop(bool),
    MulticastIf(IpAddr),
    AddMembership((IpAddr, IpAddr)),

    // ---- Extra options ----
    NonBlocking(bool),
}

/// Trait for configurable socket-like objects.
#[enum_dispatch]
pub trait Configurable {
    /// Get a socket option, returns `true` if the socket supports the option.
    fn get_option_inner(&self, opt: &mut GetSocketOption) -> AxResult<bool>;
    /// Set a socket option, returns `true` if the socket supports the option.
    fn set_option_inner(&self, opt: SetSocketOption) -> AxResult<bool>;

    fn get_option(&self, mut opt: GetSocketOption) -> AxResult {
        self.get_option_inner(&mut opt).and_then(|supported| {
            if !supported {
                Err(AxError::Other(LinuxError::ENOPROTOOPT))
            } else {
                Ok(())
            }
        })
    }
    fn set_option(&self, opt: SetSocketOption) -> AxResult {
        self.set_option_inner(opt).and_then(|supported| {
            if !supported {
                Err(AxError::Other(LinuxError::ENOPROTOOPT))
            } else {
                Ok(())
            }
        })
    }
}
