//! A PROXYv2 wrapper for hyper and tonic.

#[macro_use]
extern crate log;

#[cfg(feature = "track_conn_count")]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::{
    convert::TryInto,
    io::{self, ErrorKind},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use hyper::server::conn::AddrStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod wrapped_incoming;
pub use wrapped_incoming::WrappedIncoming;

#[derive(Clone, Copy, Debug)]
/// Accept/Reject mode for accepting connections
pub enum ProxyMode {
    /// Disable PROXYv2 (if sent, PROXYv2 data will be passed through)
    None,
    /// PROXYv2 data is parsed if present, otherwise the original address is used
    Accept,
    /// PROXYv2 data is required or the connection will be rejected
    Require,
}

const PROXY_PACKET_HEADER_LEN: usize = 16;
const PROXY_PACKET_MAX_PROXY_ADDR_SIZE: usize = 216;
const PROXY_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const PROXY_PROTOCOL_VERSION: u8 = 2;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
/// A PROXYv2 Command
pub enum Command {
    Local,
    Proxy,
}

impl Command {
    fn from_u8(from: u8) -> Option<Self> {
        match from {
            0 => Some(Command::Local),
            1 => Some(Command::Proxy),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
/// A PROXYv2 family
pub enum Family {
    Unspecified,
    Ipv4,
    Ipv6,
    Unix,
}

impl Family {
    fn from_u8(from: u8) -> Option<Self> {
        match from {
            0 => Some(Family::Unspecified),
            1 => Some(Family::Ipv4),
            2 => Some(Family::Ipv6),
            3 => Some(Family::Unix),
            _ => None,
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Family::Unspecified => None,
            Family::Ipv4 => Some(12),
            Family::Ipv6 => Some(36),
            Family::Unix => Some(216),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
/// A PROXYv2 protocol
pub enum Protocol {
    Unspecified,
    Stream,
    Datagram,
}

impl Protocol {
    fn from_u8(from: u8) -> Option<Self> {
        match from {
            0 => Some(Protocol::Unspecified),
            1 => Some(Protocol::Stream),
            2 => Some(Protocol::Datagram),
            _ => None,
        }
    }
}

/// A wrapper over [`hyper::server::conn::AddrStream`] that grabs PROXYv2 information
pub struct WrappedStream {
    inner: Pin<Box<AddrStream>>,
    #[cfg(feature = "track_conn_count")]
    conn_count: Arc<AtomicU64>,
    proxy_header: [u8; PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE],
    proxy_header_index: usize,
    proxy_header_rewrite_index: usize,
    proxy_header_target: usize,
    discovered_dest: Option<SocketAddr>,
    discovered_src: Option<SocketAddr>,
    command: Option<Command>,
    family: Family,
    protocol: Protocol,
    proxy_mode: ProxyMode,
}

#[cfg(feature = "tonic")]
impl tonic::transport::server::Connected for WrappedStream {
    type ConnectInfo = Option<SocketAddr>;
    fn connect_info(&self) -> Self::ConnectInfo {
        Some(
            self.discovered_src
                .unwrap_or_else(|| self.inner.remote_addr()),
        )
    }
}

fn to_array<const SIZE: usize>(from: &[u8]) -> [u8; SIZE] {
    from.try_into().unwrap()
}

impl AsyncRead for WrappedStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !matches!(self.proxy_mode, ProxyMode::None) && self.proxy_header_target > 0 {
            let index = self.proxy_header_index;
            let target = self.proxy_header_target;
            let mut proxy_header =
                [MaybeUninit::uninit(); PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE];
            let mut read_buf = ReadBuf::uninit(&mut proxy_header[index..target]);
            match self.inner.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    (&mut self.proxy_header[index..index + read_buf.filled().len()])
                        .copy_from_slice(read_buf.filled());

                    self.proxy_header_index += read_buf.filled().len();

                    // check signature
                    let signature_end = self.proxy_header_index.min(12);
                    if self.proxy_header[0..signature_end] != PROXY_SIGNATURE[0..signature_end] {
                        // re-emit everything / not a proxy connection
                        if matches!(self.proxy_mode, ProxyMode::Require) {
                            debug!("attempted non-proxy connection when required");
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "invalid proxy protocol version",
                            )));
                        }
                        self.proxy_header_target = 0;
                    } else if self.proxy_header_index >= PROXY_PACKET_HEADER_LEN {
                        let version = (self.proxy_header[12] & 0xf0) >> 4;
                        if version != PROXY_PROTOCOL_VERSION {
                            debug!("invalid proxy protocol version: {}", version);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "invalid proxy protocol version",
                            )));
                        }
                        let command = self.proxy_header[12] & 0x0f;
                        let command = match Command::from_u8(command) {
                            Some(c) => c,
                            None => {
                                debug!("invalid proxy protocol command: {}", command);
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "invalid proxy protocol command",
                                )));
                            }
                        };
                        self.command = Some(command);

                        let family = (self.proxy_header[13] & 0xf0) >> 4;
                        self.family = match Family::from_u8(family) {
                            None => {
                                debug!("invalid proxy family: {}", family);
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "invalid proxy family",
                                )));
                            }
                            Some(family) => {
                                trace!("PROXY family: {:?}", family);
                                family
                            }
                        };

                        let protocol = self.proxy_header[13] & 0x0f;
                        self.protocol = match Protocol::from_u8(protocol) {
                            None => {
                                debug!("invalid proxy protocol: {}", protocol);
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "invalid proxy protocol",
                                )));
                            }
                            Some(protocol) => {
                                trace!("PROXY protocol: {:?}", protocol);
                                protocol
                            }
                        };

                        let len =
                            u16::from_be_bytes([self.proxy_header[14], self.proxy_header[15]]);
                        let target_len = if matches!(command, Command::Local) {
                            None
                        } else {
                            self.family.len()
                        };

                        if let Some(target_len) = target_len {
                            if len as usize != target_len {
                                debug!("invalid proxy address length: {}", target_len);
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "invalid proxy address length",
                                )));
                            }
                        }

                        self.proxy_header_target = PROXY_PACKET_HEADER_LEN + len as usize;
                        if self.proxy_header_index as usize >= self.proxy_header_target {
                            let raw = &self.proxy_header
                                [PROXY_PACKET_HEADER_LEN..self.proxy_header_target];

                            match self.family {
                                Family::Unspecified => {
                                    trace!("unspecified PROXY family data: {:?}", raw);
                                }
                                Family::Ipv4 => {
                                    let src_addr = IpAddr::V4(Ipv4Addr::from(to_array(&raw[..4])));
                                    let dest_addr =
                                        IpAddr::V4(Ipv4Addr::from(to_array(&raw[4..8])));
                                    let src_port =
                                        u16::from_be_bytes((&raw[8..10]).try_into().unwrap());
                                    let dest_port =
                                        u16::from_be_bytes((&raw[10..12]).try_into().unwrap());
                                    self.discovered_src = Some(SocketAddr::new(src_addr, src_port));
                                    self.discovered_dest =
                                        Some(SocketAddr::new(dest_addr, dest_port));
                                }
                                Family::Ipv6 => {
                                    let src_addr = IpAddr::V6(to_array(&raw[..16]).into());
                                    let dest_addr = IpAddr::V6(to_array(&raw[16..32]).into());
                                    let src_port =
                                        u16::from_be_bytes((&raw[32..34]).try_into().unwrap());
                                    let dest_port =
                                        u16::from_be_bytes((&raw[34..36]).try_into().unwrap());
                                    self.discovered_src = Some(SocketAddr::new(src_addr, src_port));
                                    self.discovered_dest =
                                        Some(SocketAddr::new(dest_addr, dest_port));
                                }
                                Family::Unix => {
                                    warn!("unsupported UNIX PROXY family, ignored.");
                                }
                            }
                            self.proxy_header_rewrite_index = self.proxy_header_target;
                            self.proxy_header_target = 0;
                        }
                    }
                }
            }
        }
        if !matches!(self.as_ref().proxy_mode, ProxyMode::None)
            && self.proxy_header_target == 0
            && self.proxy_header_rewrite_index < self.proxy_header_index
        {
            let len = self.proxy_header_index - self.proxy_header_rewrite_index;
            let actual_len = if len < buf.remaining() {
                len
            } else {
                buf.remaining()
            };
            buf.put_slice(
                &self.proxy_header
                    [self.proxy_header_rewrite_index..self.proxy_header_rewrite_index + actual_len],
            );
            self.proxy_header_rewrite_index += actual_len;
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }

        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl WrappedStream {
    /// Returns `true` if PROXYv2 information was sent
    pub fn was_proxied(&self) -> bool {
        self.command.is_some()
    }

    /// PROXY reported command or None
    pub fn command(&self) -> Option<Command> {
        self.command
    }

    /// PROXY reported family or Unspecified
    pub fn family(&self) -> Family {
        self.family
    }

    /// PROXY reported protocol or Unspecified
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// PROXY reported destination or None
    pub fn destination(&self) -> Option<SocketAddr> {
        self.discovered_dest
    }

    /// PROXY reported source or original address if none
    pub fn source(&self) -> SocketAddr {
        self.discovered_src
            .unwrap_or_else(|| self.inner.remote_addr())
    }

    /// The actual source that connected to us
    pub fn original_source(&self) -> SocketAddr {
        self.inner.remote_addr()
    }
}

impl AsyncWrite for WrappedStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(feature = "track_conn_count")]
impl Drop for WrappedStream {
    fn drop(&mut self) {
        self.conn_count.fetch_sub(1, Ordering::SeqCst);
    }
}
