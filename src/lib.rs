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

use futures::Future;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

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
#[derive(Debug, Clone, Copy, PartialEq)]
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
#[derive(Debug, Clone, Copy, PartialEq)]
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
#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(PartialEq, Debug)]
struct ProxyInfo {
    command: Command,
    family: Family,
    protocol: Protocol,
    discovered_dest: Option<SocketAddr>,
    discovered_src: Option<SocketAddr>,
}

#[derive(PartialEq, Debug)]
enum ProxyResult {
    Proxy(ProxyInfo),
    SignatureBytes([u8; PROXY_SIGNATURE.len()]),
}

/// A wrapper over [`hyper::server::conn::AddrStream`] that grabs PROXYv2 information
pub struct WrappedStream {
    remote_addr: SocketAddr,
    inner_write: Pin<Box<OwnedWriteHalf>>,
    inner_read: Option<Pin<Box<OwnedReadHalf>>>,
    #[cfg(feature = "track_conn_count")]
    conn_count: Arc<AtomicU64>,
    pending_read_proxy: Option<
        Pin<
            Box<
                dyn Future<Output = io::Result<(ProxyResult, Pin<Box<OwnedReadHalf>>)>>
                    + Send
                    + Sync
                    + 'static,
            >,
        >,
    >,
    info: Option<ProxyInfo>,
    #[cfg(feature = "tonic")]
    connect_info: std::sync::Arc<std::sync::RwLock<Option<SocketAddr>>>,
    fused_error: bool,
    proxy_mode: ProxyMode,
}

#[cfg(feature = "tonic")]
#[derive(Clone)]
pub struct TcpConnectInfo {
    inner: std::sync::Arc<std::sync::RwLock<Option<SocketAddr>>>,
}

#[cfg(feature = "tonic")]
impl TcpConnectInfo {
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        *self.inner.read().unwrap()
    }
}

#[cfg(feature = "tonic")]
impl tonic::transport::server::Connected for WrappedStream {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        TcpConnectInfo {
            inner: self.connect_info.clone(),
        }
    }
}

#[cfg(feature = "tonic")]
pub fn tonic_remote_addr<T>(request: &tonic::Request<T>) -> Option<SocketAddr> {
    request
        .extensions()
        .get::<TcpConnectInfo>()
        .expect("missing TCP connect info (was hyperproxy inline with tonic?)")
        .remote_addr()
}

#[cfg(feature = "axum")]
impl<'a> axum::extract::connect_info::Connected<&'a WrappedStream> for SocketAddr {
    fn connect_info(target: &'a WrappedStream) -> Self {
        target.source()
    }
}

fn to_array<const SIZE: usize>(from: &[u8]) -> [u8; SIZE] {
    from.try_into().unwrap()
}

async fn read_proxy<R: AsyncRead + Unpin>(mut read: R) -> io::Result<(ProxyResult, R)> {
    let mut signature = [0u8; PROXY_SIGNATURE.len()];
    read.read_exact(&mut signature[..]).await?;
    if signature != PROXY_SIGNATURE {
        return Ok((ProxyResult::SignatureBytes(signature), read));
    }

    // 4 bytes
    let mut header = [0u8; PROXY_PACKET_HEADER_LEN - PROXY_SIGNATURE.len()];
    read.read_exact(&mut header[..]).await?;

    let version = (header[0] & 0xf0) >> 4;
    if version != PROXY_PROTOCOL_VERSION {
        debug!("invalid proxy protocol version: {}", version);
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid proxy protocol version",
        ));
    }
    let command = header[0] & 0x0f;
    let command = match Command::from_u8(command) {
        Some(c) => c,
        None => {
            debug!("invalid proxy protocol command: {}", command);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid proxy protocol command",
            ));
        }
    };

    let family = (header[1] & 0xf0) >> 4;
    let family = match Family::from_u8(family) {
        None => {
            debug!("invalid proxy family: {}", family);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid proxy family",
            ));
        }
        Some(family) => {
            trace!("PROXY family: {:?}", family);
            family
        }
    };

    let protocol = header[1] & 0x0f;
    let protocol = match Protocol::from_u8(protocol) {
        None => {
            debug!("invalid proxy protocol: {}", protocol);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid proxy protocol",
            ));
        }
        Some(protocol) => {
            trace!("PROXY protocol: {:?}", protocol);
            protocol
        }
    };

    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let target_len = if matches!(command, Command::Local) {
        None
    } else {
        family.len()
    };

    if let Some(target_len) = target_len {
        if len < target_len {
            debug!("invalid proxy address length: {}", target_len);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid proxy address length",
            ));
        }
    }

    let mut raw =
        unsafe { MaybeUninit::<[u8; PROXY_PACKET_MAX_PROXY_ADDR_SIZE]>::uninit().assume_init() };
    read.read_exact(&mut raw[..len]).await?;
    let raw = &raw[..len];

    let mut discovered_src = None;
    let mut discovered_dest = None;

    match family {
        Family::Unspecified => {
            debug!("unspecified PROXY family data: {:?}", raw);
        }
        Family::Ipv4 => {
            let src_addr = IpAddr::V4(Ipv4Addr::from(to_array(&raw[..4])));
            let dest_addr = IpAddr::V4(Ipv4Addr::from(to_array(&raw[4..8])));
            let src_port = u16::from_be_bytes((&raw[8..10]).try_into().unwrap());
            let dest_port = u16::from_be_bytes((&raw[10..12]).try_into().unwrap());
            discovered_src = Some(SocketAddr::new(src_addr, src_port));
            discovered_dest = Some(SocketAddr::new(dest_addr, dest_port));
        }
        Family::Ipv6 => {
            let src_addr = IpAddr::V6(to_array(&raw[..16]).into());
            let dest_addr = IpAddr::V6(to_array(&raw[16..32]).into());
            let src_port = u16::from_be_bytes((&raw[32..34]).try_into().unwrap());
            let dest_port = u16::from_be_bytes((&raw[34..36]).try_into().unwrap());
            discovered_src = Some(SocketAddr::new(src_addr, src_port));
            discovered_dest = Some(SocketAddr::new(dest_addr, dest_port));
        }
        Family::Unix => {
            warn!("unsupported UNIX PROXY family, ignored.");
        }
    }

    Ok((
        ProxyResult::Proxy(ProxyInfo {
            command,
            family,
            protocol,
            discovered_dest,
            discovered_src,
        }),
        read,
    ))
}

impl AsyncRead for WrappedStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.fused_error {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::Unsupported,
                "called read after error",
            )));
        }
        if matches!(self.proxy_mode, ProxyMode::None) {
            return self
                .inner_read
                .as_mut()
                .unwrap()
                .as_mut()
                .poll_read(cx, buf);
        }
        assert!(buf.remaining() >= PROXY_SIGNATURE.len());

        if self.pending_read_proxy.is_none() {
            self.pending_read_proxy = Some(Box::pin(read_proxy(self.inner_read.take().unwrap())));
        }
        let output = self.pending_read_proxy.as_mut().unwrap().as_mut().poll(cx);
        match output {
            Poll::Ready(Err(e)) => {
                self.fused_error = true;
                self.pending_read_proxy = None;
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok((ProxyResult::SignatureBytes(bytes), stream))) => {
                if matches!(self.proxy_mode, ProxyMode::Require) {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "required a PROXYv2 header, none found",
                    )));
                }
                self.proxy_mode = ProxyMode::None;
                buf.put_slice(&bytes[..]);
                self.pending_read_proxy = None;
                self.inner_read = Some(stream);
                #[cfg(feature = "tonic")]
                {
                    *self.connect_info.write().unwrap() = Some(self.source());
                }
                self.inner_read
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll_read(cx, buf)
            }
            Poll::Ready(Ok((ProxyResult::Proxy(info), stream))) => {
                self.proxy_mode = ProxyMode::None;
                self.info = Some(info);
                self.pending_read_proxy = None;
                self.inner_read = Some(stream);
                #[cfg(feature = "tonic")]
                {
                    *self.connect_info.write().unwrap() = Some(self.source());
                }
                self.inner_read
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll_read(cx, buf)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl WrappedStream {
    /// Returns `true` if PROXYv2 information was sent
    pub fn was_proxied(&self) -> bool {
        self.info.is_some()
    }

    /// PROXYv2 reported command or None
    pub fn command(&self) -> Option<Command> {
        self.info.as_ref().map(|x| x.command)
    }

    /// PROXYv2 reported family or None
    pub fn family(&self) -> Option<Family> {
        self.info.as_ref().map(|x| x.family)
    }

    /// PROXYv2 reported protocol or None
    pub fn protocol(&self) -> Option<Protocol> {
        self.info.as_ref().map(|x| x.protocol)
    }

    /// PROXYv2 reported destination or None
    pub fn destination(&self) -> Option<SocketAddr> {
        self.info.as_ref().map(|x| x.discovered_dest).flatten()
    }

    /// PROXYv2 reported source or original address if none
    pub fn source(&self) -> SocketAddr {
        self.info
            .as_ref()
            .map(|x| x.discovered_src)
            .flatten()
            .unwrap_or_else(|| self.remote_addr)
    }

    /// The actual source that connected to us
    pub fn original_source(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl AsyncWrite for WrappedStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner_write.as_mut().poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.inner_write.as_mut().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner_write.as_mut().poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner_write.as_mut().poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner_write.is_write_vectored()
    }
}

#[cfg(feature = "track_conn_count")]
impl Drop for WrappedStream {
    fn drop(&mut self) {
        self.conn_count.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse() {
        let raw = hex::decode("0d0a0d0a000d0a515549540a21110054ffffffffac1f1cd1898801bb030004508978bb04003e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(
            read_proxy(&raw[..]).await.unwrap().0,
            ProxyResult::Proxy(ProxyInfo {
                command: Command::Proxy,
                family: Family::Ipv4,
                protocol: Protocol::Stream,
                discovered_dest: Some("172.31.28.209:443".parse().unwrap()),
                discovered_src: Some("255.255.255.255:35208".parse().unwrap()),
            })
        );
    }
}
