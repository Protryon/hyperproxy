use std::net::SocketAddr;
use std::pin::Pin;
#[cfg(feature = "track_conn_count")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "track_conn_count")]
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::Stream;
use hyper::server::accept::Accept;
use hyper::server::conn::AddrIncoming;

use crate::{ProxyMode, WrappedStream};

pub struct WrappedIncoming {
    inner: AddrIncoming,
    #[cfg(feature = "track_conn_count")]
    conn_count: Arc<AtomicU64>,
    proxy_mode: ProxyMode,
}

impl WrappedIncoming {
    pub fn new(
        addr: SocketAddr,
        nodelay: bool,
        keepalive: Option<Duration>,
        proxy_mode: ProxyMode,
    ) -> hyper::Result<Self> {
        let mut inner = AddrIncoming::bind(&addr)?;
        inner.set_nodelay(nodelay);
        inner.set_keepalive(keepalive);
        Ok(WrappedIncoming {
            inner,
            #[cfg(feature = "track_conn_count")]
            conn_count: Arc::new(AtomicU64::new(0)),
            proxy_mode,
        })
    }

    #[cfg(feature = "track_conn_count")]
    pub fn get_conn_count(&self) -> Arc<AtomicU64> {
        self.conn_count.clone()
    }
}

impl Stream for WrappedIncoming {
    type Item = Result<WrappedStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_accept(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                #[cfg(feature = "track_conn_count")]
                self.conn_count.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(WrappedStream {
                    inner: Some(Box::pin(stream)),
                    #[cfg(feature = "track_conn_count")]
                    conn_count: self.conn_count.clone(),
                    pending_read_proxy: None,
                    fused_error: false,
                    info: None,
                    proxy_mode: self.proxy_mode,
                })))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
