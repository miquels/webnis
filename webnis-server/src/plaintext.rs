//! A plain TCP version of the AddrIncoming from hyper_tls_hack.
//!
//! This exists so that we can utilize from_std_listener.
//! Should patch upstream hyper for this and send a pull request. really.
//!
use std::fmt;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::{Duration, Instant};
use std::io;

use futures::prelude::*;
use futures::stream::Stream;
use tokio::reactor::Handle;
use tokio::net::{TcpStream, TcpListener};
use tokio::timer::Delay;

/// A stream of connections from binding to an address.
#[must_use = "streams do nothing unless polled"]
pub struct AddrIncoming {
    addr: SocketAddr,
    listener: TcpListener,
    sleep_on_errors: bool,
    tcp_keepalive_timeout: Option<Duration>,
    tcp_nodelay: bool,
    timeout: Option<Delay>,
}

impl AddrIncoming {

    /// Build a new `AddrIncoming`
    #[allow(dead_code)]
    pub fn new(addr: &SocketAddr, handle: Option<&Handle>) -> io::Result<AddrIncoming> {
        let listener = if let Some(handle) = handle {
            let std_listener = StdTcpListener::bind(addr)?;
            TcpListener::from_std(std_listener, handle)?
        } else {
            TcpListener::bind(addr)?
        };

        let addr = listener.local_addr()?;

        Ok(AddrIncoming {
            addr: addr,
            listener: listener,
            sleep_on_errors: true,
            tcp_keepalive_timeout: None,
            tcp_nodelay: false,
            timeout: None,
        })
    }

    /// Create a new `AddrIncoming` from the standard library's TCP listener.
    #[allow(dead_code)]
    pub fn from_std_listener(std_listener: StdTcpListener, handle: Option<&Handle>) -> io::Result<AddrIncoming> {
        let listener = if let Some(handle) = handle {
            TcpListener::from_std(std_listener, handle)?
        } else {
            TcpListener::from_std(std_listener, &Handle::default())?
        };

        let addr = listener.local_addr()?;

        Ok(AddrIncoming {
            addr: addr,
            listener: listener,
            sleep_on_errors: true,
            tcp_keepalive_timeout: None,
            tcp_nodelay: false,
            timeout: None,
        })
    }

    /// Get the local address bound to this listener.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Set whether TCP keepalive messages are enabled on accepted connections.
    /// probes.
    #[allow(dead_code)]
    pub fn set_keepalive(&mut self, keepalive: Option<Duration>) -> &mut Self {
        self.tcp_keepalive_timeout = keepalive;
        self
    }

    /// Set the value of `TCP_NODELAY` option for accepted connections.
    #[allow(dead_code)]
    pub fn set_nodelay(&mut self, enabled: bool) -> &mut Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Set whether to sleep on accept errors.
    #[allow(dead_code)]
    pub fn set_sleep_on_errors(&mut self, val: bool) {
        self.sleep_on_errors = val;
    }
}

impl Stream for AddrIncoming {
    type Item = TcpStream;
    type Error = ::std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

        // Check if a previous timeout is active that was set by IO errors.
        if let Some(ref mut to) = self.timeout {
            match to.poll() {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(err) => {
                    error!("sleep timer error: {}", err);
                }
            }
        }
        self.timeout = None;

        // Check the listening socket for incoming TCP connections.
        loop {
            match self.listener.poll_accept() {
                Ok(Async::Ready((socket, _addr))) => {
                    if let Some(dur) = self.tcp_keepalive_timeout {
                        if let Err(e) = socket.set_keepalive(Some(dur)) {
                            trace!("error trying to set TCP keepalive: {}", e);
                        }
                    }
                    if let Err(e) = socket.set_nodelay(self.tcp_nodelay) {
                        trace!("error trying to set TCP nodelay: {}", e);
                    }
                    return Ok(Async::Ready(Some(socket)));
                },
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    if self.sleep_on_errors {
                        // Connection errors can be ignored directly, continue by
                        // accepting the next request.
                        if is_connection_error(&e) {
                            debug!("accepted connection already errored: {}", e);
                            continue;
                        }
                        // Sleep 1s.
                        let delay = Instant::now() + Duration::from_secs(1);
                        let mut timeout = Delay::new(delay);

                        match timeout.poll() {
                            Ok(Async::Ready(())) => {
                                // Wow, it's been a second already? Ok then...
                                error!("accept error: {}", e);
                                continue
                            },
                            Ok(Async::NotReady) => {
                                error!("accept error: {}", e);
                                self.timeout = Some(timeout);
                                return Ok(Async::NotReady);
                            },
                            Err(timer_err) => {
                                error!("couldn't sleep on error, timer error: {}", timer_err);
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(e);
                    }
                },
            }
        }
    }
}

/// This function defines errors that are per-connection. Which basically
/// means that if we get this error from `accept()` system call it means
/// next connection might be ready to be accepted.
///
/// All other errors will incur a timeout before next `accept()` is performed.
/// The timeout is useful to handle resource exhaustion errors like ENFILE
/// and EMFILE. Otherwise, could enter into tight loop.
fn is_connection_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionRefused ||
    e.kind() == io::ErrorKind::ConnectionAborted ||
    e.kind() == io::ErrorKind::ConnectionReset
}

impl fmt::Debug for AddrIncoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AddrIncoming")
            .field("addr", &self.addr)
            .field("sleep_on_errors", &self.sleep_on_errors)
            .field("tcp_keepalive_timeout", &self.tcp_keepalive_timeout)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .finish()
    }
}

