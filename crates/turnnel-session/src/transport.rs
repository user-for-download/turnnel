use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

use crate::codec::TurnCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Tls { sni: String },
}

#[async_trait]
pub trait TransportTx: Send + Sync {
    async fn send(&self, data: Bytes) -> anyhow::Result<()>;
    fn server_addr(&self) -> SocketAddr;
}

#[async_trait]
pub trait TransportRx: Send + Sync {
    async fn recv(&mut self) -> anyhow::Result<(Bytes, SocketAddr)>;
    async fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<Option<(Bytes, SocketAddr)>>;
}

pub async fn connect(
    server_addr: SocketAddr,
    protocol: &TransportProtocol,
) -> anyhow::Result<(Box<dyn TransportTx>, Box<dyn TransportRx>)> {
    match protocol {
        TransportProtocol::Udp => {
            let bind_addr: SocketAddr = if server_addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

            let tx = Box::new(UdpTx {
                socket: socket.clone(),
                server_addr,
            });
            let rx = Box::new(UdpRx {
                socket,
                server_addr,
            });
            Ok((tx, rx))
        }
        TransportProtocol::Tcp => {
            let stream = TcpStream::connect(server_addr).await?;
            stream.set_nodelay(true)?;

            let framed = Framed::new(stream, TurnCodec);
            let (sink, stream) = framed.split();

            let tx = Box::new(StreamTx {
                sink: Arc::new(Mutex::new(sink)),
                server_addr,
            });
            let rx = Box::new(StreamRx {
                stream,
                server_addr,
            });
            Ok((tx, rx))
        }
        TransportProtocol::Tls { sni } => {
            let mut root_cert_store = RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                root_cert_store.add(cert).ok();
            }

            let config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let stream = TcpStream::connect(server_addr).await?;
            stream.set_nodelay(true)?;

            let domain = rustls_pki_types::ServerName::try_from(sni.as_str())?.to_owned();

            let tls_stream = connector.connect(domain, stream).await?;
            let framed = Framed::new(tls_stream, TurnCodec);
            let (sink, stream) = framed.split();

            let tx = Box::new(StreamTx {
                sink: Arc::new(Mutex::new(sink)),
                server_addr,
            });
            let rx = Box::new(StreamRx {
                stream,
                server_addr,
            });
            Ok((tx, rx))
        }
    }
}

struct UdpTx {
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
}

#[async_trait]
impl TransportTx for UdpTx {
    async fn send(&self, data: Bytes) -> anyhow::Result<()> {
        self.socket.send_to(&data, self.server_addr).await?;
        Ok(())
    }
    fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

struct UdpRx {
    socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    server_addr: SocketAddr,
}

#[async_trait]
impl TransportRx for UdpRx {
    async fn recv(&mut self) -> anyhow::Result<(Bytes, SocketAddr)> {
        let mut buf = vec![0u8; 65535];
        let (n, src) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((Bytes::from(buf), src))
    }

    async fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<Option<(Bytes, SocketAddr)>> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(res) => Ok(Some(res?)),
            Err(_) => Ok(None),
        }
    }
}

struct StreamTx<S> {
    sink: Arc<Mutex<S>>,
    server_addr: SocketAddr,
}

#[async_trait]
impl<S> TransportTx for StreamTx<S>
where
    S: futures_util::Sink<Bytes, Error = std::io::Error> + Unpin + Send + Sync,
{
    async fn send(&self, data: Bytes) -> anyhow::Result<()> {
        let mut sink = self.sink.lock().await;
        sink.send(data).await?;
        Ok(())
    }
    fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

struct StreamRx<S> {
    stream: S,
    server_addr: SocketAddr,
}

#[async_trait]
impl<S> TransportRx for StreamRx<S>
where
    S: futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin + Send + Sync,
{
    async fn recv(&mut self) -> anyhow::Result<(Bytes, SocketAddr)> {
        match self.stream.next().await {
            Some(Ok(bytes)) => Ok((bytes, self.server_addr)),
            Some(Err(e)) => anyhow::bail!("Stream read error: {}", e),
            None => anyhow::bail!("Stream closed by server"),
        }
    }

    async fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<Option<(Bytes, SocketAddr)>> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(res) => Ok(Some(res?)),
            Err(_) => Ok(None),
        }
    }
}
