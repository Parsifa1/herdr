//! SSH-authorized QUIC transport for remote clients.
//!
//! The transport is an opaque pipe. An authenticated QUIC connection is
//! adapted onto a Unix socketpair whose far end is handed to the ordinary
//! client acceptor, so nothing here decodes the framed protocol it carries:
//! the server render, input, and session paths are byte-for-byte the ones a
//! local Unix client drives.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::config::RemoteConfig;
use crate::protocol::{
    RemoteBootstrapRecord, RemoteBootstrapRequest, RemoteQuicAccepted, RemoteQuicHello,
    MAX_FRAME_SIZE, REMOTE_QUIC_ALPN, REMOTE_QUIC_HASH_BYTES, REMOTE_QUIC_ID_BYTES,
    REMOTE_QUIC_SCHEMA_VERSION,
};
use crate::remote::frame::{hash_bytes, lock, read_async_message, write_async_message};
use crate::remote::quic_policy::{
    REMOTE_QUIC_CLOSE_AUTH, REMOTE_QUIC_CLOSE_EVICTED, REMOTE_QUIC_CLOSE_HANDOFF,
    REMOTE_QUIC_CLOSE_PROTOCOL, REMOTE_QUIC_CLOSE_REPLACED, REMOTE_QUIC_CLOSE_SHUTDOWN,
    REMOTE_QUIC_INITIAL_CONGESTION_WINDOW, REMOTE_QUIC_INITIAL_RTT,
};

/// Client slots kept live at once. An authenticated device opens one slot per
/// logical client it claims, so the bound is about memory, not trust.
const MAX_CLIENTS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// A hello is a handful of scalars plus fixed-size identifiers; anything
/// larger is a peer that cannot authenticate anyway, so it is refused before
/// the decoder is handed a length it would trust.
const MAX_HELLO_SIZE: usize = 4096;
/// The server's own NAT keep-alive. The client drives resume probes; this is
/// only the cheap heartbeat that keeps a middlebox binding warm well inside
/// `remote.quic_transport_idle_timeout_seconds`.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
// Flow-control caps, not allocations; see the client-side note in
// src/remote/quic.rs. Sized for the render burst a graphics-heavy pane sends,
// not for one high-latency link profile. `QUIC_SEND_WINDOW` only seeds the
// connection: `bound_unsent` lowers it before every write.
const QUIC_SEND_WINDOW: u64 = 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const QUIC_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// How much quinn may hold written but unsent past what the congestion window
/// lets out, connection-wide. quinn counts written-but-unacknowledged bytes
/// against its send window, so bound the window to `cwnd + this` and in-flight
/// is at most cwnd: at most this much waits where nothing can reorder or drop
/// it. Without it the window above lets a megabyte of screen output sit
/// outside reach of any priority, and the next control frame queues behind it.
const QUIC_LOWAT: u64 = 16 * 1024;
/// Per-direction copy buffer for one adapted connection. Large enough that a
/// multi-megabyte frame moves in a few syscalls, small enough that 32
/// pre-auth connections cannot pin meaningful memory.
const COPY_BUFFER_BYTES: usize = 64 * 1024;
// Connection close codes live in src/remote/quic_policy.rs: they are on the
// wire, so the client and the server must read them from one place.

/// Receives the server-side end of an accepted, authenticated QUIC client.
/// The callee treats it exactly like a freshly accepted Unix-socket client:
/// the socket carries the ordinary framed protocol, starting with the client's
/// own `Hello`.
pub(crate) type AcceptedClientSink = Arc<dyn Fn(StdUnixStream) + Send + Sync>;

#[derive(Debug)]
struct ActiveClient {
    active_connection: Option<Connection>,
    issued_order: u64,
}

/// One remote client: the device certificate it authenticated with, plus the
/// logical client it claims to be. The certificate digest comes from the TLS
/// peer identity, so neither half can be chosen by an unauthenticated peer.
type ClientKey = ([u8; REMOTE_QUIC_HASH_BYTES], [u8; REMOTE_QUIC_ID_BYTES]);

struct ServerState {
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    clients: Mutex<HashMap<ClientKey, ActiveClient>>,
    client_order: AtomicU64,
    /// The single session this server process owns. A device enrolled for
    /// another session never authenticates here.
    active_session: String,
    sink: AcceptedClientSink,
}

/// Process-lifetime QUIC endpoint. It is constructed only after an authenticated
/// local bootstrap request, so ordinary/local Herdr never binds UDP or creates TLS material.
pub(crate) struct RemoteQuicServer {
    endpoints: Vec<Endpoint>,
    /// Duplicates of the bound UDP sockets, kept only so a live handoff can
    /// pass the listening sockets to the successor process. They are never
    /// read from: quinn owns its own duplicate of each.
    sockets: Vec<UdpSocket>,
    state: Arc<ServerState>,
    port: u16,
    identity: ServerIdentity,
    handed_off: AtomicBool,
}

impl RemoteQuicServer {
    /// Binds the listener and spawns its accept loops onto the ambient tokio
    /// runtime, which is the server's own.
    pub(crate) fn start(
        config: &RemoteConfig,
        active_session: String,
        sink: AcceptedClientSink,
    ) -> io::Result<Self> {
        let (start_port, end_port) = parse_port_range(&config.quic_port_range)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let identity = ServerIdentity::load_or_create().map_err(|err| {
            io::Error::other(format!("failed to load remote QUIC identity: {err}"))
        })?;
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout()).map_err(
                |err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to build remote QUIC server config: {err}"),
                    )
                },
            )?;
        let (sockets, port) = bind_sockets(start_port, end_port)?;
        let endpoints = make_endpoints(&server_config, &sockets)?;

        let server_instance_id = identity.server_instance_id;
        let state = Arc::new(ServerState {
            server_instance_id,
            clients: Mutex::new(HashMap::new()),
            client_order: AtomicU64::new(1),
            active_session,
            sink,
        });

        for endpoint in &endpoints {
            tokio::spawn(accept_connections(endpoint.clone(), Arc::clone(&state)));
        }
        info!(
            port,
            endpoints = endpoints.len(),
            "remote QUIC endpoint enabled"
        );
        Ok(Self {
            endpoints,
            sockets,
            state,
            port,
            identity,
            handed_off: AtomicBool::new(false),
        })
    }

    /// Rebuilds the endpoint in a successor process from an exported state and
    /// the inherited sockets. Server instance id, certificate, and port are
    /// preserved, so a client's pinned certificate fingerprint keeps
    /// validating and the device certificate it already enrolled with is still
    /// the one the successor accepts: it reconnects instead of rebootstrapping
    /// over SSH.
    pub(crate) fn resume(
        config: &RemoteConfig,
        active_session: String,
        sink: AcceptedClientSink,
        state: RemoteQuicHandoffState,
        sockets: Vec<UdpSocket>,
    ) -> io::Result<Self> {
        if sockets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote QUIC handoff carried no sockets",
            ));
        }
        let identity = ServerIdentity {
            server_instance_id: state.server_instance_id,
            certificate_der: state.certificate_der,
            private_key_der: state.private_key_der,
            fingerprint: state.certificate_fingerprint,
        };
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout()).map_err(
                |err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to restore remote QUIC certificate: {err}"),
                    )
                },
            )?;
        for socket in &sockets {
            socket.set_nonblocking(true)?;
        }
        let endpoints = make_endpoints(&server_config, &sockets)?;

        let server_state = Arc::new(ServerState {
            server_instance_id: state.server_instance_id,
            clients: Mutex::new(HashMap::new()),
            client_order: AtomicU64::new(1),
            active_session,
            sink,
        });
        for endpoint in &endpoints {
            tokio::spawn(accept_connections(
                endpoint.clone(),
                Arc::clone(&server_state),
            ));
        }
        info!(
            port = state.port,
            endpoints = endpoints.len(),
            "remote QUIC endpoint resumed from handoff"
        );
        Ok(Self {
            endpoints,
            sockets,
            state: server_state,
            port: state.port,
            identity,
            handed_off: AtomicBool::new(false),
        })
    }

    /// UDP port the endpoint listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Answers the SSH-authenticated caller with the information it cannot
    /// learn locally: this endpoint's port and the identity to pin.
    ///
    /// Nothing here authorizes the client. Authorization is the device
    /// certificate it presents on the QUIC handshake, so the reply carries no
    /// secret and a copied hosts.json grants nothing.
    pub(crate) fn bootstrap(
        &self,
        request: &RemoteBootstrapRequest,
    ) -> Result<RemoteBootstrapRecord, String> {
        if request.session != self.state.active_session {
            return Err(format!(
                "remote bootstrap session mismatch: requested {}, server owns {}",
                request.session, self.state.active_session
            ));
        }

        Ok(RemoteBootstrapRecord {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: self.state.server_instance_id,
            port: self.port,
            certificate_fingerprint: self.identity.fingerprint,
        })
    }

    /// Snapshots everything a successor process needs to serve the same
    /// endpoint, together with duplicates of the listening UDP sockets (IPv4
    /// first, then IPv6 when bound). The duplicates are what travel to the
    /// successor; this process keeps its own.
    pub(crate) fn export_handoff(&self) -> io::Result<(RemoteQuicHandoffState, Vec<UdpSocket>)> {
        let mut sockets = Vec::with_capacity(self.sockets.len());
        for socket in &self.sockets {
            sockets.push(socket.try_clone()?);
        }
        let socket_fd_count = u8::try_from(sockets.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "too many remote QUIC sockets to hand off",
            )
        })?;
        Ok((
            RemoteQuicHandoffState {
                server_instance_id: self.state.server_instance_id,
                certificate_der: self.identity.certificate_der.clone(),
                private_key_der: self.identity.private_key_der.clone(),
                certificate_fingerprint: self.identity.fingerprint,
                port: self.port,
                socket_fd_count,
            },
            sockets,
        ))
    }

    /// Closes every endpoint with the handoff code, telling connected clients
    /// to reconnect with the device certificate they already enrolled instead
    /// of rebootstrapping over SSH. Suppresses the shutdown close on drop.
    pub(crate) fn close_for_handoff(&self) {
        self.handed_off.store(true, Ordering::Release);
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_HANDOFF),
                b"server handoff",
            );
        }
    }

    /// Closes every endpoint permanently: the port, certificate, and instance
    /// id die with this process, so clients must bootstrap again.
    pub(crate) fn close_for_shutdown(&self) {
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_SHUTDOWN),
                b"server shutdown",
            );
        }
    }
}

impl Drop for RemoteQuicServer {
    fn drop(&mut self) {
        if self.handed_off.load(Ordering::Acquire) {
            // `close_for_handoff` already told clients to reconnect; a second
            // close would look like a permanent shutdown.
            return;
        }
        self.close_for_shutdown();
    }
}

/// Everything a successor process needs to serve the same QUIC endpoint across
/// a live handoff. Client authorization does not travel with it: it comes from
/// the device allowlist on disk and the certificate each client presents, so a
/// client reconnects with what it already has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RemoteQuicHandoffState {
    pub(crate) server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) private_key_der: Vec<u8>,
    pub(crate) certificate_fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) port: u16,
    /// Number of UDP socket descriptors that travel with this state.
    #[serde(default)]
    pub(crate) socket_fd_count: u8,
}

fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| "remote.quic_port_range must look like 48000-48100".to_owned())?;
    let start = start
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid start port".to_owned())?;
    let end = end
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid end port".to_owned())?;
    if start < 1024 || start > end {
        return Err("remote.quic_port_range must be an ascending unprivileged range".to_owned());
    }
    Ok((start, end))
}

/// The self-signed TLS material the client pins by fingerprint. Kept in DER
/// so a live handoff can rebuild the exact same identity in the successor.
#[derive(Clone)]
struct ServerIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
}

impl ServerIdentity {
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["herdr".to_owned()])?;
        let certificate_der = cert.der().to_vec();
        let private_key_der = signing_key.serialize_der();
        Ok(Self {
            fingerprint: hash_bytes(&certificate_der),
            server_instance_id: derive_instance_id(&certificate_der),
            certificate_der,
            private_key_der,
        })
    }

    /// Reload the identity a previous process persisted, or mint and store a
    /// new one. Clients pin the certificate fingerprint, so a per-process
    /// identity would force an SSH bootstrap after every server restart.
    fn load_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = server_key_path();
        if let Some(identity) = Self::read(&path)? {
            return Ok(identity);
        }
        let identity = Self::generate()?;
        identity.store(&path)?;
        Self::read(&path)?.ok_or_else(|| {
            io::Error::other(format!("{} disappeared while it was created", path.display())).into()
        })
    }

    fn read(path: &std::path::Path) -> io::Result<Option<Self>> {
        let Some(bytes) = crate::remote::private_file::read(path)? else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let (private_key_der, certificate_der) =
            crate::remote::private_file::pem_read_key_and_certificate(text)?;
        Ok(Some(Self {
            fingerprint: hash_bytes(&certificate_der),
            server_instance_id: derive_instance_id(&certificate_der),
            certificate_der,
            private_key_der,
        }))
    }

    fn store(&self, path: &std::path::Path) -> io::Result<()> {
        let bundle = crate::remote::private_file::pem_encode(&[
            ("PRIVATE KEY", &self.private_key_der),
            ("CERTIFICATE", &self.certificate_der),
        ]);
        crate::remote::private_file::create_exclusive(path, bundle.as_bytes())?;
        Ok(())
    }
}

/// Derived from the certificate rather than stored: a client's cached credential
/// and its pinned fingerprint then depend on exactly one persisted fact, so a
/// fresh instance id can never invalidate a credential the certificate still
/// authorizes.
fn derive_instance_id(certificate_der: &[u8]) -> [u8; REMOTE_QUIC_ID_BYTES] {
    let digest = hash_bytes(certificate_der);
    let mut instance_id = [0u8; REMOTE_QUIC_ID_BYTES];
    instance_id.copy_from_slice(&digest[..REMOTE_QUIC_ID_BYTES]);
    instance_id
}

fn server_key_path() -> std::path::PathBuf {
    crate::config::state_dir().join("server.key")
}

fn make_server_config(
    identity: &ServerIdentity,
    idle_timeout: Duration,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let cert_der = rustls::pki_types::CertificateDer::from(identity.certificate_der.clone());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into();
    let verifier = Arc::new(crate::remote::device::DeviceCertVerifier::new());
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert_der], key)?;
    tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.migration(true);
    server_config.transport_config(Arc::new(transport_config(idle_timeout)?));
    Ok(server_config)
}

fn transport_config(idle_timeout: Duration) -> Result<quinn::TransportConfig, io::Error> {
    let mut transport = quinn::TransportConfig::default();
    let idle = idle_timeout.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC idle timeout is too large",
        )
    })?;
    transport
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        // One control stream carries the hello and the health pings; every
        // further bidirectional stream is one remote client session, so a
        // multiplexing bridge can attach several clients over one
        // connection.
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_CLIENT_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        .initial_rtt(REMOTE_QUIC_INITIAL_RTT)
        // See the matching note in src/remote/quic.rs: BBR paces to measured
        // bottleneck bandwidth, so random loss on a mobile path does not
        // collapse the send window the way loss-based Cubic does. Its initial
        // window is overridden for the same reason as there: quinn's BBR
        // starts at 200 packets, and the server's first burst is a full-screen
        // repaint.
        .congestion_controller_factory(Arc::new({
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(REMOTE_QUIC_INITIAL_CONGESTION_WINDOW);
            bbr
        }));
    Ok(transport)
}

/// Binds the first port in the range that IPv4 accepts. IPv6 is best effort
/// at that same port: refusing the port because its v6 half is taken would
/// leave the client with no endpoint at all, so the failure is logged and the
/// IPv4-only listener is kept.
fn bind_sockets(start_port: u16, end_port: u16) -> io::Result<(Vec<UdpSocket>, u16)> {
    let mut last_error = None;
    for port in start_port..=end_port {
        let ipv4_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let ipv4_socket = match bind_udp_socket(Domain::IPV4, ipv4_address) {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut sockets = vec![ipv4_socket];

        let ipv6_address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match bind_udp_socket(Domain::IPV6, ipv6_address) {
            Ok(socket) => sockets.push(socket),
            Err(error) => {
                debug!(%error, port, "IPv6 QUIC listener unavailable; using IPv4");
            }
        }
        return Ok((sockets, port));
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no free UDP port in {start_port}-{end_port}"),
        )
    }))
}

/// Hands quinn its own duplicate of each socket, so the originals stay
/// available for a later handoff.
fn make_endpoints(
    server_config: &quinn::ServerConfig,
    sockets: &[UdpSocket],
) -> io::Result<Vec<Endpoint>> {
    sockets
        .iter()
        .map(|socket| make_endpoint(server_config.clone(), socket.try_clone()?))
        .collect()
}

fn bind_udp_socket(domain: Domain, address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn make_endpoint(server_config: quinn::ServerConfig, socket: UdpSocket) -> io::Result<Endpoint> {
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Pre-auth admission cap: each accepted handshake spawns unauthenticated work
/// (TLS handshake, hello decode) and quinn's default allows up to 65,536
/// concurrent incoming, so without a bound an attacker can exhaust memory/CPU
/// before ever authenticating. Excess handshakes are refused outright.
const MAX_PREAUTH_CONNECTIONS: usize = 32;
/// Client sessions one authenticated connection may carry as concurrent
/// bidirectional streams. A bridge multiplexes every attached client onto
/// one connection; the bound keeps a rogue peer from exhausting the
/// stream map.
const MAX_CLIENT_STREAMS: u32 = 128;

async fn accept_connections(endpoint: Endpoint, state: Arc<ServerState>) {
    let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            debug!(remote = %incoming.remote_address(), "refusing QUIC connection: admission limit reached");
            incoming.refuse();
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    // Every failure path inside `serve_connection` closes with
                    // the code the client needs to act on, so there is nothing
                    // left to decide here.
                    if let Err(err) = serve_connection(connection.clone(), state, permit).await {
                        debug!(err = %err, remote = %connection.remote_address(), "remote QUIC connection ended");
                    }
                }
                Err(err) => debug!(err = %err, "remote QUIC handshake failed"),
            }
        });
    }
}

async fn serve_connection(
    connection: Connection,
    state: Arc<ServerState>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), String> {
    let (send, recv, hello) = match accept_hello(&connection).await {
        Ok(accepted) => accepted,
        Err(err) => {
            connection.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_PROTOCOL),
                b"unusable remote QUIC hello",
            );
            return Err(err);
        }
    };

    validate_and_fence(&state, &connection, &hello)?;
    // The admission cap exists to bound work an *unauthenticated* peer can
    // start, so it ends here. Holding it for the connection's life turns the
    // cap into a limit on live sessions: a reconnect storm would occupy every
    // permit with already-trusted connections and refuse the next one.
    drop(permit);
    // Reply on the hello stream before it becomes the liveness channel; a
    // session then rides on its own stream, opened by the bridge.
    let mut control_send = send;
    write_async_message(
        &mut control_send,
        &RemoteQuicAccepted {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
        },
        MAX_FRAME_SIZE,
    )
    .await?;
    let control = tokio::spawn(drain_control_stream(control_send, recv));
    loop {
        let (stream_send, stream_recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let state = Arc::clone(&state);
        let stream_connection = connection.clone();
        tokio::spawn(async move {
            if let Err(err) =
                serve_client_stream(stream_send, stream_recv, &stream_connection, &state).await
            {
                debug!(%err, "remote QUIC client stream ended");
            }
        });
    }
    control.abort();
    Ok(())
}

/// Reads the hello stream's halves open so the bridge's health pings keep a
/// reader on the other side. A health ping is answered with a pong: the bridge
/// measures path liveness from these replies. Anything else stays opaque and
/// is discarded so it does not fill the stream's receive buffer; the send half
/// is held open so the bridge never sees the liveness channel close.
async fn drain_control_stream(mut send: SendStream, mut recv: RecvStream) -> Result<(), String> {
    loop {
        let control: Result<crate::protocol::ClientMessage, String> =
            read_async_message(&mut recv, MAX_HELLO_SIZE).await;
        let message = match control {
            Ok(message) => message,
            Err(detail) => {
                // The bridge closes the stream when the pump ends; the peer
                // sending garbage on the liveness channel ends the same way.
                debug!(%detail, "remote QUIC control stream ended");
                return Ok(());
            }
        };
        if let crate::protocol::ClientMessage::EndpointControl { kind, data } = message {
            if let Some(pong) = crate::server::client_endpoint_control::response(&kind, data) {
                if let Err(detail) = write_async_message(&mut send, &pong, MAX_FRAME_SIZE).await {
                    return Err(detail);
                }
            }
        }
    }
}

/// Reads the first frame on the client's single bidirectional stream. Every
/// failure here is a protocol failure: the peer either never opened the
/// stream, sent something undecodable, or speaks a different schema.
async fn accept_hello(
    connection: &Connection,
) -> Result<(SendStream, RecvStream, RemoteQuicHello), String> {
    let (send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| "timed out waiting for the QUIC client stream".to_owned())?
        .map_err(|err| format!("failed to accept the QUIC client stream: {err}"))?;
    let hello: RemoteQuicHello = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_async_message(&mut recv, MAX_HELLO_SIZE),
    )
    .await
    .map_err(|_| "timed out waiting for the QUIC hello".to_owned())??;
    if hello.schema_version != REMOTE_QUIC_SCHEMA_VERSION {
        return Err(format!(
            "remote QUIC schema mismatch: client {}, server {REMOTE_QUIC_SCHEMA_VERSION}",
            hello.schema_version
        ));
    }
    Ok((send, recv, hello))
}

/// Turns one bidirectional stream of the authenticated connection into an
/// ordinary client of this server: one end of a Unix socketpair goes to the
/// acceptor, and this task copies bytes between the other end and the QUIC
/// stream. Nothing is decoded, so the client and server negotiate their
/// protocol exactly as they do over a local socket. Closing the stream ends
/// only this client session; the connection and its other streams live on.
async fn serve_client_stream(
    mut send: SendStream,
    recv: RecvStream,
    connection: &Connection,
    state: &ServerState,
) -> Result<(), String> {
    let (adapter_end, client_end) = tokio::net::UnixStream::pair()
        .map_err(|err| format!("failed to create the remote QUIC socket pair: {err}"))?;
    let client_end = client_end
        .into_std()
        .map_err(|err| format!("failed to detach the remote QUIC client socket: {err}"))?;
    // The acceptor expects the same blocking socket its own listener yields.
    client_end
        .set_nonblocking(false)
        .map_err(|err| format!("failed to reset the remote QUIC client socket: {err}"))?;
    (state.sink)(client_end);
    let (local_read, local_write) = adapter_end.into_split();
    tokio::select! {
        result = copy_stream(local_read, &mut send, Some(connection)) => {
            // The acceptor closed its end: this client's session is over as
            // far as the server is concerned, but the client slot and the
            // connection stay good for the next stream.
            result.map_err(|err| format!("remote QUIC uplink failed: {err}"))
        }
        result = copy_stream(recv, local_write, None) => {
            // The QUIC side ended; dropping the pair end hands the acceptor an
            // EOF, which is exactly what a local client disconnect looks like.
            result.map_err(|err| format!("remote QUIC downlink failed: {err}"))
        }
    }
}

/// Keeps quinn's unsent backlog at [`QUIC_LOWAT`] past what the congestion
/// window lets out. Refreshed before every write so it follows cwnd as
/// acknowledgments arrive, which is what keeps a large frame from parking
/// itself in quinn's buffer where CREDIT, priorities and cancellation cannot
/// reach it.
fn bound_unsent(connection: &Connection) {
    connection.set_send_window(connection.stats().path.cwnd + QUIC_LOWAT);
}

async fn copy_stream(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    bounded: Option<&Connection>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            return to.flush().await;
        }
        if let Some(connection) = bounded {
            bound_unsent(connection);
        }
        to.write_all(&buffer[..read]).await?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthRejection {
    ServerInstanceChanged,
    DeviceNotAuthorized,
}

impl std::fmt::Display for AuthRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerInstanceChanged => formatter.write_str("remote server instance changed"),
            Self::DeviceNotAuthorized => formatter.write_str("remote device is not authorized"),
        }
    }
}

fn reject(connection: &Connection, rejection: AuthRejection, device: Option<&str>) -> String {
    // The peer gets one opaque reason: telling it "not enrolled" apart from
    // "stale generation" is an oracle for a caller that has not authenticated
    // yet. The variant stays in the log, where an operator can see it.
    let detail = "remote connection rejected";
    connection.close(VarInt::from_u32(REMOTE_QUIC_CLOSE_AUTH), detail.as_bytes());
    let source = connection.remote_address();
    // A refusal from a device the allowlist names is worth recording at the
    // default level. An unknown peer can generate refusals at will, so those
    // stay at debug: otherwise a stranger could push every earlier audit line
    // out of the rotating log.
    match device {
        Some(name) => info!(
            event = "remote.quic.auth.rejected",
            device = %name,
            source = %source,
            rejection = %rejection,
            "remote QUIC client rejected"
        ),
        None => debug!(
            event = "remote.quic.auth.rejected",
            source = %source,
            rejection = %rejection,
            "remote QUIC client rejected"
        ),
    }
    rejection.to_string()
}

fn validate_and_fence(
    state: &ServerState,
    connection: &Connection,
    hello: &RemoteQuicHello,
) -> Result<(), String> {
    let Some(certificate) = presented_device(connection) else {
        return Err(reject(connection, AuthRejection::DeviceNotAuthorized, None));
    };
    // Read per handshake rather than cached, so a revoke takes effect on this
    // device's next connection.
    let devices = crate::remote::device::DeviceList::load(&crate::remote::device::devices_path());
    let authorized = devices.authorize(&certificate, &state.active_session);
    let device = authorized
        .map(|entry| entry.name.as_str())
        .or_else(|| devices.enrolled_name(&certificate));
    if authorized.is_none() {
        return Err(reject(connection, AuthRejection::DeviceNotAuthorized, device));
    }
    if hello.server_instance_id != state.server_instance_id {
        return Err(reject(connection, AuthRejection::ServerInstanceChanged, device));
    }
    let key = (hash_bytes(&certificate), hello.logical_client_id);
    let mut clients = lock(&state.clients);
    if !clients.contains_key(&key) {
        evict_oldest_client(&mut clients);
        let issued_order = state.client_order.fetch_add(1, Ordering::Relaxed);
        clients.insert(
            key,
            ActiveClient {
                active_connection: None,
                issued_order,
            },
        );
    }
    let Some(client) = clients.get_mut(&key) else {
        return Err("remote client slot disappeared while fencing".to_owned());
    };
    // Whatever this slot held is superseded: the client dials only after its
    // own session died, so the newer connection is the one that speaks for it.
    if let Some(previous) = client.active_connection.replace(connection.clone()) {
        previous.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_REPLACED),
            b"newer connection accepted",
        );
    }
    drop(clients);
    // The audit line for the event this whole module exists to decide. Without
    // it a shared host has no record of who connected, which is what an
    // operator needs after any suspected compromise.
    info!(
        event = "remote.quic.auth.accepted",
        device = %device.unwrap_or("unknown-device"),
        source = %connection.remote_address(),
        session = %state.active_session,
        "remote QUIC client authenticated"
    );
    Ok(())
}

/// Bounds the client table. An authenticated peer opens one slot per logical
/// client id it claims, so the oldest slot makes room when the table is full.
fn evict_oldest_client(clients: &mut HashMap<ClientKey, ActiveClient>) {
    if clients.len() < MAX_CLIENTS {
        return;
    }
    let Some(oldest) = clients
        .iter()
        .min_by_key(|(_, client)| client.issued_order)
        .map(|(key, _)| *key)
    else {
        return;
    };
    let Some(removed) = clients.remove(&oldest) else {
        return;
    };
    if let Some(connection) = removed.active_connection {
        connection.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_EVICTED),
            b"client slot evicted",
        );
    }
}

fn presented_device(connection: &Connection) -> Option<Vec<u8>> {
    connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|certificates| certificates.first().map(|certificate| certificate.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    const TEST_SESSION: &str = "session-a";

    #[test]
    fn port_range_requires_ascending_unprivileged_ports() {
        assert_eq!(parse_port_range("48000-48100"), Ok((48000, 48100)));
        assert!(parse_port_range("80-81").is_err());
        assert!(parse_port_range("48100-48000").is_err());
        assert!(parse_port_range("invalid").is_err());
    }

    /// Creates a device identity under a throwaway directory. The directory is
    /// removed once the key and certificate are in memory.
    fn test_device_identity(name: &str) -> crate::remote::device::DeviceIdentity {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "herdr-mtls-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity =
            crate::remote::device::DeviceIdentity::load_or_create(&dir.join("device.json"))
                .expect("create device identity");
        let _ = std::fs::remove_dir_all(&dir);
        identity
    }

    /// Writes a new device certificate into the server's authorized list under
    /// the active config root, so the real verifier runs against real files.
    fn enroll_test_device(name: &str) -> crate::remote::device::DeviceIdentity {
        let identity = test_device_identity(name);
        crate::remote::device::enroll(&identity.certificate_der(), name, TEST_SESSION)
            .expect("enroll device");
        identity
    }

    /// One identity for every dial that does not care which device it is.
    /// Sharing it keeps two connections in one test attributable to the same
    /// client slot, which is what the fencing tests need. Enrollment stays per
    /// call because each test drives its own state root.
    fn shared_test_device() -> &'static crate::remote::device::DeviceIdentity {
        static DEVICE: std::sync::LazyLock<crate::remote::device::DeviceIdentity> =
            std::sync::LazyLock::new(|| test_device_identity("shared"));
        &DEVICE
    }

    #[tokio::test]
    async fn an_enrolled_device_is_accepted_and_a_revoked_one_is_refused() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("mtls");
        let TestServer { server, .. } = test_server_on_free_port();
        let record = mint(&server);

        let identity = enroll_test_device("laptop");
        let mut client = dial_with_hello_and_device(&record, 31, Some(&identity)).await;
        let accepted_hello: RemoteQuicAccepted =
            read_async_message(&mut client.recv, MAX_HELLO_SIZE)
                .await
                .expect("an enrolled device is accepted");
        assert_eq!(accepted_hello.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        drop(client);

        let mut devices =
            crate::remote::device::DeviceList::load(&crate::remote::device::devices_path());
        devices.devices[0].revoked = true;
        devices
            .save(&crate::remote::device::devices_path())
            .expect("save revoked devices");

        let mut revoked = dial_with_hello_and_device(&record, 31, Some(&identity)).await;
        let refusal =
            read_async_message::<RemoteQuicAccepted>(&mut revoked.recv, MAX_HELLO_SIZE).await;
        assert!(
            refusal.is_err(),
            "a revoked certificate must not be accepted"
        );
    }

    #[tokio::test]
    async fn a_device_enrolled_for_another_session_is_refused() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("other-session");
        let TestServer { server, .. } = test_server_on_free_port();
        let record = mint(&server);

        let identity = test_device_identity("elsewhere");
        crate::remote::device::enroll(&identity.certificate_der(), "elsewhere", "session-b")
            .expect("enroll for another session");

        let mut client = dial_with_hello_and_device(&record, 32, Some(&identity)).await;
        let refusal =
            read_async_message::<RemoteQuicAccepted>(&mut client.recv, MAX_HELLO_SIZE).await;
        assert!(
            refusal.is_err(),
            "an enrollment scoped to another session must not authenticate"
        );
        assert!(lock(&server.state.clients).is_empty(), "no slot was created");
        drop(client);
    }

    #[tokio::test]
    async fn an_unenrolled_device_is_refused() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("unenrolled");
        let TestServer { server, .. } = test_server_on_free_port();
        let record = mint(&server);

        let identity = test_device_identity("stranger");
        let mut client = dial_with_hello_and_device(&record, 34, Some(&identity)).await;
        let refusal =
            read_async_message::<RemoteQuicAccepted>(&mut client.recv, MAX_HELLO_SIZE).await;
        assert!(
            refusal.is_err(),
            "a certificate the allowlist does not name must not authenticate"
        );
        assert!(lock(&server.state.clients).is_empty(), "no slot was created");
        drop(client);
    }

    /// Client slots are process state, so a restart forgets them; the device
    /// allowlist is on disk, so the same device reconnects without SSH.
    #[tokio::test]
    async fn an_enrolled_device_reconnects_after_a_server_restart() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("restart");
        let TestServer { server, .. } = test_server_on_free_port();
        let record = mint(&server);
        let identity = enroll_test_device("laptop");

        lock(&server.state.clients).clear();

        let mut client = dial_with_hello_and_device(&record, 33, Some(&identity)).await;
        let accepted: RemoteQuicAccepted = read_async_message(&mut client.recv, MAX_HELLO_SIZE)
            .await
            .expect("an enrolled device reconnects after the slot table dies");
        assert_eq!(accepted.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        assert_eq!(
            lock(&server.state.clients).len(),
            1,
            "the slot is rebuilt for the next reconnect"
        );
        drop(client);
    }

    /// The admission cap bounds work an unauthenticated peer can start. Once a
    /// connection authenticates, its permit must stop counting: otherwise a
    /// reconnect storm holds every permit with trusted connections and the
    /// next client is refused with "server refused to accept a new connection".
    #[tokio::test]
    async fn authenticated_connections_do_not_exhaust_the_admission_cap() {
        let TestServer { server, .. } = test_server_on_free_port();

        // More live connections than the pre-auth cap, each authenticated and
        // then idle: the shape of a bridge that keeps reconnecting. The
        // acceptance reply is the proof the server admitted it; the sink is
        // not involved, so the assertion does not depend on stream relay.
        let mut clients = Vec::new();
        for index in 0..(MAX_PREAUTH_CONNECTIONS + 4) {
            let logical_client_id = u8::try_from(index % 200).expect("id fits a byte");
            let record = mint(&server);
            let mut client = dial_with_hello(&record, logical_client_id).await;
            let accepted_hello: RemoteQuicAccepted =
                read_async_message(&mut client.recv, MAX_HELLO_SIZE)
                    .await
                    .unwrap_or_else(|err| {
                        panic!(
                            "connection {index} was refused past the pre-auth cap, so the \
                             permit was not released on authentication: {err}"
                        )
                    });
            assert_eq!(accepted_hello.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
            clients.push(client);
        }
        assert_eq!(
            clients.len(),
            MAX_PREAUTH_CONNECTIONS + 4,
            "every one of these connections is live at the same time"
        );
    }

    #[test]
    fn admission_semaphore_refuses_beyond_cap_and_recovers() {
        let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
        let permits: Vec<_> = (0..MAX_PREAUTH_CONNECTIONS)
            .map(|_| {
                Arc::clone(&admission)
                    .try_acquire_owned()
                    .expect("permit within cap")
            })
            .collect();
        assert!(Arc::clone(&admission).try_acquire_owned().is_err());
        drop(permits);
        assert!(Arc::clone(&admission).try_acquire_owned().is_ok());
    }

    #[test]
    fn transport_idle_timeout_is_independent_of_the_client_table() {
        let config = RemoteConfig::default();

        let transport =
            transport_config(config.validated_transport_idle_timeout()).expect("transport config");
        let rendered = format!("{transport:?}");
        let expected_idle = u32::try_from(config.validated_transport_idle_timeout().as_millis())
            .expect("idle timeout fits a VarInt");
        assert!(
            rendered.contains(&format!(
                "max_idle_timeout: {:?}",
                Some(VarInt::from_u32(expected_idle))
            )),
            "transport must idle out on the transport timeout, not on any authorization clock: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "keep_alive_interval: {:?}",
                Some(KEEP_ALIVE_INTERVAL)
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("initial_rtt: {REMOTE_QUIC_INITIAL_RTT:?}")),
            "transport must not keep quinn's 333 ms first-RTT guess: {rendered}"
        );
        assert!(
            rendered.contains(&format!("send_window: {QUIC_SEND_WINDOW}")),
            "{rendered}"
        );
    }

    /// One server plus the queue of client sockets its acceptor would receive.
    struct TestServer {
        server: RemoteQuicServer,
        accepted: mpsc::UnboundedReceiver<StdUnixStream>,
    }

    fn test_server_on_free_port() -> TestServer {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (accepted_tx, accepted) = mpsc::unbounded_channel();
        let sink: AcceptedClientSink = Arc::new(move |stream| {
            let _ = accepted_tx.send(stream);
        });
        let server = RemoteQuicServer::start(&config, TEST_SESSION.to_owned(), sink)
            .expect("start QUIC server");
        TestServer { server, accepted }
    }

    fn mint(server: &RemoteQuicServer) -> RemoteBootstrapRecord {
        server
            .bootstrap(&RemoteBootstrapRequest {
                session: TEST_SESSION.to_owned(),
            })
            .expect("bootstrap the endpoint")
    }

    /// Test-only stand-in for the client's own fingerprint verifier: these
    /// tests dial the real endpoint, so they need the real self-signed
    /// certificate to validate.
    #[derive(Debug)]
    struct PinnedTestCert {
        fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedTestCert {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if hash_bytes(end_entity.as_ref()) == self.fingerprint {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("fingerprint mismatch".to_owned()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// One real client, connected and past the hello handshake, with one
    /// data stream open the way a multiplexing bridge attaches a session.
    struct LiveTestClient {
        _endpoint: Endpoint,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    }

    /// Dials the real endpoint and sends `hello`, without assuming the server
    /// accepts it: rejection tests need exactly this much of the handshake.
    /// The device certificate is the only authenticator the endpoint takes, so
    /// every dial presents one.
    async fn dial_with_hello(
        record: &RemoteBootstrapRecord,
        logical_client_id: u8,
    ) -> LiveTestClient {
        let device = shared_test_device();
        crate::remote::device::enroll(&device.certificate_der(), "shared", TEST_SESSION)
            .expect("enroll the shared device for this state root");
        dial_with_hello_and_device(record, logical_client_id, Some(device)).await
    }

    /// Same dial, optionally presenting a device certificate so the server's
    /// client-certificate path is exercised rather than bypassed.
    async fn dial_with_hello_and_device(
        record: &RemoteBootstrapRecord,
        logical_client_id: u8,
        device: Option<&crate::remote::device::DeviceIdentity>,
    ) -> LiveTestClient {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("enable TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTestCert {
                fingerprint: record.certificate_fingerprint,
                provider,
            }));
        let mut tls = match device.and_then(|device| device.client_config().ok()) {
            Some((certificate, key)) => builder
                .with_client_auth_cert(
                    vec![rustls::pki_types::CertificateDer::from(certificate)],
                    key,
                )
                .expect("present device certificate"),
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client crypto");
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));

        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind test client endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(
                SocketAddr::from((Ipv4Addr::LOCALHOST, record.port)),
                "herdr",
            )
            .expect("start QUIC connect")
            .await
            .expect("QUIC handshake");

        let (mut send, recv) = connection.open_bi().await.expect("open client stream");
        let hello = RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: record.server_instance_id,
            logical_client_id: [logical_client_id; REMOTE_QUIC_ID_BYTES],
        };
        write_async_message(&mut send, &hello, MAX_FRAME_SIZE)
            .await
            .expect("send hello");
        LiveTestClient {
            _endpoint: endpoint,
            connection,
            send,
            recv,
        }
    }

    async fn connect_live_test_client(
        record: &RemoteBootstrapRecord,
        logical_client_id: u8,
    ) -> LiveTestClient {
        let mut client = dial_with_hello(record, logical_client_id).await;
        let accepted: RemoteQuicAccepted = read_async_message(&mut client.recv, MAX_HELLO_SIZE)
            .await
            .expect("read accepted");
        assert_eq!(accepted.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        // The hello stream stays as the liveness channel; a session rides on
        // its own stream, the way the multiplexing bridge attaches one.
        let (send, recv) = client.connection.open_bi().await.expect("open data stream");
        LiveTestClient {
            _endpoint: client._endpoint,
            connection: client.connection,
            send,
            recv,
        }
    }

    async fn closed_code(connection: &Connection) -> u64 {
        let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .expect("the peer learns the connection closed");
        match closed {
            quinn::ConnectionError::ApplicationClosed(frame) => u64::from(frame.error_code),
            other => panic!("expected an application close, got {other}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_reports_the_endpoint_and_refuses_a_foreign_session() {
        let TestServer { server, .. } = test_server_on_free_port();
        assert!(server
            .bootstrap(&RemoteBootstrapRequest {
                session: format!("{TEST_SESSION}-wrong"),
            })
            .is_err());

        let first = mint(&server);
        assert_eq!(first.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        assert_eq!(first.port, server.port);
        assert_eq!(first.certificate_fingerprint, server.identity.fingerprint);
        assert!(
            lock(&server.state.clients).is_empty(),
            "bootstrap hands out no authority of its own"
        );
    }

    /// The whole point of the adapter: the acceptor gets an ordinary Unix
    /// client socket, and bytes cross it in both directions untouched.
    #[tokio::test]
    async fn an_accepted_connection_is_an_ordinary_client_socket() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server);
        let mut client = connect_live_test_client(&record, 21).await;

        client
            .send
            .write_all(b"client-to-server")
            .await
            .expect("write uplink");
        let adapted = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("the sink is handed a client socket")
            .expect("sink channel open");
        adapted
            .set_nonblocking(true)
            .expect("adapt the client socket");
        let mut adapted =
            tokio::net::UnixStream::from_std(adapted).expect("register the client socket");

        let mut uplink = [0u8; 16];
        tokio::time::timeout(Duration::from_secs(5), adapted.read_exact(&mut uplink))
            .await
            .expect("uplink arrives")
            .expect("read uplink");
        assert_eq!(&uplink, b"client-to-server");

        adapted
            .write_all(b"server-to-client")
            .await
            .expect("write downlink");
        let mut downlink = [0u8; 16];
        tokio::time::timeout(
            Duration::from_secs(5),
            client.recv.read_exact(&mut downlink),
        )
        .await
        .expect("downlink arrives")
        .expect("read downlink");
        assert_eq!(&downlink, b"server-to-client");

        // The acceptor dropping the client ends only that session's stream;
        // the connection and its credential stay good for the next one.
        drop(adapted);
        let mut scratch = [0u8; 1];
        let stream_end =
            tokio::time::timeout(Duration::from_secs(5), client.recv.read(&mut scratch))
                .await
                .expect("stream settles after the acceptor leaves")
                .expect("read the stream end");
        assert_eq!(stream_end, None, "the data stream must see EOF");
        assert!(client.connection.close_reason().is_none());
    }

    /// Minimal multiplexing proof: after the hello exchange, a second
    /// open_bi on the same connection must reach the server's accept loop
    /// and carry bytes both ways.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_stream_multiplexes_onto_the_connection() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server);
        let mut client = connect_live_test_client(&record, 31).await;
        client.send.write_all(b"ping").await.expect("write ping");
        let adapted = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("the sink is handed a client socket")
            .expect("sink channel open");
        adapted
            .set_nonblocking(true)
            .expect("adapt the client socket");
        let mut adapted =
            tokio::net::UnixStream::from_std(adapted).expect("register the client socket");

        let mut ping = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), adapted.read_exact(&mut ping))
            .await
            .expect("ping arrives")
            .expect("read ping");
        assert_eq!(&ping, b"ping");

        adapted.write_all(b"pong").await.expect("write pong");
        let mut pong = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), client.recv.read_exact(&mut pong))
            .await
            .expect("pong arrives")
            .expect("read pong");
        assert_eq!(&pong, b"pong");
    }

    /// The hello stream doubles as the liveness channel: a health ping written
    /// there must be answered with a pong, or the bridge's PathMonitor sees
    /// silence and tears the connection down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_health_ping_on_the_hello_stream_is_answered_with_a_pong() {
        let TestServer { server, accepted } = test_server_on_free_port();
        drop(accepted);
        let record = mint(&server);
        let mut client = dial_with_hello(&record, 41).await;
        let _accepted: RemoteQuicAccepted = read_async_message(&mut client.recv, MAX_HELLO_SIZE)
            .await
            .expect("read accepted");
        let ping = crate::protocol::ClientMessage::EndpointControl {
            kind: crate::protocol::endpoint::HEALTH_PING_KIND.to_owned(),
            data: String::new(),
        };
        write_async_message(&mut client.send, &ping, MAX_FRAME_SIZE)
            .await
            .expect("write health ping");
        let pong: Result<crate::protocol::ServerMessage, String> =
            read_async_message(&mut client.recv, MAX_FRAME_SIZE).await;
        match pong {
            Ok(crate::protocol::ServerMessage::EndpointControl { kind, .. })
                if kind == crate::protocol::endpoint::HEALTH_PONG_KIND => {}
            other => panic!("expected a health pong, got {other:?}"),
        }
    }

    /// A roamed client re-dials under the same process id; the connection it
    /// is replacing must be told, or two clients would own one session.
    #[tokio::test]
    async fn a_newer_connection_replaces_the_live_one() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server);
        let mut first = connect_live_test_client(&record, 22).await;
        first
            .send
            .write_all(b"x")
            .await
            .expect("wake the accept loop");
        let _first_socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("first client reaches the acceptor")
            .expect("sink channel open");

        let mut second = connect_live_test_client(&record, 22).await;
        second
            .send
            .write_all(b"x")
            .await
            .expect("wake the accept loop");
        assert_eq!(
            closed_code(&first.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_REPLACED)
        );
        let _second_socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("second client reaches the acceptor")
            .expect("sink channel open");

        // The slot names the connection that replaced the first one, and
        // nothing on the way out can take it away.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let key = (
            hash_bytes(&shared_test_device().certificate_der()),
            [22; REMOTE_QUIC_ID_BYTES],
        );
        let clients = lock(&server.state.clients);
        let client = clients.get(&key).expect("client slot survives");
        assert!(client.active_connection.is_some());
        drop(clients);
        drop(second);
    }

    /// A graceful shutdown closes every endpoint, so a remote client learns it
    /// must bootstrap again instead of waiting out `ROAMING_GRACE` on a path
    /// nothing will ever answer.
    #[tokio::test]
    async fn a_shutdown_tells_live_connections_the_server_is_leaving() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server);
        let mut client = connect_live_test_client(&record, 25).await;
        client
            .send
            .write_all(b"x")
            .await
            .expect("wake the accept loop");
        let _socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("client reaches the acceptor")
            .expect("sink channel open");

        server.close_for_shutdown();
        assert_eq!(
            closed_code(&client.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_SHUTDOWN)
        );
    }

    /// Eviction removes the client slot, and with it the connection that owned
    /// it: the table is bounded, so the oldest slot makes room.
    #[tokio::test]
    async fn evicting_a_client_slot_closes_its_connection_as_evicted() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("evict");
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server);
        let mut client = connect_live_test_client(&record, 24).await;
        client
            .send
            .write_all(b"x")
            .await
            .expect("wake the accept loop");
        let _socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("client reaches the acceptor")
            .expect("sink channel open");

        // Distinct logical client ids from one enrolled device fill the table
        // with distinct slots, so the oldest is the one this test holds.
        for index in 0..=u8::try_from(MAX_CLIENTS).expect("slot cap fits a byte") {
            let id = index.saturating_add(1);
            if id == 24 {
                continue;
            }
            let extra = mint(&server);
            let mut extra_client = connect_live_test_client(&extra, id).await;
            extra_client
                .send
                .write_all(b"x")
                .await
                .expect("wake the accept loop");
            let _ = tokio::time::timeout(Duration::from_secs(5), accepted.recv()).await;
            std::mem::forget(extra_client);
        }
        assert_eq!(lock(&server.state.clients).len(), MAX_CLIENTS);
        assert_eq!(
            closed_code(&client.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_EVICTED)
        );
    }

    #[tokio::test]
    async fn handoff_export_and_import_keep_serving_the_same_endpoint() {
        let TestServer { server, .. } = test_server_on_free_port();
        let port = server.port;
        let record = mint(&server);

        let (state, sockets) = server.export_handoff().expect("export handoff");
        assert_eq!(usize::from(state.socket_fd_count), sockets.len());
        assert_eq!(usize::from(state.socket_fd_count), server.endpoints.len());
        assert_eq!(state.port, port);
        assert_eq!(
            state.certificate_fingerprint,
            record.certificate_fingerprint
        );
        assert_eq!(state.server_instance_id, record.server_instance_id);

        server.close_for_handoff();
        drop(server);

        let config = RemoteConfig::default();
        let (accepted_tx, _accepted) = mpsc::unbounded_channel();
        let sink: AcceptedClientSink = Arc::new(move |stream| {
            let _ = accepted_tx.send(stream);
        });
        let resumed =
            RemoteQuicServer::resume(&config, TEST_SESSION.to_owned(), sink, state, sockets)
                .expect("import handoff");
        // Same listening socket, same identity: the client's pinned
        // fingerprint still applies.
        assert_eq!(resumed.port, port);
        assert_eq!(
            resumed
                .sockets
                .first()
                .expect("inherited socket")
                .local_addr()
                .expect("inherited address")
                .port(),
            port
        );
        assert_eq!(resumed.identity.fingerprint, record.certificate_fingerprint);

        // The device allowlist is on disk, so the successor authenticates the
        // same certificate without any capability travelling with the state.
        let identity = shared_test_device();
        crate::remote::device::enroll(&identity.certificate_der(), "shared", TEST_SESSION)
            .expect("enroll the shared device");
        let mut client = dial_with_hello_and_device(&record, 8, Some(identity)).await;
        let accepted: RemoteQuicAccepted = read_async_message(&mut client.recv, MAX_HELLO_SIZE)
            .await
            .expect("the successor accepts the enrolled device");
        assert_eq!(accepted.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        drop(client);

        let next = mint(&resumed);
        assert_eq!(next.server_instance_id, record.server_instance_id);
        assert_eq!(next.certificate_fingerprint, record.certificate_fingerprint);
        assert_eq!(lock(&resumed.state.clients).len(), 1);
    }

    /// Points both XDG roots at a throwaway directory so the identity files a
    /// test writes never reach the developer's real Herdr state.
    struct StateRoot {
        base: std::path::PathBuf,
        config: Option<std::ffi::OsString>,
        state: Option<std::ffi::OsString>,
    }

    impl StateRoot {
        fn new(name: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("herdr-quicid-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            let config = std::env::var_os("XDG_CONFIG_HOME");
            let state = std::env::var_os("XDG_STATE_HOME");
            std::env::set_var("XDG_CONFIG_HOME", base.join("config"));
            std::env::set_var("XDG_STATE_HOME", base.join("state"));
            Self {
                base,
                config,
                state,
            }
        }
    }

    impl Drop for StateRoot {
        fn drop(&mut self) {
            match &self.config {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match &self.state {
                Some(value) => std::env::set_var("XDG_STATE_HOME", value),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn the_server_identity_survives_a_restart() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("identity");

        let first = ServerIdentity::load_or_create().expect("mint identity");
        let second = ServerIdentity::load_or_create().expect("reload identity");
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(first.private_key_der, second.private_key_der);
        assert_eq!(
            first.server_instance_id,
            derive_instance_id(&first.certificate_der),
            "the instance id follows the certificate, not a second file"
        );
    }

    #[test]
    fn the_server_key_is_a_pem_bundle_openssl_can_read() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("identity-pem");
        ServerIdentity::load_or_create().expect("mint identity");

        let path = server_key_path();
        assert_eq!(path.file_name().unwrap(), "server.key");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{text}");
        assert!(text.contains("-----BEGIN CERTIFICATE-----\n"), "{text}");
        let (key, certificate) =
            crate::remote::private_file::pem_read_key_and_certificate(&text).unwrap();
        assert!(!key.is_empty(), "the bundle carries a private key");
        assert!(!certificate.is_empty(), "the bundle carries its certificate");
    }

    #[test]
    fn the_instance_id_is_derived_from_the_certificate() {
        let certificate = vec![1u8, 2, 3, 4];
        assert_eq!(derive_instance_id(&certificate), derive_instance_id(&certificate));
        assert_ne!(
            derive_instance_id(&certificate),
            derive_instance_id(&[9u8, 9])
        );
    }

    #[test]
    fn an_unparseable_server_key_is_an_error_rather_than_a_fresh_identity() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let _root = StateRoot::new("identity-corrupt");
        let path = server_key_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not a pem").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            ServerIdentity::load_or_create().is_err(),
            "re-minting would invalidate every pinned client without saying so"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"not a pem");
    }
}
