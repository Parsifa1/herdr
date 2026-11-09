//! QUIC application close codes shared by the remote client and the remote
//! server.
//!
//! These are on the wire: they are the server's only way to tell the client
//! whether to reconnect with the credential it already holds or to bootstrap a
//! new one, so they may only be added to, never renumbered. They live outside
//! either endpoint so neither has to depend on the other's implementation
//! module.

use std::time::Duration;

/// The RTT guessed before the first sample. quinn's 333 ms default schedules
/// the first probe timeout about a second out, so a path that loses an
/// initial packet spends most of the bridge's two-second dial budget waiting
/// out one backoff. 100 ms leaves room for several attempts in the same
/// budget, which is what turns "the network blipped during the handshake"
/// from a failed dial into a slow one.
pub(crate) const REMOTE_QUIC_INITIAL_RTT: Duration = Duration::from_millis(100);

/// Bytes in flight before any acknowledgment arrives: ten 1200-byte packets.
/// quinn's BBR default is 200 packets, and BBR paces from that window, so a
/// first flight on a shared or cellular path offers roughly sixteen times the
/// link rate and builds a queue that only loss can drain. Cubic and ssh's TCP
/// both start near ten packets.
pub(crate) const REMOTE_QUIC_INITIAL_CONGESTION_WINDOW: u64 = 12_000;

/// Connection superseded: a newer generation of the *same* client slot was
/// accepted, so another connection now owns this session. The device
/// certificate is still valid, but reconnecting would fence the connection
/// that just took over, which would fence this one back — an endless
/// replacement loop. The losing client stops instead.
pub(crate) const REMOTE_QUIC_CLOSE_REPLACED: u32 = 0x100;
/// Authentication rejected: the device certificate is unknown, revoked, or not
/// enrolled for this session, or the connection generation is stale. The
/// client must bootstrap again over SSH.
pub(crate) const REMOTE_QUIC_CLOSE_AUTH: u32 = 0x101;
/// Schema version mismatch or an unreadable hello. Bootstrapping again is the
/// only thing that can resolve it, since the peer's build changed.
pub(crate) const REMOTE_QUIC_CLOSE_PROTOCOL: u32 = 0x102;
/// The server process is going away for good. The port, certificate, and
/// instance id all die with it, so the client must bootstrap again.
pub(crate) const REMOTE_QUIC_CLOSE_SHUTDOWN: u32 = 0x103;
/// The server is handing this session to a successor process that inherits the
/// same UDP socket, certificate, and instance id. The client reconnects with
/// the device certificate it already enrolled; bootstrapping again would be
/// pointless work during an update.
pub(crate) const REMOTE_QUIC_CLOSE_HANDOFF: u32 = 0x104;
/// A client stream ended on a multiplexed connection. Kept for wire
/// compatibility with single-stream peers; a multiplexing server closes
/// only the stream, so it no longer sends this on the connection.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const REMOTE_QUIC_CLOSE_RESYNC: u32 = 0x105;
/// The client slot was evicted from the server's bounded table, so the
/// connection that owned it is over. Reconnecting is fine: the device
/// certificate is untouched, and the next dial takes a fresh slot.
pub(crate) const REMOTE_QUIC_CLOSE_EVICTED: u32 = 0x106;
