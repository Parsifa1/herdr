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

/// Connection superseded: a newer generation of the *same* capability was
/// accepted, so another client now owns this session. The credential is still
/// valid, but reconnecting with it would fence the client that just took
/// over, which would fence this one back — an endless replacement loop. The
/// losing client stops instead.
pub(crate) const REMOTE_QUIC_CLOSE_REPLACED: u32 = 0x100;
/// Capability rejected: unknown, expired, or a stale connection generation.
/// The client must bootstrap a fresh credential.
pub(crate) const REMOTE_QUIC_CLOSE_AUTH: u32 = 0x101;
/// Schema version mismatch or an unreadable hello. Bootstrapping again is the
/// only thing that can resolve it, since the peer's build changed.
pub(crate) const REMOTE_QUIC_CLOSE_PROTOCOL: u32 = 0x102;
/// The server process is going away for good. The port, certificate, and
/// instance id all die with it, so the client must bootstrap again.
pub(crate) const REMOTE_QUIC_CLOSE_SHUTDOWN: u32 = 0x103;
/// The server is handing this session to a successor process that inherits the
/// same UDP socket, certificate, instance id, and capability tokens. The
/// client reconnects with the credential it already holds; bootstrapping again
/// would be pointless work during an update.
pub(crate) const REMOTE_QUIC_CLOSE_HANDOFF: u32 = 0x104;
/// A client stream ended on a multiplexed connection. Kept for wire
/// compatibility with single-stream peers; a multiplexing server closes
/// only the stream, so it no longer sends this on the connection.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const REMOTE_QUIC_CLOSE_RESYNC: u32 = 0x105;
/// The capability itself was evicted from the server's token table (overflow),
/// so the credential the client holds no longer resolves to anything. Retrying
/// with it can only fail; the client must bootstrap a new one.
pub(crate) const REMOTE_QUIC_CLOSE_EVICTED: u32 = 0x106;
