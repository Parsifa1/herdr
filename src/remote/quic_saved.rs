//! Persistent QUIC bridge for saved SSH endpoints, mirroring the
//! ControlMaster reuse flow in `saved.rs`: probe the stable socket, connect
//! through a live daemon, or spawn one and wait for it.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::attach::find_installed_remote_herdr;
use super::quic_bridge::{QuicBridge, QuicBridgeConfig};
use super::saved::validated_saved_ssh;

const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn persisted_bridge_path(profile_id: &str, target: &str, session: &str) -> PathBuf {
    let hash = persisted_socket_hash(profile_id, target, session);
    let readable = format!("herdr-qp-{profile_id}-{hash}.sock");
    let short = format!("herdr-q-{}-{hash}.sock", &profile_id[..16]);
    crate::platform::remote_bridge_endpoint_path(&readable, &short)
}

fn persisted_socket_hash(profile_id: &str, target: &str, session: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    profile_id.hash(&mut hasher);
    target.hash(&mut hasher);
    session.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// A stream through a live persisted bridge daemon.
pub(crate) struct PersistedQuicStream {
    pub(crate) stream: crate::ipc::LocalStream,
}

/// Connect a saved SSH endpoint through the persisted QUIC bridge, spawning
/// the daemon when no live one exists. Mirrors `connect_saved_ssh`: validate,
/// probe the shared transport, then hand the caller a connected stream.
pub(crate) fn connect_persisted_quic(
    profile_id: &str,
    target: &str,
    session: &str,
    cancelled: Arc<AtomicBool>,
) -> io::Result<PersistedQuicStream> {
    validate_profile_path_id(profile_id)?;
    crate::session::validate_name(session)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let path = persisted_bridge_path(profile_id, target, session);
    if crate::ipc::connect_local_stream(&path).is_ok() {
        return connect_stream(&path, &cancelled);
    }

    spawn_persisted_daemon(profile_id, target, session)?;
    let deadline = Instant::now() + DAEMON_STARTUP_TIMEOUT;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(super::process::cancelled());
        }
        if crate::ipc::connect_local_stream(&path).is_ok() {
            return connect_stream(&path, &cancelled);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "persisted remote bridge daemon did not become ready",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn connect_stream(
    path: &Path,
    cancelled: &AtomicBool,
) -> io::Result<PersistedQuicStream> {
    crate::ipc::connect_local_stream_cancellable(
        path,
        cancelled,
        Instant::now() + Duration::from_secs(5),
    )
    .map(|stream| PersistedQuicStream { stream })
}

fn validate_profile_path_id(profile_id: &str) -> io::Result<()> {
    if profile_id.len() == 32
        && profile_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SSH endpoint profile id",
        ))
    }
}

fn spawn_persisted_daemon(profile_id: &str, target: &str, session: &str) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("remote-bridge-daemon")
        .arg(profile_id)
        .arg(target)
        .arg(session)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::platform::detach_server_daemon_command(&mut command);
    command.spawn().map(|_| ()).map_err(|err| {
        io::Error::new(err.kind(), format!("failed to spawn remote bridge daemon: {err}"))
    })
}

/// Entry point of `herdr remote-bridge-daemon <profile> <target> <session>`:
/// bind the QUIC bridge at the stable path and idle out when unused.
pub(crate) fn run_remote_bridge_daemon(args: &[String]) -> io::Result<()> {
    let [profile_id, target, session] = args else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: remote-bridge-daemon <profile-id> <target> <session>",
        ));
    };
    validate_profile_path_id(profile_id)?;
    crate::session::validate_name(session)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    crate::logging::init_file_logging("herdr-remote-bridge-daemon.log");

    let ssh = validated_saved_ssh(profile_id, target, session)?;
    let remote_herdr = find_installed_remote_herdr(&ssh)?;
    let path = persisted_bridge_path(profile_id, target, session);

    let bridge = QuicBridge::start(
        QuicBridgeConfig {
            target: target.to_owned(),
            remote_herdr,
            session: session.to_owned(),
            ssh_options: ssh.options().cloned(),
            noninteractive: true,
            transport: crate::config::Config::load().config.remote.transport,
            logical_client_id: QuicBridgeConfig::process_logical_client_id(),
        },
        path,
    )?;
    bridge.persist_when_idle();

    // Park the main thread; the bridge's accept thread exits the process on
    // idle and Drop's socket cleanup follows it.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
