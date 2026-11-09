//! Remote-host side of the SSH stdio bridge and the QUIC bootstrap helper.

use std::io;
use std::time::Duration;

/// Set by the client on the bootstrap command line.
#[cfg(unix)]
pub(crate) const DEVICE_LABEL_ENV_VAR: &str = "HERDR_QUIC_DEVICE_LABEL";

pub(crate) fn run_remote_client_bridge(args: &[String]) -> io::Result<()> {
    let idle_timeout = match args {
        [] => false,
        [option]
            if option == "--idle-timeout-v1"
                && crate::platform::REMOTE_BRIDGE_IDLE_TIMEOUT_SUPPORTED =>
        {
            true
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported remote client bridge option",
            ))
        }
    };
    ensure_remote_server_running()?;
    #[cfg(unix)]
    let _ssh_agent = super::ssh_agent::Registration::start();

    let socket_path = crate::server::socket_paths::client_socket_path();
    let stream = crate::ipc::connect_local_stream(&socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr client socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;

    crate::platform::forward_remote_bridge_stdio(stream, idle_timeout)
}

/// `herdr remote-quic-bootstrap [certificate-hex]`: ask the local server for a
/// QUIC credential on behalf of the SSH-authenticated caller and print it as
/// JSON. The caller's SSH session is the authentication; this helper only
/// relays. A certificate argument enrolls that device, which is what lets it
/// reconnect later without SSH.
#[cfg(unix)]
pub(crate) fn run_remote_quic_bootstrap(args: &[String]) -> io::Result<()> {
    let certificate = match args {
        [] => None,
        [certificate] => Some(
            super::device::decode_hex(certificate)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?,
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: remote-quic-bootstrap [certificate-hex]",
            ))
        }
    };
    ensure_remote_server_running()?;
    // The SSH session that ran this helper also names the session the caller
    // may attach to, so the enrollment is scoped to it.
    let session = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    if let Some(certificate) = certificate {
        let name = device_label();
        match super::device::enroll(&certificate, &name, &session) {
            Ok(true) => tracing::info!(device = %name, "remote QUIC device enrolled"),
            Ok(false) => {}
            Err(err) => {
                // Enrollment failing must not cost the caller its credential.
                tracing::warn!(error = %err, "remote QUIC device enrollment failed");
            }
        }
    }

    let socket_path = crate::server::socket_paths::client_socket_path();
    let mut stream = crate::ipc::connect_local_stream(&socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr client socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;
    crate::protocol::write_message(
        &mut stream,
        &crate::protocol::ClientMessage::RemoteBootstrap(crate::protocol::RemoteBootstrapRequest {
            session,
        }),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let response: crate::protocol::ServerMessage =
        crate::protocol::read_message(&mut stream, crate::protocol::MAX_FRAME_SIZE)
            .map_err(|err| io::Error::other(err.to_string()))?;
    let record = match response {
        crate::protocol::ServerMessage::RemoteBootstrap {
            record: Some(record),
            error: None,
        } => record,
        crate::protocol::ServerMessage::RemoteBootstrap {
            error: Some(error), ..
        } => return Err(io::Error::other(error)),
        _ => return Err(io::Error::other("invalid remote QUIC bootstrap response")),
    };
    serde_json::to_writer(io::stdout().lock(), &record)
        .map_err(|err| io::Error::other(format!("failed to encode QUIC bootstrap: {err}")))?;
    println!();
    Ok(())
}

/// The enrolling machine's name. The client supplies it in the environment
/// because this helper runs on the server and cannot see the caller's hostname;
/// falling back to our own keeps a bare invocation working.
#[cfg(unix)]
fn device_label() -> String {
    std::env::var(DEVICE_LABEL_ENV_VAR)
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            crate::platform::hostname()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned())
        })
}

fn ensure_remote_server_running() -> io::Result<()> {
    let socket_path = crate::server::socket_paths::client_socket_path();
    if crate::server::autodetect::is_server_listening()? {
        let status = crate::api::read_runtime_status_at(
            &crate::api::socket_path(),
            Duration::from_millis(500),
        )?
        .ok_or_else(|| io::Error::other("remote server status API is unavailable"))?;
        if status
            .capabilities
            .as_ref()
            .and_then(|capabilities| capabilities.endpoint_protocol_generation)
            == Some(crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION)
        {
            return Ok(());
        }
        return Err(io::Error::other(
            "remote herdr server needs one final update before this bridge can attach; rerun `herdr --remote` from an interactive terminal to approve it",
        ));
    }

    crate::server::autodetect::spawn_server_daemon()?;
    crate::server::autodetect::wait_for_server_socket(&socket_path, Duration::from_secs(5))
}
