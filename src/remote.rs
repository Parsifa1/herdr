mod args;
mod attach;
#[cfg(all(test, unix))]
mod benchmark;
#[cfg(unix)]
pub(crate) mod frame;
mod host;
mod process;
#[cfg(unix)]
mod quic;
#[cfg(unix)]
mod quic_bridge;
#[cfg(unix)]
pub(crate) mod quic_policy;
#[cfg(unix)]
mod quic_saved;
mod restart_policy;
mod saved;
#[cfg(unix)]
mod ssh_agent;

pub(crate) use args::*;
pub(crate) use attach::*;
pub(crate) use host::run_remote_client_bridge;
#[cfg(unix)]
pub(crate) use host::run_remote_quic_bootstrap;
#[cfg(unix)]
pub(crate) use quic_saved::run_remote_bridge_daemon;
pub(crate) use saved::*;

#[cfg(windows)]
pub(crate) fn run_remote_quic_bootstrap(_logical_client_id: Option<&str>) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "remote Windows hosts are not supported yet",
    ))
}

pub(crate) fn run_remote_api_bridge(args: &[String]) -> std::io::Result<()> {
    match args {
        [] => {
            let path = crate::api::socket_path();
            let stream = crate::ipc::connect_local_stream(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to connect to remote Herdr API socket {}: {error}",
                        path.display()
                    ),
                )
            })?;
            crate::platform::forward_remote_bridge_stdio(stream, false)
        }
        [flag] if flag == "--check" => {
            println!("herdr-api-bridge-v1");
            Ok(())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: herdr remote-api-bridge [--check]",
        )),
    }
}

pub(crate) fn print_saved_ssh_error_hint(err: &std::io::Error, target: &str) {
    if is_remote_host_key_error(err) {
        eprintln!(
            "hint: saved machines use strict host-key checking; add the host key to the configured known_hosts file, then retry."
        );
    } else {
        print_remote_error_hint(err, target);
    }
}

pub(crate) fn print_remote_error_hint(err: &std::io::Error, target: &str) {
    if is_remote_auth_error(err) {
        eprintln!(
            "hint: verify SSH access first with `{}`.",
            ssh_check_command(target)
        );
    }
}

fn is_remote_host_key_error(err: &std::io::Error) -> bool {
    let message = err.to_string();
    message.contains("Host key verification failed")
        || message.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
}

fn is_remote_auth_error(err: &std::io::Error) -> bool {
    let message = err.to_string();
    message.contains("Permission denied")
}

fn ssh_check_command(target: &str) -> String {
    format!("ssh {}", shell_quote(target))
}

pub(crate) fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._/:@%+".contains(&b))
    {
        return value.to_string();
    }
    let mut escaped = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_host_key_error_matches_ssh_diagnostics() {
        for message in [
            "Host key verification failed.",
            "REMOTE HOST IDENTIFICATION HAS CHANGED!",
        ] {
            assert!(is_remote_host_key_error(&std::io::Error::other(message)));
        }
        assert!(!is_remote_host_key_error(&std::io::Error::other(
            "server closed connection"
        )));
    }

    #[test]
    fn remote_auth_error_matches_ssh_auth_denied() {
        let err = std::io::Error::other(
            "remote platform detection failed: user@host: Permission denied (publickey).",
        );

        assert!(is_remote_auth_error(&err));
    }

    #[test]
    fn remote_auth_error_matches_keyboard_interactive_denied() {
        let err = std::io::Error::other(
            "remote server status failed: user@host: Permission denied (keyboard-interactive).",
        );

        assert!(is_remote_auth_error(&err));
    }

    #[test]
    fn remote_auth_error_ignores_non_auth_errors() {
        let err = std::io::Error::other("remote platform detection failed: unsupported platform");

        assert!(!is_remote_auth_error(&err));
    }

    #[test]
    fn ssh_check_command_quotes_remote_target() {
        assert_eq!(ssh_check_command("host name"), "ssh 'host name'");
    }
}
