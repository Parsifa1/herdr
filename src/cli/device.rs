use std::io::IsTerminal as _;

use serde::Serialize;

use crate::remote::device;

const HELP: &str = "Usage:
  herdr device list [--json]
  herdr device revoke <name>

Devices enroll themselves once, through the SSH bootstrap that starts a QUIC
connection: the first `herdr --remote <target>` from a machine adds it here,
scoped to the session that bootstrap ran under. An enrolled device keeps
connecting without SSH, for those sessions, until it is revoked.
Revoking takes effect on that device's next connection and cannot be undone
by re-enrolling the same key.";

#[derive(Serialize)]
struct DeviceRow<'a> {
    name: &'a str,
    certificate_sha256: &'a str,
    enrolled_unix_seconds: u64,
    sessions: &'a [String],
    revoked: bool,
}

pub(super) fn run_device_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("list") => list(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn list(args: &[String]) -> std::io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr device list [--json]");
            return Ok(2);
        }
    };
    let devices = device::list()?;
    if json {
        let rows = devices
            .devices
            .iter()
            .map(|entry| DeviceRow {
                name: &entry.name,
                certificate_sha256: &entry.certificate_sha256,
                enrolled_unix_seconds: entry.enrolled_unix_seconds,
                sessions: &entry.sessions,
                revoked: entry.revoked,
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(0);
    }
    if devices.devices.is_empty() {
        println!("no enrolled devices");
        return Ok(0);
    }
    for entry in &devices.devices {
        let state = if entry.revoked { "revoked" } else { "enabled" };
        // Entries written before names were sanitized can still carry control
        // characters, and this output goes straight to a terminal.
        let name = device::sanitize_device_name(&entry.name);
        let sessions = entry.sessions.join(",");
        println!(
            "{} {} {} sessions={}",
            name, state, entry.certificate_sha256, sessions
        );
    }
    Ok(0)
}

fn revoke(args: &[String]) -> std::io::Result<i32> {
    let [name] = args else {
        eprintln!("usage: herdr device revoke <name>");
        return Ok(2);
    };
    if !device::revoke(name)? {
        eprintln!("no enabled device named {name}");
        return Ok(1);
    }
    if std::io::stdout().is_terminal() {
        println!("revoked {name}");
    }
    Ok(0)
}
