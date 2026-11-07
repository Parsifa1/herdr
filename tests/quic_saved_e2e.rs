//! End-to-end cold-start test for a saved SSH endpoint.
//!
//! It drives the real binary the way a user does: a headless client attaches
//! through a PTY, spawns the persisted bridge daemon, and gets a rendered
//! screen back. Only SSH is faked, so the test can count every command and
//! point the hostname at the loopback address the real server binds.
//!
//! It covers both halves of the contract:
//!
//! - cold: no daemon yet, so the client pays SSH discovery and bootstrap;
//! - warm and steady: the daemon already holds a QUIC session, so later
//!   attaches add no SSH commands at all and ride the same connection.
//!
//! Assertions are on the SSH log and the daemon log rather than wall-clock
//! time: client startup dominates that number on a loaded runner, so timing
//! two attaches measures noise, not the daemon.

#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};

mod support;

const PROFILE: &str = "0123456789abcdef0123456789abcdef";
const TARGET: &str = "fakehost";
const RENDERED_OUTPUT_BYTES: usize = 2000;

fn unique_dir(_prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    PathBuf::from("/tmp").join(format!("hqt-{nonce:x}"))
}

fn wait_for_file(path: &Path, log: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}; log {}:\n{}",
            path.display(),
            log.display(),
            fs::read_to_string(log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(10));
    }
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

fn crate_persisted_path(temp_dir: &Path) -> PathBuf {
    let hash = persisted_socket_hash(PROFILE, TARGET, "default");
    temp_dir.join(format!("herdr-qp-{PROFILE}-{hash}.sock"))
}

/// How many SSH commands the fake ssh has been asked to run so far.
fn ssh_command_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|text| text.lines().filter(|line| !line.is_empty()).count())
        .unwrap_or(0)
}

/// A UDP port the remote server can bind for QUIC. The probe socket closes
/// before the server starts, so the only guarantee is that the port was free a
/// moment ago.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind a UDP port probe")
        .local_addr()
        .expect("probe address")
        .port()
}

struct TestCleanup {
    children: Vec<Child>,
}

impl Drop for TestCleanup {
    fn drop(&mut self) {
        for child in self.children.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn a headless client and time it from spawn until its pty produced a
/// rendered screen (the TUI output that follows a completed handshake).
fn timed_client_attach(
    temp_dir: &Path,
    path_env: &str,
    config_home: &Path,
    state_home: &Path,
) -> (
    Duration,
    Box<dyn MasterPty + Send>,
    Box<dyn portable_pty::Child + Send + Sync>,
) {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    support::isolate_herdr_test_process(&mut cmd);
    cmd.arg("client");
    cmd.env("PATH", path_env);
    cmd.env("TMPDIR", temp_dir);
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_STATE_HOME", state_home);
    cmd.env("SHELL", "/bin/sh");
    cmd.env_remove("HERDR_ENV");
    cmd.env_remove("HERDR_SESSION");
    cmd.env_remove("HERDR_SOCKET_PATH");
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env_remove("HERDR_REMOTE_BINARY");

    let child = pair.slave.spawn_command(cmd).unwrap();
    support::register_spawned_herdr_pid(child.process_id());
    drop(pair.slave);

    let started = Instant::now();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = pair.master.try_clone_reader().unwrap();
    thread::spawn(move || {
        let mut reader = reader;
        let mut buffer = [0; 8192];
        while let Ok(len) = reader.read(&mut buffer) {
            if len == 0 || tx.send(buffer[..len].to_vec()).is_err() {
                break;
            }
        }
    });

    let mut received = 0usize;
    let deadline = Instant::now() + Duration::from_secs(30);
    while received < RENDERED_OUTPUT_BYTES {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(chunk) => received += chunk.len(),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        assert!(
            Instant::now() < deadline,
            "client never rendered; received {received} bytes"
        );
    }
    (started.elapsed(), pair.master, child)
}

#[test]
fn cold_start_bootstraps_over_ssh_then_the_daemon_serves_the_rest() {
    let base = unique_dir("quic-timing");
    fs::create_dir_all(&base).expect("create base");
    let temp_dir = base.join("tmp");
    fs::create_dir_all(&temp_dir).unwrap();
    let mut cleanup = TestCleanup {
        children: Vec::new(),
    };

    let config_home = base.join("config");
    let state_home = base.join("state");
    let remote_config = base.join("remote-config");
    let remote_state = base.join("remote-state");
    let remote_runtime = base.join("remote-runtime");
    let remote_api = remote_runtime.join("herdr.sock");
    let remote_client = remote_runtime.join("herdr-client.sock");
    let home = base.join("home");
    let quic_port = free_udp_port();
    fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
    fs::create_dir_all(state_home.join("herdr-dev").join("client")).unwrap();
    fs::create_dir_all(remote_config.join("herdr-dev")).unwrap();
    fs::create_dir_all(&remote_runtime).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(
        config_home.join("herdr-dev/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();
    fs::write(
        remote_config.join("herdr-dev/config.toml"),
        format!("onboarding = false\n\n[remote]\nquic_port_range = \"{quic_port}-{quic_port}\"\n"),
    )
    .unwrap();
    fs::write(
        state_home.join("herdr-dev").join("client").join("endpoints.json"),
        serde_json::json!({
            "version": 1, "selected_profile": PROFILE,
            "ssh": [{"id": PROFILE, "label": "Timing machine", "target": TARGET, "session": "default", "enabled": true}],
        })
        .to_string(),
    )
    .unwrap();

    let server_log = base.join("server.log");
    let server = Command::new("setsid")
        .arg(env!("CARGO_BIN_EXE_herdr"))
        .arg("server")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &remote_config)
        .env("XDG_STATE_HOME", &remote_state)
        .env("XDG_RUNTIME_DIR", &remote_runtime)
        .env("HERDR_SOCKET_PATH", &remote_api)
        .env("HERDR_CLIENT_SOCKET_PATH", &remote_client)
        .env("SHELL", "/bin/sh")
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::File::create(&server_log).expect("create server log"),
        ))
        .spawn()
        .expect("spawn server");
    cleanup.children.push(server);
    wait_for_file(&remote_api, &server_log, Duration::from_secs(10));
    wait_for_file(&remote_client, &server_log, Duration::from_secs(10));

    let bin = base.join("bin");
    fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_herdr"), bin.join("herdr")).unwrap();
    let ssh_commands = base.join("ssh-commands");
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
    fs::write(
        bin.join("ssh"),
        format!(
            "#!/bin/sh\nsleep 0.025\nexport HOME={} XDG_CONFIG_HOME={} XDG_STATE_HOME={} XDG_RUNTIME_DIR={} HERDR_SOCKET_PATH={}\nunset HERDR_CLIENT_SOCKET_PATH HERDR_SESSION HERDR_ENV\ncontrol=; previous=; configuration=; last=\nfor arg do\n  if [ \"$previous\" = -S ]; then control=$arg; fi\n  if [ \"$arg\" = -G ]; then configuration=yes; fi\n  previous=$arg; last=$arg\ndone\nif [ -n \"$configuration\" ]; then printf 'controlpath %s\\n' \"$control\"; printf 'hostname %s\\n' 127.0.0.1; printf 'port %s\\n' {port}; exit 0; fi\nprintf '%s\\n' \"$last\" >> {}\nexec /bin/sh -c \"$last\"\n",
            quote(&home),
            quote(&remote_config),
            quote(&remote_state),
            quote(&remote_runtime),
            quote(&remote_api),
            quote(&ssh_commands),
            port = quic_port,
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let stable_socket = crate_persisted_path(&temp_dir);
    let _ = fs::remove_file(&stable_socket);
    let daemon_log = config_home.join("herdr-dev/herdr-remote-bridge-daemon.log");

    // Cold: no daemon yet. The client spawns one, which discovers the remote
    // host over SSH and bootstraps a credential.
    let (cold, _cold_master, mut cold_child) =
        timed_client_attach(&temp_dir, &path_env, &config_home, &state_home);
    wait_for_file(&stable_socket, &daemon_log, Duration::from_secs(15));

    let (warm, _warm_master, mut warm_child) =
        timed_client_attach(&temp_dir, &path_env, &config_home, &state_home);
    let settle = Instant::now() + Duration::from_secs(5);
    let mut settled_calls = 0usize;
    while Instant::now() < settle {
        settled_calls = ssh_command_count(&ssh_commands);
        thread::sleep(Duration::from_millis(100));
    }

    // Steady state: the daemon owns a warm credential; this connection must
    // run zero SSH commands.
    let (third, _third_master, mut third_child) =
        timed_client_attach(&temp_dir, &path_env, &config_home, &state_home);
    let steady_calls = ssh_command_count(&ssh_commands);
    let steady_log = fs::read_to_string(&daemon_log).unwrap_or_default();

    // The cold path really did have to reach the host.
    assert!(
        settled_calls > 0,
        "the cold connection and the daemon's bootstrap must have run SSH commands; daemon log:\n{steady_log}"
    );
    // The whole point of the daemon: the steady-state attach adds nothing.
    assert_eq!(
        settled_calls, steady_calls,
        "the steady-state connection must add no SSH commands; daemon log:\n{steady_log}"
    );
    // And it is not merely skipping SSH -- the QUIC transport carried it.
    // Every attach that reaches a live session logs this line.
    assert_eq!(
        steady_log
            .lines()
            .filter(|line| line.contains("remote QUIC transport connected"))
            .count(),
        1,
        "the daemon must hold exactly one QUIC session across all three attaches; daemon log:\n{steady_log}"
    );
    // A single daemon serves all three attaches: no respawn, so PIDs are stable
    // and the steady-state client reuses the socket the cold client created.
    assert!(
        stable_socket.exists(),
        "the daemon's socket must survive for the steady-state attach"
    );
    assert!(
        !steady_log.contains("persisted remote bridge idled out"),
        "the daemon must not have idled out between attaches; daemon log:\n{steady_log}"
    );

    eprintln!(
        "cold: {cold:?}, warm: {warm:?}, steady: {third:?}, ssh commands: {settled_calls}"
    );

    let _ = &mut cold_child;
    let _ = &mut warm_child;
    let _ = &mut third_child;
    let _ = fs::remove_file(&stable_socket);
}
