//! Timing test proving the persisted bridge daemon makes a saved SSH
//! endpoint connection faster: the first (cold) client pays SSH discovery
//! and bootstrap, the second (warm) client attaches through the daemon and
//! skips every SSH command.

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

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("herdr-{prefix}-{}-{nonce}", std::process::id()))
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
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

fn crate_persisted_path() -> PathBuf {
    let hash = persisted_socket_hash(PROFILE, TARGET, "default");
    std::env::temp_dir().join(format!("herdr-qp-{PROFILE}-{hash}.sock"))
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
    path_env: &str,
    config_home: &Path,
    state_home: &Path,
) -> (Duration, Box<dyn MasterPty + Send>, Box<dyn portable_pty::Child + Send + Sync>) {
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
fn warm_connection_through_the_daemon_is_faster_than_the_cold_one() {
    let base = unique_dir("quic-timing");
    fs::create_dir_all(&base).expect("create base");
    let mut cleanup = TestCleanup { children: Vec::new() };

    let config_home = base.join("config");
    let state_home = base.join("state");
    let remote_config = base.join("remote-config");
    let remote_state = base.join("remote-state");
    let remote_runtime = base.join("remote-runtime");
    let remote_api = remote_runtime.join("herdr.sock");
    let remote_client = remote_runtime.join("herdr-client.sock");
    let home = base.join("home");
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
        "onboarding = false\n",
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    cleanup.children.push(server);
    wait_for_file(&remote_api, Duration::from_secs(10));
    wait_for_file(&remote_client, Duration::from_secs(10));

    let bin = base.join("bin");
    fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_herdr"), bin.join("herdr")).unwrap();
    let ssh_commands = base.join("ssh-commands");
    let quote =
        |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
    fs::write(
        bin.join("ssh"),
        format!(
            "#!/bin/sh\nsleep 0.025\nexport HOME={} XDG_CONFIG_HOME={} XDG_STATE_HOME={} XDG_RUNTIME_DIR={} HERDR_SOCKET_PATH={}\nunset HERDR_CLIENT_SOCKET_PATH HERDR_SESSION HERDR_ENV\ncontrol=; previous=; configuration=; last=\nfor arg do\n  if [ \"$previous\" = -S ]; then control=$arg; fi\n  if [ \"$arg\" = -G ]; then configuration=yes; fi\n  previous=$arg; last=$arg\ndone\nif [ -n \"$configuration\" ]; then printf 'controlpath %s\\n' \"$control\"; exit 0; fi\nprintf '%s\\n' \"$last\" >> {}\nexec /bin/sh -c \"$last\"\n",
            quote(&home),
            quote(&remote_config),
            quote(&remote_state),
            quote(&remote_runtime),
            quote(&remote_api),
            quote(&ssh_commands),
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    let path_env = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());

    let stable_socket = crate_persisted_path();
    // A daemon left over from a previous test run still owns the stable
    // socket's listener; its file can be removed but the process must die or
    // this run's cold connection would silently attach through it.
    let _ = std::process::Command::new("pkill")
        .args(["-f", &format!("remote-bridge-daemon {PROFILE} ")])
        .status();
    let _ = fs::remove_file(&stable_socket);
    thread::sleep(Duration::from_millis(200));

    // Cold: no daemon yet; the client pays SSH discovery and bootstrap.
    let (cold, _cold_master, mut cold_child) =
        timed_client_attach(&path_env, &config_home, &state_home);
    wait_for_file(&stable_socket, Duration::from_secs(15));

    // Warm: the client attaches through the daemon. The freshly spawned
    // daemon still owes its own one-time credential bootstrap, so allow it
    // to settle before timing the steady state.
    let (warm, _warm_master, mut warm_child) =
        timed_client_attach(&path_env, &config_home, &state_home);
    let settle = Instant::now() + Duration::from_secs(5);
    let mut settled_calls = 0usize;
    while Instant::now() < settle {
        settled_calls = fs::read_to_string(&ssh_commands)
            .map(|text| text.lines().count())
            .unwrap_or(0);
        thread::sleep(Duration::from_millis(100));
    }

    // Steady state: the daemon owns a warm credential; this connection must
    // run zero SSH commands.
    let (third, _third_master, mut third_child) =
        timed_client_attach(&path_env, &config_home, &state_home);
    let steady_calls = fs::read_to_string(&ssh_commands)
        .map(|text| text.lines().count())
        .unwrap_or(0);
    assert_eq!(
        settled_calls, steady_calls,
        "the steady-state connection must not run SSH commands"
    );

    eprintln!("cold: {cold:?}, warm: {warm:?}, steady: {third:?}");
    assert!(
        third < cold,
        "steady ({third:?}) must be faster than cold ({cold:?})"
    );

    let _ = &mut cold_child;
    let _ = &mut warm_child;
    let _ = &mut third_child;
    let _ = fs::remove_file(&stable_socket);
}
