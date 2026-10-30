//! Integration test for the persisted QUIC bridge on the saved SSH endpoint
//! path: the client supervisor's `connect_saved_ssh` must prefer a live
//! bridge daemon, and after the first connection the daemon must keep
//! serving subsequent connections from its stable socket.

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

fn wait_until(timeout: Duration, interval: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if probe() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(interval);
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
type SpawnClientPtyReturn = (
    Box<dyn MasterPty + Send>,
    Box<dyn portable_pty::Child + Send + Sync>,
    mpsc::Receiver<Vec<u8>>,
);
fn spawn_client_pty(
    args: &[&str],
    path_env: &str,
    config_home: &Path,
    state_home: &Path,
) -> SpawnClientPtyReturn {
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
    for arg in args {
        cmd.arg(arg);
    }
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

    let (tx, rx) = mpsc::channel();
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

    (pair.master, child, rx)
}

fn collected(rx: &mpsc::Receiver<Vec<u8>>) -> String {
    let mut out = String::new();
    while let Ok(chunk) = rx.try_recv() {
        out.push_str(&String::from_utf8_lossy(&chunk));
    }
    out
}

#[test]
fn saved_endpoint_connections_reuse_the_persisted_bridge_daemon() {
    let base = unique_dir("quic-saved");
    fs::create_dir_all(&base).expect("create base");
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

    // The saved endpoint catalog: one enabled SSH machine.
    fs::write(
        state_home.join("herdr-dev").join("client").join("endpoints.json"),
        serde_json::json!({
            "version": 1, "selected_profile": PROFILE,
            "ssh": [{"id": PROFILE, "label": "Test machine", "target": TARGET, "session": "default", "enabled": true}],
        })
        .to_string(),
    )
    .unwrap();

    // The "remote" machine: a real local herdr server in its own config root.
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

    // The fake ssh runs every remote command against that server.
    let bin = base.join("bin");
    fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_herdr"), bin.join("herdr")).unwrap();
    let ssh_commands = base.join("ssh-commands");
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
    fs::write(
        bin.join("ssh"),
        format!(
            "#!/bin/sh\nexport HOME={} XDG_CONFIG_HOME={} XDG_STATE_HOME={} XDG_RUNTIME_DIR={} HERDR_SOCKET_PATH={}\nunset HERDR_CLIENT_SOCKET_PATH HERDR_SESSION HERDR_ENV\ncontrol=; previous=; configuration=; last=\nfor arg do\n  if [ \"$previous\" = -S ]; then control=$arg; fi\n  if [ \"$arg\" = -G ]; then configuration=yes; fi\n  previous=$arg; last=$arg\ndone\nif [ -n \"$configuration\" ]; then printf 'controlpath %s\\n' \"$control\"; exit 0; fi\nprintf '%s\\n' \"$last\" >> {}\nexec /bin/sh -c \"$last\"\n",
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
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let stable_socket = crate_persisted_path();
    let _ = fs::remove_file(&stable_socket);

    // First client connection: the supervisor builds the bridge through the
    // fake ssh; connect_saved_ssh spawns the persisted daemon because no
    // socket is live yet.
    let (_master, mut child, rx) =
        spawn_client_pty(&["client"], &path_env, &config_home, &state_home);
    let mut output = String::new();
    assert!(
        wait_until(Duration::from_secs(30), Duration::from_millis(100), || {
            output.push_str(&collected(&rx));
            output.len() > 2000
        }),
        "first client never rendered; output: {output}"
    );

    // The daemon must exist and own the stable socket.
    assert!(
        wait_until(Duration::from_secs(15), Duration::from_millis(50), || {
            stable_socket.exists()
        }),
        "persisted bridge daemon never bound the stable socket"
    );

    // A second connection must go through the daemon: no new SSH commands
    // after the first connection settled.
    let settle_deadline = Instant::now() + Duration::from_secs(5);
    let mut calls_after_first = 0usize;
    while Instant::now() < settle_deadline {
        calls_after_first = fs::read_to_string(&ssh_commands)
            .map(|text| text.lines().count())
            .unwrap_or(0);
        thread::sleep(Duration::from_millis(100));
    }
    let before_second = calls_after_first;

    let (_master2, mut child2, rx2) =
        spawn_client_pty(&["client"], &path_env, &config_home, &state_home);
    let mut output2 = String::new();
    assert!(
        wait_until(Duration::from_secs(30), Duration::from_millis(100), || {
            output2.push_str(&collected(&rx2));
            output2.len() > 2000
        }),
        "second client never rendered; output: {output2}"
    );

    let after_second = fs::read_to_string(&ssh_commands)
        .map(|text| text.lines().count())
        .unwrap_or(0);
    assert_eq!(
        before_second, after_second,
        "second connection must not run SSH commands through the daemon path"
    );

    let _ = &mut child;
    let _ = &mut child2;
    let _ = fs::remove_file(&stable_socket);
}

/// Same derivation as quic_saved.rs persisted_bridge_path: readable form via
/// platform::remote_bridge_endpoint_path with profile and hash.
fn crate_persisted_path() -> PathBuf {
    let hash = persisted_socket_hash(PROFILE, TARGET, "default");
    let readable = format!("herdr-qp-{PROFILE}-{hash}.sock");
    std::env::temp_dir().join(readable)
}
