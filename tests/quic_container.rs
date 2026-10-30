//! Container-based end-to-end test for the persisted QUIC bridge, using a
//! real OpenSSH server and a real herdr server inside a container. Proves
//! the warm connection through the persisted daemon skips SSH and is
//! faster than the cold one.
//!
//! Requires a working container engine (podman or docker) and is ignored by
//! default: run with `cargo test --test quic_container -- --ignored`.

#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncBuilder;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericBuildableImage};

mod support;

const CONTAINER_QUIC_PORT: u16 = 48_100;

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("herdr-{prefix}-{}-{nonce}", std::process::id()))
}

fn timed_client_attach(
    ssh_target: &str,
    home: &Path,
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
    cmd.arg("--remote");
    cmd.arg(ssh_target);
    cmd.env("HOME", home);
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
    let deadline = Instant::now() + Duration::from_secs(60);
    while received < 2000 {
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

/// Detach a running remote client: SIGINT its child, mirroring the clean
/// Ctrl-C exit that leaves the persisted bridge behind.
fn detach(child: &mut Box<dyn portable_pty::Child + Send + Sync>) {
    let pid = child.process_id().expect("client pid");
    unsafe { libc::kill(pid as i32, libc::SIGINT) };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().expect("child status").is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("client did not exit after SIGINT");
}

#[tokio::test]
#[ignore = "needs a container engine (podman/docker) and a built debug binary"]
async fn persisted_bridge_speeds_up_reattach_over_real_ssh() {
    let base = unique_dir("quic-ctr");
    fs::create_dir_all(&base).expect("create base");

    // A throwaway key pair for the container's root login.
    let keys = base.join("keys");
    fs::create_dir_all(&keys).unwrap();
    let identity = keys.join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "herdr-quic-test", "-f"])
        .arg(&identity)
        .status()
        .expect("ssh-keygen");
    assert!(status.success());
    let pubkey = fs::read_to_string(keys.join("id_ed25519.pub")).unwrap();

    let herdr = std::env::current_dir()
        .expect("cwd")
        .join("target/debug/herdr");
    assert!(herdr.is_file(), "build herdr first: {}", herdr.display());

    let dockerfile = r#"FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd /root/.ssh
COPY authorized_keys /root/.ssh/authorized_keys
RUN chmod 700 /root/.ssh \
    && chmod 600 /root/.ssh/authorized_keys \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
COPY herdr /usr/local/bin/herdr
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
"#
    .to_owned();

    let image = GenericBuildableImage::new("herdr-quic-test", "latest")
        .with_dockerfile_string(dockerfile)
        .with_file(&herdr, "./herdr")
        .with_data(pubkey, "./authorized_keys")
        .build_image()
        .await
        .expect("build the ssh+herdr image");

    let container = image
        .with_exposed_port(22.tcp())
        .with_exposed_port(CONTAINER_QUIC_PORT.udp())
        .with_wait_for(WaitFor::message_on_either_std("Server listening"))
        .start()
        .await
        .expect("start the ssh+herdr container");

    let host = container.get_host().await.expect("container host");
    let ssh_port = container
        .get_host_port_ipv4(22.tcp())
        .await
        .expect("mapped ssh port");
    let _quic_port = container
        .get_host_port_ipv4(CONTAINER_QUIC_PORT.udp())
        .await
        .expect("mapped quic port");

    let ssh_target = format!("root@{host}:{ssh_port}");
    eprintln!("[quic-container] ssh target: {ssh_target}");

    let config_home = base.join("config");
    let state_home = base.join("state");
    fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
    fs::create_dir_all(&state_home).unwrap();
    fs::write(
        config_home.join("herdr-dev/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    // The managed SSH config must use the generated identity; herdr includes
    // ~/.ssh/config, so point HOME's config at the key through a stub.
    let home = base.join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::copy(&identity, home.join(".ssh/id_ed25519")).unwrap();
    fs::write(
        home.join(".ssh/config"),
        format!("Host {host}\n  User root\n  Port {ssh_port}\n  IdentityFile ~/.ssh/id_ed25519\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n"),
    )
    .unwrap();

    // First (cold) attach: real SSH discovery, real bootstrap, real QUIC.
    let (cold, _cold_master, mut cold_child) =
        timed_client_attach(&ssh_target, &home, &config_home, &state_home);
    eprintln!("[quic-container] cold attach: {cold:?}");

    detach(&mut cold_child);

    // Give the launcher a moment to persist before the warm attach.
    thread::sleep(Duration::from_millis(500));
    let (warm, _warm_master, mut warm_child) =
        timed_client_attach(&ssh_target, &home, &config_home, &state_home);
    eprintln!("[quic-container] warm attach: {warm:?}");

    eprintln!("cold: {cold:?}, warm: {warm:?}");
    assert!(
        warm < cold,
        "warm attach ({warm:?}) must be faster than cold ({cold:?})"
    );
    let _ = &mut warm_child;
}
