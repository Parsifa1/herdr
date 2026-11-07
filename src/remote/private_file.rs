//! Private on-disk state for the remote QUIC transport.
//!
//! Everything here holds or pins a secret, so the same three rules apply to
//! all of it: a file is 0600 from the byte it is created rather than after a
//! chmod, a file that others can write is refused rather than trusted, and a
//! read-modify-write cycle holds an exclusive lock so two daemons cannot lose
//! each other's entries.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;

/// Refuses a path that is not a regular file owned by this user with no group
/// or other permissions. A missing path is fine: the caller creates it.
///
/// A secret others can read is compromised, so every caller of [`read`] gets
/// this check for free rather than having to remember it.
pub(crate) fn check_private(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        check_private_dir(parent)?;
    }
    // symlink_metadata, not metadata: a symlink to a private file is still a
    // path somebody else chose.
    let metadata = match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
        Ok(metadata) => metadata,
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let uid = unsafe { libc::getuid() };
    if metadata.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not {uid}",
                path.display(),
                metadata.uid()
            ),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by others (mode {mode:04o}); chmod 600 it",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// A world-writable directory can rename or replace the file inside it, so a
/// 0600 file is only private if the directory holding it is private too.
fn check_private_dir(path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symlink, not a directory", path.display()),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is writable by others (mode {mode:04o}); chmod go-w it",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Reads a private file after checking it. `None` means the file is absent,
/// which callers treat as "nothing stored yet" rather than as an error.
pub(crate) fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    check_private(path)?;
    match std::fs::read(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
        Ok(bytes) => Ok(Some(bytes)),
    }
}

/// Replaces `path` atomically. The temporary file is created 0600 and is never
/// linked under the final name, so a reader sees either the previous contents
/// or the new ones, and never a world-readable window in between.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (mut file, temporary) = create_temp(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })
}

/// Publishes `bytes` at `path` only if nothing is there yet. Returns false when
/// another process got there first, which is how a key is created exactly once
/// even when several processes start together: the loser reads the winner's
/// key instead of replacing it with one of its own.
pub(crate) fn create_exclusive(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let (mut file, temporary) = create_temp(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let published = written.and_then(|()| match std::fs::hard_link(&temporary, path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    });
    let _ = std::fs::remove_file(&temporary);
    published
}

fn create_temp(path: &Path) -> io::Result<(File, PathBuf)> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A random suffix, not the pid: two daemons in different namespaces can
    // share a pid, and a collision would truncate the other's temporary file.
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|err| io::Error::other(err.to_string()))?;
    let temporary = path.with_file_name(format!(
        ".{name}.tmp.{}",
        nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    Ok((file, temporary))
}

/// An exclusive advisory lock, released when dropped.
///
/// Sibling to the file it guards, so the lock never outlives the data it
/// protects: the lock file is created 0600 and left in place, because removing
/// it would race a process that is about to lock it.
#[derive(Debug)]
pub(crate) struct Lock(#[allow(dead_code)] File);

pub(crate) fn lock(path: &Path) -> io::Result<Lock> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    let lock_path = path.with_file_name(name);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    file.lock()?;
    Ok(Lock(file))
}

pub(crate) fn pem_encode(blocks: &[(&str, &[u8])]) -> String {
    let mut out = String::new();
    for (kind, der) in blocks {
        out.push_str("-----BEGIN ");
        out.push_str(kind);
        out.push_str("-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        for line in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END ");
        out.push_str(kind);
        out.push_str("-----\n");
    }
    out
}

/// The first private key and the first certificate in a PEM bundle, which is
/// how the key file and the certificate it minted share one path.
pub(crate) fn pem_read_key_and_certificate(text: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let blocks = pem_decode(text)?;
    let find = |kind: &str| {
        blocks
            .iter()
            .find(|(name, _)| name == kind)
            .map(|(_, der)| der.clone())
            .ok_or_else(|| invalid(format!("PEM bundle has no {kind} block")))
    };
    Ok((find("PRIVATE KEY")?, find("CERTIFICATE")?))
}

fn pem_decode(text: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut blocks = Vec::new();
    let mut open: Option<(String, String)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(kind) = armor(line, "-----BEGIN ", "-----") {
            if open.is_some() {
                return Err(invalid("PEM blocks are never nested".to_owned()));
            }
            open = Some((kind.to_owned(), String::new()));
        } else if let Some(kind) = armor(line, "-----END ", "-----") {
            let Some((begun, body)) = open.take() else {
                return Err(invalid("PEM END without a BEGIN".to_owned()));
            };
            if begun != kind {
                return Err(invalid(format!("PEM block {begun:?} ends as {kind:?}")));
            }
            let der = base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|err| invalid(format!("PEM body is not base64: {err}")))?;
            blocks.push((begun, der));
        } else if let Some((_, body)) = open.as_mut() {
            body.push_str(line);
        } else if !line.is_empty() {
            return Err(invalid("text outside a PEM block".to_owned()));
        }
    }
    if open.is_some() {
        return Err(invalid("PEM block is never closed".to_owned()));
    }
    Ok(blocks)
}

fn armor<'a>(line: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)?.strip_suffix(suffix)
}

fn invalid(detail: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "herdr-private-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch root");
            Scratch(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_written_file_is_private_from_the_start_and_reads_back() {
        let scratch = Scratch::new("write");
        let path = scratch.join("secret");
        assert_eq!(read(&path).unwrap(), None, "a missing file is not an error");
        write_atomic(&path, b"one").unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        write_atomic(&path, b"two").unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"two"[..]));
        let leftovers = std::fs::read_dir(&scratch.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0, "a replace must not leave a temporary file");
    }

    #[test]
    fn a_file_others_can_reach_is_refused_rather_than_trusted() {
        let scratch = Scratch::new("modes");
        let path = scratch.join("secret");
        write_atomic(&path, b"x").unwrap();
        for mode in [0o644, 0o640, 0o660, 0o604] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read(&path).expect_err("a reachable secret is not private");
            assert!(err.to_string().contains("chmod 600"), "{mode:04o}: {err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn a_symlink_is_never_the_private_file() {
        let scratch = Scratch::new("symlink");
        let real = scratch.join("real");
        let link = scratch.join("link");
        write_atomic(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read(&link).is_err(), "a symlink can point anywhere");
    }

    #[test]
    fn a_directory_others_can_write_is_refused() {
        let scratch = Scratch::new("shared-dir");
        let dir = scratch.join("nested");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        write_atomic(&path, b"x").unwrap();
        for mode in [0o777, 0o757, 0o775] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read(&path).expect_err("a replaceable file is not private");
            assert!(err.to_string().contains("chmod go-w"), "{mode:04o}: {err}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn concurrent_writers_keep_every_entry() {
        let scratch = Scratch::new("concurrent");
        let path = scratch.join("table");
        // Each writer does exactly what a bridge daemon does: lock, re-read,
        // append its own row, write. A snapshot kept outside the lock would
        // lose rows here.
        let writers = 8;
        let appends = 5;
        std::thread::scope(|scope| {
            for writer in 0..writers {
                let path = path.clone();
                scope.spawn(move || {
                    for append in 0..appends {
                        let _lock = lock(&path).unwrap();
                        let mut rows = read(&path)
                            .unwrap()
                            .map(|bytes| String::from_utf8(bytes).unwrap())
                            .unwrap_or_default();
                        rows.push_str(&format!("{writer}-{append}\n"));
                        write_atomic(&path, rows.as_bytes()).unwrap();
                    }
                });
            }
        });
        let rows = read(&path).unwrap().unwrap();
        let rows = String::from_utf8(rows).unwrap();
        assert_eq!(
            rows.lines().count(),
            writers * appends,
            "a lost update means the lock was released too early:\n{rows}"
        );
    }

    #[test]
    fn exclusive_creation_lets_exactly_one_writer_win() {
        let scratch = Scratch::new("exclusive");
        let path = scratch.join("key");
        assert!(create_exclusive(&path, b"winner").unwrap());
        assert!(!create_exclusive(&path, b"loser").unwrap(), "the second writer must lose");
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"winner"[..]));
    }

    #[test]
    fn the_lock_is_exclusive_across_threads() {
        let scratch = Scratch::new("lock");
        let path = scratch.join("state");
        let held = lock(&path).unwrap();
        // The same process is excluded too: a second descriptor is a second
        // holder as far as flock is concerned.
        let contender = std::thread::spawn({
            let path = path.clone();
            move || {
                let second = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path.with_file_name("state.lock"))
                    .unwrap();
                second.try_lock().map(|()| ())
            }
        });
        assert!(contender.join().unwrap().is_err(), "the lock is already held");
        drop(held);
        let reopened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.with_file_name("state.lock"))
            .unwrap();
        assert!(reopened.try_lock().is_ok(), "dropping the guard releases the lock");
    }

    #[test]
    fn a_pem_bundle_round_trips_both_blocks() {
        let encoded = pem_encode(&[("PRIVATE KEY", b"key-bytes"), ("CERTIFICATE", b"cert-bytes")]);
        assert!(encoded.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let (key, certificate) = pem_read_key_and_certificate(&encoded).unwrap();
        assert_eq!(key, b"key-bytes");
        assert_eq!(certificate, b"cert-bytes");
        assert!(
            pem_read_key_and_certificate("not a pem").is_err(),
            "garbage is not a key"
        );
        assert!(
            pem_read_key_and_certificate(&pem_encode(&[("CERTIFICATE", b"c")])).is_err(),
            "a bundle without a key is not a key file"
        );
    }
}
