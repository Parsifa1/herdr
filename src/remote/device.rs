//! Device identity for the remote QUIC transport: enroll once over the
//! authenticated SSH bootstrap, then prove the device with a self-signed TLS
//! client certificate. The server authorizes certificate digests, so revoking
//! an entry takes effect on that device's next connection.

use std::io;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};

use super::private_file;

pub(crate) const CLIENT_KEY_FILE: &str = "client.key";
pub(crate) const DEVICES_FILE: &str = "devices";

/// The local device's key and its self-signed certificate, in one PEM bundle:
/// the key as PKCS#8 so `openssl pkey -in` reads it, the certificate beside it
/// because its digest — which the server authorizes — must stay stable across
/// restarts rather than being re-minted.
pub(crate) struct DeviceIdentity {
    private_key_der: Vec<u8>,
    certificate_der: Vec<u8>,
}

impl DeviceIdentity {
    /// Reads an enrolled device, never creating one: checking whether this
    /// machine can renew a credential must not enroll it as a side effect.
    pub(crate) fn load(path: &Path) -> Option<Self> {
        Self::try_load(path).ok().flatten()
    }

    /// `Ok(None)` means no key has been written yet. A key file that exists but
    /// does not parse is an error, never a reason to mint a new one: replacing
    /// it would silently un-enroll the machine and abandon the certificate the
    /// server still lists.
    pub(crate) fn try_load(path: &Path) -> io::Result<Option<Self>> {
        let Some(bytes) = private_file::read(path)? else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|err| invalid(format!("{} is not a PEM file: {err}", path.display())))?;
        let (private_key_der, certificate_der) =
            private_file::pem_read_key_and_certificate(text).map_err(|err| {
                invalid(format!("{} is not a device key: {err}", path.display()))
            })?;
        Ok(Some(Self {
            private_key_der,
            certificate_der,
        }))
    }

    /// Creates the device key unless one is already there, and returns whichever
    /// key the machine now has. Creation is exclusive, so two processes starting
    /// together agree on one identity instead of replacing each other's.
    pub(crate) fn load_or_create(path: &Path) -> io::Result<Self> {
        if let Some(identity) = Self::try_load(path)? {
            return Ok(identity);
        }
        let identity = Self::create()?;
        let bundle = private_file::pem_encode(&[
            ("PRIVATE KEY", &identity.private_key_der),
            ("CERTIFICATE", &identity.certificate_der),
        ]);
        private_file::create_exclusive(path, bundle.as_bytes())?;
        Self::try_load(path)?.ok_or_else(|| {
            io::Error::other(format!(
                "{} disappeared while it was being created",
                path.display()
            ))
        })
    }

    fn create() -> io::Result<Self> {
        let key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|err| io::Error::other(err.to_string()))?;
        let params = CertificateParams::new(vec!["herdr-device".to_owned()])
            .map_err(|err| io::Error::other(err.to_string()))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Self {
            private_key_der: key.serialize_der(),
            certificate_der: certificate.der().to_vec(),
        })
    }

    pub(crate) fn certificate_der(&self) -> Vec<u8> {
        self.certificate_der.clone()
    }

    #[cfg(test)]
    fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    /// The TLS client configuration that presents this device.
    pub(crate) fn client_config(
        &self,
    ) -> Result<(Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>), String> {
        Ok((
            self.certificate_der.clone(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into(),
        ))
    }
}

/// The authorized devices, one compact JSON object per line: a line can be read
/// and rewritten without parsing the rest, and a truncated line costs one entry
/// rather than the whole list.
#[derive(Debug, Default)]
pub(crate) struct DeviceList {
    pub(crate) devices: Vec<AuthorizedDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthorizedDevice {
    pub(crate) name: String,
    pub(crate) certificate_sha256: String,
    #[serde(default)]
    pub(crate) enrolled_unix_seconds: u64,
    /// A revoked entry stays behind as a tombstone so the next SSH bootstrap
    /// cannot silently re-authorize the same certificate.
    #[serde(default)]
    pub(crate) revoked: bool,
}

impl DeviceList {
    /// The authorization path. A corrupt file yields an empty list, so every
    /// device is refused rather than trusted: a server that cannot read its
    /// allowlist must not admit anyone.
    pub(crate) fn load(path: &Path) -> Self {
        Self::try_load(path).unwrap_or_else(|err| {
            tracing::warn!(path = %path.display(), error = %err, "remote QUIC device list is not readable");
            Self::default()
        })
    }

    /// The mutation path: an unreadable line is an error, so a corrupt file is
    /// never rewritten over. Filtering it to the lines that parse would quietly
    /// drop every device the corruption touched.
    pub(crate) fn try_load(path: &Path) -> io::Result<Self> {
        let Some(bytes) = private_file::read(path)? else {
            return Ok(Self::default());
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|err| invalid(format!("{} is not UTF-8: {err}", path.display())))?;
        let mut devices = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            devices.push(serde_json::from_str(line).map_err(|err| {
                invalid(format!("{}:{}: {err}", path.display(), index + 1))
            })?);
        }
        Ok(Self { devices })
    }

    pub(crate) fn contains(&self, certificate: &[u8]) -> bool {
        let digest = hex_encode(&hash(certificate));
        self.devices.iter().any(|device| {
            !device.revoked && device.certificate_sha256.eq_ignore_ascii_case(&digest)
        })
    }

    fn is_revoked(&self, certificate: &[u8]) -> bool {
        let digest = hex_encode(&hash(certificate));
        self.devices
            .iter()
            .any(|device| device.revoked && device.certificate_sha256.eq_ignore_ascii_case(&digest))
    }

    pub(crate) fn add(&mut self, name: &str, certificate: &[u8], now_unix_seconds: u64) -> bool {
        if self.is_revoked(certificate) || self.contains(certificate) {
            return false;
        }
        self.devices.push(AuthorizedDevice {
            name: name.to_owned(),
            certificate_sha256: hex_encode(&hash(certificate)),
            enrolled_unix_seconds: now_unix_seconds,
            revoked: false,
        });
        true
    }

    pub(crate) fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::new();
        for device in &self.devices {
            bytes.extend_from_slice(&serde_json::to_vec(device).map_err(io::Error::other)?);
            bytes.push(b'\n');
        }
        private_file::write_atomic(path, &bytes)
    }
}

fn hash(bytes: &[u8]) -> [u8; crate::protocol::REMOTE_QUIC_HASH_BYTES] {
    super::frame::hash_bytes(bytes)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub(crate) fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    hex_decode(value)
}

fn hex_decode(value: &str) -> io::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hex string has an odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let text = std::str::from_utf8(chunk)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        bytes.push(
            u8::from_str_radix(text, 16)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
        );
    }
    Ok(bytes)
}

fn invalid(detail: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

pub(crate) fn client_key_path() -> PathBuf {
    crate::config::state_dir().join(CLIENT_KEY_FILE)
}

pub(crate) fn devices_path() -> PathBuf {
    crate::config::state_dir().join(DEVICES_FILE)
}

/// Records the certificate the SSH-authenticated bootstrap presented. The
/// read-modify-write holds the list's lock, so a concurrent revoke is not lost.
pub(crate) fn enroll(certificate: &[u8], name: &str) -> io::Result<bool> {
    update_devices(|devices| devices.add(name, certificate, unix_seconds()))
}

/// Marks a device revoked and keeps its tombstone so the same certificate
/// cannot be re-enrolled by a later SSH bootstrap.
pub(crate) fn revoke(name: &str) -> io::Result<bool> {
    update_devices(|devices| {
        let mut revoked = false;
        for device in &mut devices.devices {
            if device.name == name && !device.revoked {
                device.revoked = true;
                revoked = true;
            }
        }
        revoked
    })
}

fn update_devices(change: impl FnOnce(&mut DeviceList) -> bool) -> io::Result<bool> {
    let path = devices_path();
    let _lock = private_file::lock(&path)?;
    let mut devices = DeviceList::try_load(&path)?;
    let changed = change(&mut devices);
    if changed {
        devices.save(&path)?;
    }
    Ok(changed)
}

pub(crate) fn list() -> io::Result<DeviceList> {
    DeviceList::try_load(&devices_path())
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Authorizes a presented client certificate against the devices file. Read per
/// handshake so revocation takes effect on the next connection.
#[derive(Debug)]
pub(crate) struct DeviceCertVerifier {
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl DeviceCertVerifier {
    pub(crate) fn new() -> Self {
        Self {
            provider: std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for DeviceCertVerifier {
    /// Offer, never require: a client that predates device enrollment still
    /// authenticates with the capability token it obtained over SSH.
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Acceptance here only proves the peer holds the key it presented. It
        // does not authorize the device: that check needs the hello's token and
        // runs per connection, where an unknown certificate is refused without
        // failing the handshake a legacy token client might still need.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("herdr-device-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn device_list() -> DeviceList {
        DeviceList::default()
    }

    #[test]
    fn enrollment_is_idempotent_and_authorizes_only_that_certificate() {
        let mut devices = device_list();
        assert!(devices.add("laptop", b"cert-a", 10));
        assert!(!devices.add("laptop", b"cert-a", 11));
        assert!(devices.contains(b"cert-a"));
        assert!(!devices.contains(b"cert-b"));
        assert_eq!(devices.devices.len(), 1);
    }

    #[test]
    fn revocation_survives_re_enrollment() {
        let mut devices = device_list();
        devices.add("laptop", b"cert-a", 10);
        devices.devices[0].revoked = true;
        assert!(!devices.contains(b"cert-a"));
        assert!(
            !devices.add("laptop", b"cert-a", 20),
            "a revoked key must not re-enroll"
        );
        assert_eq!(devices.devices.len(), 1);
    }

    #[test]
    fn the_device_list_is_one_json_object_per_line() {
        let dir = scratch("ndjson");
        let path = dir.join("devices");
        let mut devices = device_list();
        devices.add("laptop", b"cert-a", 10);
        devices.add("phone", b"cert-b", 20);
        devices.save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.starts_with("{\"name\":\"laptop\""), "{text}");
        assert!(text.ends_with('\n'), "{text}");
        let reloaded = DeviceList::try_load(&path).unwrap();
        assert_eq!(reloaded.devices.len(), 2);
        assert!(reloaded.contains(b"cert-a") && reloaded.contains(b"cert-b"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_devices_file_is_an_error_not_an_empty_list() {
        let dir = scratch("corrupt");
        let path = dir.join("devices");
        std::fs::write(
            &path,
            b"{\"name\":\"a\",\"certificate_sha256\":\"00\"}\n{not json\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = DeviceList::try_load(&path).expect_err("a corrupt list must not read as empty");
        assert!(err.to_string().contains(":2:"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_enrollments_keep_every_device() {
        let _lock = crate::config::test_config_env_lock().lock().unwrap();
        let root = scratch("enroll-race");
        let config = root.join("config");
        let state = root.join("state");
        let previous = (
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("XDG_STATE_HOME"),
        );
        std::env::set_var("XDG_CONFIG_HOME", &config);
        std::env::set_var("XDG_STATE_HOME", &state);

        // Enrollment runs from an SSH bootstrap, so two hosts enrolling at
        // once must not lose each other's row.
        std::thread::scope(|scope| {
            for index in 0..8 {
                scope.spawn(move || {
                    enroll(format!("cert-{index}").as_bytes(), &format!("machine-{index}"))
                        .expect("enroll");
                });
            }
        });
        let devices = list().expect("read devices");
        assert_eq!(devices.devices.len(), 8, "{:?}", devices.devices);

        match previous.0 {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match previous.1 {
            Some(value) => std::env::set_var("XDG_STATE_HOME", value),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(
            decode_hex(&encode_hex(b"\x00\xff\x10")).unwrap(),
            b"\x00\xff\x10"
        );
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn a_device_key_is_created_once_and_reused() {
        let dir = scratch("devkey");
        let path = dir.join("device.key");
        let first = DeviceIdentity::load_or_create(&path).expect("create device key");
        let second = DeviceIdentity::load_or_create(&path).expect("reload device key");
        assert_eq!(first.certificate_der(), second.certificate_der());
        assert!(!first.certificate_der().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_device_key_is_a_pem_bundle_openssl_can_read() {
        let dir = scratch("pem");
        let path = dir.join("device.key");
        let identity = DeviceIdentity::load_or_create(&path).expect("create device key");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{text}");
        assert!(text.contains("-----BEGIN CERTIFICATE-----\n"), "{text}");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (key, certificate) = private_file::pem_read_key_and_certificate(&text).unwrap();
        assert_eq!(
            key,
            identity.private_key_der(),
            "the PEM bundle round-trips the key it was written from"
        );
        assert_eq!(certificate, identity.certificate_der());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_never_creates_a_device_key() {
        let dir = scratch("nodevkey");
        let path = dir.join("missing.key");
        assert!(DeviceIdentity::load(&path).is_none());
        assert!(!path.exists(), "a read must not enroll the machine");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_device_key_is_never_replaced() {
        let dir = scratch("badkey");
        let path = dir.join("device.key");
        std::fs::write(&path, b"-----BEGIN PRIVATE KEY-----\nnot base64!\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            DeviceIdentity::load_or_create(&path).is_err(),
            "a broken key must surface, not be re-minted"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"-----BEGIN PRIVATE KEY-----\nnot base64!\n",
            "the existing file was overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_device_key_others_can_read_is_refused() {
        let dir = scratch("worldreadable");
        let path = dir.join("device.key");
        DeviceIdentity::load_or_create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            DeviceIdentity::try_load(&path).is_err(),
            "a world-readable device key is not trusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
