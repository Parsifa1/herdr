//! Device identity for the remote QUIC transport: enroll once over the
//! authenticated SSH bootstrap, then prove the device with a self-signed TLS
//! client certificate. The server authorizes certificate digests, so revoking
//! an entry takes effect on that device's next connection.

use std::io;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};

pub(crate) const DEVICE_FILE: &str = "remote-quic-device.json";
pub(crate) const DEVICES_FILE: &str = "remote-quic-devices.json";

/// The local device's key and its self-signed certificate. The certificate is
/// stored rather than re-minted so its digest — which the server authorizes —
/// stays stable across restarts.
#[derive(Serialize, Deserialize)]
pub(crate) struct DeviceIdentity {
    private_key_hex: String,
    certificate_hex: String,
}

impl DeviceIdentity {
    /// Reads an enrolled device, never creating one: checking whether this
    /// machine can renew a credential must not enroll it as a side effect.
    pub(crate) fn load(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let stored: Self = serde_json::from_slice(&bytes).ok()?;
        stored.private_key().ok()?;
        Some(stored)
    }

    pub(crate) fn load_or_create(path: &Path) -> io::Result<Self> {
        if let Some(stored) = Self::load(path) {
            return Ok(stored);
        }
        let identity = Self::create()?;
        write_private(
            path,
            &serde_json::to_vec(&identity).map_err(io::Error::other)?,
        )?;
        Ok(identity)
    }

    fn create() -> io::Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|err| io::Error::other(err.to_string()))?;
        let params = CertificateParams::new(vec!["herdr-device".to_owned()])
            .map_err(|err| io::Error::other(err.to_string()))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Self {
            private_key_hex: hex_encode(&key.serialize_der()),
            certificate_hex: hex_encode(certificate.der()),
        })
    }

    fn private_key(&self) -> io::Result<Vec<u8>> {
        hex_decode(&self.private_key_hex)
    }

    pub(crate) fn certificate_der(&self) -> Vec<u8> {
        hex_decode(&self.certificate_hex).unwrap_or_default()
    }

    /// The TLS client configuration that presents this device.
    pub(crate) fn client_config(
        &self,
    ) -> Result<(Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>), String> {
        let key = self.private_key().map_err(|err| err.to_string())?;
        Ok((
            self.certificate_der(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        ))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct DeviceList {
    #[serde(default)]
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
    /// A missing or unreadable file is an empty list: the first enrollment
    /// creates it, and a corrupt file must not keep the endpoint down.
    pub(crate) fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
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
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        write_private(path, &bytes)
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

/// 0600 in one step: the device key authorizes this machine, so it must never
/// be world-readable, not even between create and chmod.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)
}

pub(crate) fn device_path() -> PathBuf {
    crate::config::state_dir().join(DEVICE_FILE)
}

pub(crate) fn devices_path() -> PathBuf {
    crate::config::config_dir().join(DEVICES_FILE)
}

/// Records the certificate the SSH-authenticated bootstrap presented.
pub(crate) fn enroll(certificate: &[u8], name: &str) -> io::Result<bool> {
    let path = devices_path();
    let mut devices = DeviceList::load(&path);
    let added = devices.add(name, certificate, unix_seconds());
    if added {
        devices.save(&path)?;
    }
    Ok(added)
}

/// Marks a device revoked and keeps its tombstone so the same certificate
/// cannot be re-enrolled by a later SSH bootstrap.
pub(crate) fn revoke(name: &str) -> io::Result<bool> {
    let path = devices_path();
    let mut devices = DeviceList::load(&path);
    let mut revoked = false;
    for device in &mut devices.devices {
        if device.name == name && !device.revoked {
            device.revoked = true;
            revoked = true;
        }
    }
    if revoked {
        devices.save(&path)?;
    }
    Ok(revoked)
}

pub(crate) fn list() -> io::Result<DeviceList> {
    Ok(DeviceList::load(&devices_path()))
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
    fn a_corrupt_devices_file_reads_as_empty() {
        let dir = std::env::temp_dir().join(format!("herdr-devices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(DeviceList::load(&path).devices.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
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
        let dir = std::env::temp_dir().join(format!("herdr-devkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.json");

        let first = DeviceIdentity::load_or_create(&path).expect("create device key");
        let second = DeviceIdentity::load_or_create(&path).expect("reload device key");
        assert_eq!(first.certificate_der(), second.certificate_der());
        assert!(!first.certificate_der().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_never_creates_a_device_key() {
        let dir = std::env::temp_dir().join(format!("herdr-nodevkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missing.json");

        assert!(DeviceIdentity::load(&path).is_none());
        assert!(!path.exists(), "a read must not enroll the machine");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
