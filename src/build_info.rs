//! Build identity helpers.

pub const BASE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn channel() -> &'static str {
    non_empty(option_env!("HERDR_BUILD_CHANNEL")).unwrap_or("stable")
}

pub fn build_id() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_ID"))
}

/// The canonical version every machine-readable surface reports: the API
/// `ping`, `status`, endpoint handshakes and the handoff fingerprint compare
/// against it. The fork marker stays out of it, because a suffix there reads
/// as a different release to every consumer that parses a version.
pub fn version() -> String {
    match (channel(), build_id()) {
        ("stable", _) => BASE_VERSION.to_string(),
        (channel, Some(build_id)) => format!("{BASE_VERSION}-{channel}.{build_id}"),
        (channel, None) => format!("{BASE_VERSION}-{channel}"),
    }
}

/// The human-facing `--version` line, which names this build's transport and
/// the commit it was built from.
pub fn display_version() -> String {
    match build_commit() {
        Some(commit) => format!("{} (with quic, {commit})", version()),
        None => format!("{} (with quic)", version()),
    }
}

fn build_commit() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_COMMIT")).map(|commit| {
        // Short hash, like git's --format=%h
        &commit[..commit.len().min(7)]
    })
}

pub fn is_preview() -> bool {
    channel() == "preview"
}

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn stable_version_defaults_to_cargo_version() {
        assert!(!super::version().is_empty());
    }
}
