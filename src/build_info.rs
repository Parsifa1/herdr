//! Build identity helpers.

pub const BASE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn channel() -> &'static str {
    non_empty(option_env!("HERDR_BUILD_CHANNEL")).unwrap_or("stable")
}

pub fn build_id() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_ID"))
}

pub fn version() -> String {
    let suffix = match (build_commit(), channel()) {
        (Some(commit), _) => format!(" (with quic, {commit})"),
        (None, "stable") => " (with quic)".to_string(),
        (None, channel) => match build_id() {
            Some(build_id) => format!("-{channel}.{build_id}"),
            None => format!("-{channel}"),
        },
    };
    format!("{BASE_VERSION}{suffix}")
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
