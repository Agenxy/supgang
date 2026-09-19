use semver::Version;

use super::UpdateError;

pub(super) fn validate_target_name(target: &str) -> Result<Version, UpdateError> {
    let prefix = "supgang-";
    let suffix = format!("-{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let version = target
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(&suffix))
        .ok_or(UpdateError::WrongPlatform)?;
    if version.is_empty() || target.len() > 128 || !target.bytes().all(is_target_byte) {
        return Err(UpdateError::InvalidTargetName);
    }
    Version::parse(version).map_err(|_| UpdateError::InvalidTargetName)
}

pub(super) const fn is_target_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}
