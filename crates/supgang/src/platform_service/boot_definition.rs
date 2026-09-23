//! Platform-independent validation of the administrator-owned boot definition.

use super::{ServiceError, definition};
use plist::Value;
use std::path::{Path, PathBuf};
const LABEL: &str = "org.agenxy.supgang";

pub(super) const fn root_directory_is_safe(uid: u32, mode: u32, sticky_parent: bool) -> bool {
    uid == 0 && mode & 0o002 == 0 && (mode & 0o020 == 0 || (sticky_parent && mode & 0o1000 != 0))
}

pub(super) fn validate_value(
    value: &Value,
    executable: &Path,
    state: &Path,
    home: &Path,
    user: &str,
    uid: u32,
) -> Result<(), ServiceError> {
    let arguments = value
        .as_dictionary()
        .and_then(|dict| dict.get("ProgramArguments"))
        .and_then(Value::as_array)
        .ok_or(ServiceError::UnsafeDefinition)?;
    let arguments = arguments
        .iter()
        .map(|argument| argument.as_string().ok_or(ServiceError::UnsafeDefinition))
        .collect::<Result<Vec<_>, _>>()?;
    let (anchor, mapping, endpoints) = parse_policy(&arguments)?;
    let expected = boot_definition(
        executable,
        state,
        home,
        user,
        uid,
        (anchor, mapping, endpoints.as_deref()),
    )?;
    if value != &expected {
        return Err(ServiceError::UnsafeDefinition);
    }
    Ok(())
}

fn parse_policy(arguments: &[&str]) -> Result<(bool, bool, Option<PathBuf>), ServiceError> {
    let mut remaining = arguments.get(5..).ok_or(ServiceError::UnsafeDefinition)?;
    let anchor = remaining.first() == Some(&"--anchor");
    if anchor {
        remaining = remaining.get(1..).ok_or(ServiceError::UnsafeDefinition)?;
    }
    let mapping = remaining.first() == Some(&"--router-mapping");
    if mapping {
        remaining = remaining.get(1..).ok_or(ServiceError::UnsafeDefinition)?;
    }
    let endpoints = match remaining {
        [] => None,
        ["--endpoints", path] if !mapping => Some(PathBuf::from(path)),
        _ => return Err(ServiceError::UnsafeDefinition),
    };
    if let Some(path) = &endpoints {
        definition::validated_endpoints(Some(path))?;
    }
    Ok((anchor, mapping, endpoints))
}

fn boot_definition(
    executable: &Path,
    state: &Path,
    _home: &Path,
    user: &str,
    uid: u32,
    policy: (bool, bool, Option<&Path>),
) -> Result<Value, ServiceError> {
    let (anchor, mapping, endpoints) = policy;
    let text = definition::render_launchd(executable, state, endpoints, anchor, mapping)?;
    let mut value = Value::from_reader_xml(text.as_bytes()).map_err(|_| ServiceError::UnsafeDefinition)?;
    let dict = value.as_dictionary_mut().ok_or(ServiceError::UnsafeDefinition)?;
    dict.remove("LimitLoadToSessionType");
    dict.insert("Label".to_owned(), Value::String(format!("{LABEL}.{uid}")));
    dict.insert("UserName".to_owned(), Value::String(user.to_owned()));
    dict.insert("Umask".to_owned(), Value::Integer(63.into()));
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{boot_definition, validate_value};

    #[test]
    fn sticky_admin_library_preserves_root_owned_child_trust() {
        assert!(super::root_directory_is_safe(0, 0o1775, true));
        assert!(super::root_directory_is_safe(0, 0o755, false));
        assert!(!super::root_directory_is_safe(501, 0o1775, true));
        assert!(!super::root_directory_is_safe(0, 0o775, true));
        assert!(!super::root_directory_is_safe(0, 0o1777, true));
        assert!(!super::root_directory_is_safe(0, 0o1775, false));
    }

    #[test]
    fn boot_definition_rejects_elevation_and_changed_authority() -> Result<(), Box<dyn std::error::Error>> {
        let executable = Path::new("/Users/member/bin/supgang");
        let state = Path::new("/Users/member/state");
        let home = Path::new("/Users/member");
        let value = boot_definition(executable, state, home, "member", 501, (true, true, None))?;
        validate_value(&value, executable, state, home, "member", 501)?;
        for (key, replacement) in [
            ("UserName", plist::Value::String("root".to_owned())),
            ("KeepAlive", plist::Value::Boolean(false)),
            ("Program", plist::Value::String("/tmp/other".to_owned())),
            (
                "EnvironmentVariables",
                plist::Value::Dictionary(plist::Dictionary::new()),
            ),
        ] {
            let mut changed = value.clone();
            changed
                .as_dictionary_mut()
                .ok_or("not a dictionary")?
                .insert(key.to_owned(), replacement);
            assert!(validate_value(&changed, executable, state, home, "member", 501).is_err());
        }
        assert!(
            validate_value(
                &value,
                executable,
                Path::new("/Users/member/other"),
                home,
                "member",
                501
            )
            .is_err()
        );
        assert!(validate_value(&value, executable, state, home, "member", 502).is_err());
        Ok(())
    }
}
