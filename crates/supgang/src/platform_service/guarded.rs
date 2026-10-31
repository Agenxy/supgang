//! macOS consent boundaries, checked before writing or loading a definition.

use std::path::Path;

use super::ServiceError;

pub(super) fn validate(path: &Path, home: &Path) -> Result<(), ServiceError> {
    for (relative, name) in [
        ("Desktop", "~/Desktop"),
        ("Documents", "~/Documents"),
        ("Downloads", "~/Downloads"),
        ("Library/Mobile Documents", "iCloud Drive (~/Library/Mobile Documents)"),
        ("Library/CloudStorage", "~/Library/CloudStorage"),
    ] {
        if path.starts_with(home.join(relative)) {
            return Err(ServiceError::GuardedDirectory(name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate;
    use std::path::Path;

    #[test]
    fn a_program_in_a_directory_the_platform_guards_is_refused_by_name() -> Result<(), Box<dyn std::error::Error>> {
        let home = Path::new("/Users/member");
        for directory in [
            "Desktop",
            "Documents",
            "Downloads",
            "Library/Mobile Documents",
            "Library/CloudStorage",
        ] {
            let error = validate(&home.join(directory).join("bin/supgang"), home)
                .err()
                .ok_or("guarded path accepted")?;
            let message = error.to_string();
            assert!(message.contains(directory));
            assert!(message.contains("~/Library/Application Support/org.agenxy.supgang"));
        }
        assert!(validate(&home.join("Desktop-other/supgang"), home).is_ok());
        assert!(
            validate(
                &home.join("Library/Application Support/org.agenxy.supgang/bin/supgang"),
                home
            )
            .is_ok()
        );
        Ok(())
    }
}
