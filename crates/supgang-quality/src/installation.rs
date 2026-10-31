//! Static installation checks complement, but cannot prove, runtime conformance.

use std::{fs, path::Path};

pub fn inspect(root: &Path) -> Result<(), String> {
    for file in [
        "docs/architecture/agenxy-installation.md",
        "docs/architecture/supgang-installation-conformance.md",
    ] {
        if !root.join(file).is_file() {
            return Err(format!(
                "installation specification or conformance record missing: {file}"
            ));
        }
    }
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml")).map_err(|error| error.to_string())?;
    for required in [
        "- macos-15",
        "- ubuntu-24.04",
        "runs-on: ${{ matrix.runner }}",
        "cargo run --locked --package supgang-quality -- all",
    ] {
        if !workflow.contains(required) {
            return Err(format!(
                "installer tests must run on macOS and Linux: missing {required}"
            ));
        }
    }
    let directory = root.join("crates/supgang/src/platform_service");
    for file in [
        "definition.rs",
        "boot_definition.rs",
        "guarded.rs",
        "definition_tests.rs",
        "observation/tests.rs",
        "tests.rs",
    ] {
        let text = fs::read_to_string(directory.join(file)).map_err(|error| error.to_string())?;
        // A production platform cfg may include `test`; an OS-only cfg must
        // never hide the renderer, parser or their regression tests.
        if text.contains("#[cfg(target_os") {
            return Err(format!(
                "pure installer code/tests are hidden from another platform: {file}"
            ));
        }
    }
    Ok(())
}

pub fn source(relative: &str, text: &str) -> Result<(), String> {
    if !(relative.starts_with("crates/supgang/src/platform_service/")
        || relative == "crates/supgang/src/platform_service.rs"
        || relative == "crates/supgang/src/update/executable.rs")
        || relative.ends_with("tests.rs")
    {
        return Ok(());
    }
    let file = syn::parse_file(text).map_err(|error| format!("cannot inspect {relative}: {error}"))?;
    let mut visitor = Writes { violation: None };
    syn::visit::Visit::visit_file(&mut visitor, &file);
    visitor.violation.map_or(Ok(()), |reason| {
        Err(format!(
            "installer may overwrite an existing binary or definition: {relative}: {reason}; use create_new and rename"
        ))
    })
}

struct Writes {
    violation: Option<&'static str>,
}

impl<'ast> syn::visit::Visit<'ast> for Writes {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !item.attrs.iter().any(test_only) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !item.attrs.iter().any(test_only) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = &*call.func {
            let segments: Vec<_> = function
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if let [.., module, name] = segments.as_slice()
                && ((module == "fs" && matches!(name.as_str(), "copy" | "write"))
                    || (module == "File" && name == "create"))
            {
                self.violation = Some("truncating filesystem convenience API");
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if matches!(call.method.to_string().as_str(), "create" | "truncate") && true_argument(call) {
            self.violation = Some("create/truncate may reuse an existing inode");
        }
        if call.method == "open" {
            let mut receiver = &*call.receiver;
            let mut writable = false;
            let mut exclusive = false;
            while let syn::Expr::MethodCall(method) = receiver {
                writable |= method.method == "write" && true_argument(method);
                exclusive |= method.method == "create_new" && true_argument(method);
                receiver = &method.receiver;
            }
            if writable && !exclusive {
                self.violation = Some("write descriptor is not create_new");
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn true_argument(call: &syn::ExprMethodCall) -> bool {
    matches!(call.args.first(), Some(syn::Expr::Lit(value)) if matches!(&value.lit, syn::Lit::Bool(boolean) if boolean.value))
}

fn test_only(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("test")
        || (attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| requires_test(&meta)))
}

fn requires_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
            .is_ok_and(|entries| entries.iter().any(requires_test)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gate_rejects_detectable_in_place_installer_writes() {
        for source in [
            "fs::copy(source, installed)?;",
            "std::fs::write(installed, bytes)?;",
            "File :: create(installed)?;",
            "OpenOptions::new().write(true).open(installed)?;",
            "OpenOptions::new().write(true).create(true).open(installed)?;",
            "OpenOptions::new().write(true).create_new(true).truncate(true).open(installed)?;",
        ] {
            assert!(
                super::source(
                    "crates/supgang/src/platform_service/executable.rs",
                    &format!("fn install() {{ {source} }}")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn gate_accepts_fresh_file_and_rename_installation() {
        assert!(super::source("crates/supgang/src/platform_service/executable.rs",
            "fn install() { let file = OpenOptions::new().write(true).create_new(true).open(temporary)?; file.write_all(bytes)?; file.sync_all()?; fs::rename(temporary, installed)?; }"
        ).is_ok());
    }

    #[test]
    fn gate_scans_production_after_test_modules_and_ignores_test_only_copies() {
        let tests = "#[cfg(all(test, target_os = \"macos\"))] mod tests { fn fixture() { fs::copy(a, b); } }";
        let path = "crates/supgang/src/platform_service/executable.rs";
        assert!(super::source(path, tests).is_ok());
        assert!(super::source(path, &format!("{tests}\nfn install() {{ fs::copy(a, b); }}")).is_err());
        assert!(super::source(path, "// fs::copy is forbidden\nfn install() {} ").is_ok());
    }
}
