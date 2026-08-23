//! vynm new (V-20): plugin project scaffolding from embedded templates.
//! Templates carry a `{{name}}` placeholder; plain str replace keeps the
//! template files themselves valid, previewable Rust/JSON/TOML.

use std::path::Path;

use crate::error::VynmError;
use crate::validate::validate_identifier;

const TEMPLATE_PLUGIN_JSON: &str = include_str!("templates/new/plugin.json");
const TEMPLATE_CARGO_TOML: &str = include_str!("templates/new/Cargo.toml");
const TEMPLATE_MAIN_RS: &str = include_str!("templates/new/src_main.rs");
const TEMPLATE_GITIGNORE: &str = "/target\n";
const TEMPLATE_README: &str = include_str!("templates/new/README.md");

fn render(template: &str, name: &str) -> String {
    template.replace("{{name}}", name)
}

/// Create `./<name>/` with the scaffold. `force` overwrites existing files
/// inside the dir; without it an existing dir is refused untouched.
pub fn scaffold(base: &Path, name: &str, force: bool) -> Result<(), VynmError> {
    validate_identifier(name, 64)?;
    let dir = base.join(name);
    if dir.exists() && !force {
        return Err(VynmError::InvalidInput(format!(
            "{} already exists — pass --force to overwrite",
            dir.display()
        )));
    }
    std::fs::create_dir_all(dir.join("src"))?;

    let files: &[(&str, String)] = &[
        ("plugin.json", render(TEMPLATE_PLUGIN_JSON, name)),
        ("Cargo.toml", render(TEMPLATE_CARGO_TOML, name)),
        ("src/main.rs", render(TEMPLATE_MAIN_RS, name)),
        (".gitignore", TEMPLATE_GITIGNORE.into()),
        ("README.md", render(TEMPLATE_README, name)),
    ];
    for (rel, content) in files {
        std::fs::write(dir.join(rel), content.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "scaffold_tests.rs"]
mod tests;
