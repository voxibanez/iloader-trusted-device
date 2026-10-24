//! Removal is limited to an extracted IPA working copy. Discovery does not
//! follow symbolic links, and completes before any extension is deleted.

use crate::SideloadError;
use rootcause::prelude::*;
use std::{cmp::Reverse, path::Path};

pub(crate) fn validate_removal_source(path: &Path) -> Result<(), Report> {
    let metadata =
        isideload_vfs::fs::metadata(path).context("Failed to inspect the application archive")?;
    if !metadata.is_file() {
        bail!(SideloadError::InvalidBundle(
            "Removing app extensions requires an IPA archive. Select the original IPA instead of an app directory; the source directory has not been changed.".into(),
        ));
    }
    Ok(())
}

/// The caller must supply the real app directory inside its fresh extraction.
/// Retained links are rejected because later bundle loading and signing may
/// follow them. Links contained within an extension are deleted with that
/// extension, without ever inspecting or changing their targets.
pub(crate) fn remove_app_extensions(app_dir: &Path) -> Result<usize, Report> {
    let metadata = isideload_vfs::fs::symlink_metadata(app_dir)
        .context("Failed to inspect the extracted app directory")?;
    if metadata.is_symlink() || !metadata.is_dir() {
        bail!(SideloadError::InvalidBundle(
            "Cannot remove app extensions: the extracted app must be a regular directory, not a symbolic link.".into(),
        ));
    }

    let mut pending = vec![(app_dir.to_path_buf(), false)];
    let mut extensions = Vec::new();
    while let Some((directory, inside_extension)) = pending.pop() {
        let entries = isideload_vfs::fs::read_dir(&directory).context(format!(
            "Failed to inspect app extensions in {}",
            directory.display()
        ))?;
        for entry in entries {
            let entry = entry.context("Failed to inspect an app extension directory entry")?;
            let path = entry.path();
            // isideload-vfs's DirEntry::file_type follows links, so explicitly
            // request non-following metadata instead.
            let metadata = isideload_vfs::fs::symlink_metadata(&path)
                .context(format!("Failed to inspect {}", path.display()))?;
            if metadata.is_symlink() {
                if !inside_extension {
                    let relative = path.strip_prefix(app_dir).unwrap_or(&path);
                    bail!(SideloadError::InvalidBundle(format!(
                        "Cannot safely remove all app extensions because the extracted app contains a retained symbolic link at {}. Its target was not followed and no extensions were removed. Use an IPA with regular files and directories.",
                        relative.display()
                    )));
                }
                continue;
            }
            if !metadata.is_dir() {
                continue;
            }
            let is_extension = path
                .extension()
                .is_some_and(|extension| extension == "appex");
            if is_extension {
                extensions.push(path.clone());
            }
            pending.push((path, inside_extension || is_extension));
        }
    }

    // Count nested extensions too, and remove children before their parents.
    extensions.sort_by_key(|path| Reverse(path.components().count()));
    for path in &extensions {
        let metadata = isideload_vfs::fs::symlink_metadata(path)
            .context("Failed to inspect an app extension before removal")?;
        if metadata.is_symlink() || !metadata.is_dir() {
            bail!(SideloadError::InvalidBundle(format!(
                "Cannot remove app extension {} because its directory changed during preparation.",
                path.display()
            )));
        }
        isideload_vfs::fs::remove_dir_all(path)
            .context(format!("Failed to remove app extension {}", path.display()))?;
    }
    Ok(extensions.len())
}

#[cfg(test)]
#[path = "extension_tests.rs"]
mod tests;
