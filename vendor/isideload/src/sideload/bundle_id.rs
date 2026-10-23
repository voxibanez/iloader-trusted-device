use crate::SideloadError;
use rootcause::prelude::*;

/// Normalize an optional per-install bundle ID. An empty value keeps the
/// sideloader's usual identifier (the IPA's ID followed by the developer team).
/// Explicit IDs use reverse-DNS form, with nonempty ASCII alphanumeric/hyphen
/// components. They are final identifiers, not prefixes to append a team to.
pub fn normalize_bundle_id(bundle_id: Option<&str>) -> Result<Option<String>, Report> {
    let Some(bundle_id) = bundle_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return Ok(None);
    };

    if !bundle_id.contains('.')
        || !bundle_id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!(SideloadError::InvalidBundle(
            "Bundle ID must use reverse-DNS form, such as com.example.myapp, with only letters, numbers, hyphens, and nonempty dot-separated parts.".into(),
        ));
    }

    Ok(Some(bundle_id.to_owned()))
}

/// Remap an identifier only when it is this bundle or a dot-separated child.
/// Substrings and lookalike prefixes are unrelated identifiers.
pub(crate) fn remap_identifier(value: &str, old_id: &str, new_id: &str) -> Option<String> {
    if value == old_id {
        Some(new_id.to_owned())
    } else {
        value
            .strip_prefix(old_id)
            .filter(|suffix| suffix.starts_with('.'))
            .map(|suffix| format!("{new_id}{suffix}"))
    }
}

#[cfg(test)]
#[path = "bundle_id_tests.rs"]
mod tests;
