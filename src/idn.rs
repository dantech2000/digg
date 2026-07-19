use crate::error::DnsError;

/// Convert a domain name to its ASCII (A-label) form per UTS-46/IDNA2008.
/// ASCII input takes a fast path and is returned unchanged, so existing
/// behavior (including trailing-dot handling) is untouched for the common
/// case. Non-ASCII input that fails IDNA mapping is a usage error.
pub fn to_ascii(name: &str) -> Result<String, DnsError> {
    if name.is_ascii() {
        return Ok(name.to_string());
    }
    // Preserve a trailing root dot across conversion.
    let (bare, had_root_dot) = match name.strip_suffix('.') {
        Some(b) if !b.is_empty() => (b, true),
        _ => (name, false),
    };
    let ascii = idna::domain_to_ascii(bare)
        .map_err(|_| DnsError::Usage(format!("invalid internationalized domain name: {}", name)))?;
    if had_root_dot {
        Ok(format!("{}.", ascii))
    } else {
        Ok(ascii)
    }
}

/// Convert A-labels back to Unicode for display (+idnout). Lossy: anything
/// that fails conversion is shown as-is.
pub fn to_unicode_lossy(name: &str) -> String {
    if !name.contains("xn--") {
        return name.to_string();
    }
    let (unicode, _result) = idna::domain_to_unicode(name.trim_end_matches('.'));
    if name.ends_with('.') {
        format!("{}.", unicode)
    } else {
        unicode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_names_pass_through_unchanged() {
        assert_eq!(to_ascii("example.com").unwrap(), "example.com");
        assert_eq!(to_ascii("example.com.").unwrap(), "example.com.");
        assert_eq!(to_ascii(".").unwrap(), ".");
        assert_eq!(to_ascii("xn--mnchen-3ya.de").unwrap(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn unicode_names_convert_to_a_labels() {
        assert_eq!(to_ascii("münchen.de").unwrap(), "xn--mnchen-3ya.de");
        assert_eq!(to_ascii("日本.jp").unwrap(), "xn--wgv71a.jp");
        assert_eq!(to_ascii("münchen.de.").unwrap(), "xn--mnchen-3ya.de.");
    }

    #[test]
    fn uts46_mapping_normalizes_case_and_width() {
        // Uppercase Unicode maps down; full-width ASCII maps to ASCII.
        assert_eq!(to_ascii("MÜNCHEN.de").unwrap(), "xn--mnchen-3ya.de");
        assert_eq!(to_ascii("ｅｘａｍｐｌｅ.com").unwrap(), "example.com");
    }

    #[test]
    fn disallowed_code_points_are_usage_errors() {
        assert!(to_ascii("exa\u{2028}mple.com").is_err());
    }

    #[test]
    fn a_labels_round_trip_back_to_unicode() {
        assert_eq!(to_unicode_lossy("xn--mnchen-3ya.de"), "münchen.de");
        assert_eq!(to_unicode_lossy("xn--mnchen-3ya.de."), "münchen.de.");
        assert_eq!(to_unicode_lossy("xn--wgv71a.jp"), "日本.jp");
        // Non-IDN names skip conversion entirely.
        assert_eq!(to_unicode_lossy("example.com."), "example.com.");
    }
}
