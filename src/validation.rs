//! Shared input validation utilities for security hardening.
//!
//! This module provides reusable validation functions used across the codebase
//! to prevent command injection, SSRF, SPARQL injection, path traversal,
//! and other input-based attacks.

use std::fmt;
use std::net::IpAddr;

/// Policy for handling private/localhost IPs in URL validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrfPolicy {
    /// Block all private/localhost IPs (for external-facing features like CCG import).
    BlockPrivate,
    /// Allow private/localhost IPs but log a warning (for user-configured endpoints like embedding servers).
    WarnOnPrivate,
}

impl fmt::Display for SsrfPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsrfPolicy::BlockPrivate => write!(f, "BlockPrivate"),
            SsrfPolicy::WarnOnPrivate => write!(f, "WarnOnPrivate"),
        }
    }
}

/// Characters forbidden in git refs and shell-sensitive contexts.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '`', '$', '(', ')', '>', '<', '{', '}', '!', '\n', '\r', '\0', '\'', '"',
];

/// Maximum length for a git ref (branch, tag, commit hash).
const MAX_GIT_REF_LENGTH: usize = 256;

/// Maximum length for a GitHub owner or repo component.
const MAX_GITHUB_COMPONENT_LENGTH: usize = 100;

/// Maximum URL length.
const MAX_URL_LENGTH: usize = 2048;

/// Validates a git ref (branch name, tag, or commit hash).
///
/// Blocks:
/// - Empty strings
/// - Strings starting with `-` (git argument injection)
/// - Null bytes
/// - Shell metacharacters (`;|&`$()><{}!\n\r\0'"`)
/// - `..` sequences (directory traversal in refs)
/// - Refs longer than 256 characters
///
/// # Errors
///
/// Returns an error describing the validation failure.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::validate_git_ref;
///
/// assert!(validate_git_ref("main").is_ok());
/// assert!(validate_git_ref("feature/my-branch").is_ok());
/// assert!(validate_git_ref("abc123def").is_ok());
/// assert!(validate_git_ref(";whoami").is_err());
/// assert!(validate_git_ref("--exec=evil").is_err());
/// ```
pub fn validate_git_ref(input: &str) -> Result<(), String> {
    if input.is_empty() {
        return Err("git ref cannot be empty".to_string());
    }

    if input.len() > MAX_GIT_REF_LENGTH {
        return Err(format!(
            "git ref too long: {} characters (max {})",
            input.len(),
            MAX_GIT_REF_LENGTH
        ));
    }

    if input.starts_with('-') {
        return Err("git ref cannot start with '-' (argument injection)".to_string());
    }

    if input.contains("..") {
        return Err("git ref cannot contain '..' (directory traversal)".to_string());
    }

    for ch in input.chars() {
        if SHELL_METACHARACTERS.contains(&ch) {
            return Err(format!("git ref contains forbidden character: {:?}", ch));
        }
    }

    // Block spaces and control characters
    for ch in input.chars() {
        if ch.is_control() {
            return Err(format!(
                "git ref contains control character: U+{:04X}",
                ch as u32
            ));
        }
    }

    Ok(())
}

/// Validates a GitHub owner or repository name component.
///
/// Only allows `[a-zA-Z0-9._-]`, max 100 characters, non-empty.
///
/// # Errors
///
/// Returns an error describing the validation failure.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::validate_github_component;
///
/// assert!(validate_github_component("postrv").is_ok());
/// assert!(validate_github_component("my-repo.v2").is_ok());
/// assert!(validate_github_component("../../etc").is_err());
/// assert!(validate_github_component("owner;rm -rf").is_err());
/// ```
pub fn validate_github_component(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("GitHub component name cannot be empty".to_string());
    }

    if name.len() > MAX_GITHUB_COMPONENT_LENGTH {
        return Err(format!(
            "GitHub component name too long: {} characters (max {})",
            name.len(),
            MAX_GITHUB_COMPONENT_LENGTH
        ));
    }

    // Block path traversal patterns
    if name == "." || name == ".." || name.contains("..") {
        return Err("GitHub component name cannot be '.' or '..' or contain '..'".to_string());
    }

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_' && ch != '-' {
            return Err(format!(
                "GitHub component name contains invalid character: {:?}",
                ch
            ));
        }
    }

    Ok(())
}

/// Checks if a hostname is localhost or a private IP address.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::is_private_or_localhost;
///
/// assert!(is_private_or_localhost("localhost"));
/// assert!(is_private_or_localhost("127.0.0.1"));
/// assert!(is_private_or_localhost("10.0.0.1"));
/// assert!(!is_private_or_localhost("github.com"));
/// ```
#[must_use]
pub fn is_private_or_localhost(host: &str) -> bool {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || octets[0] == 127
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    } else {
        false
    }
}

/// Checks if a hostname is a cloud metadata service.
#[must_use]
fn is_cloud_metadata(host: &str) -> bool {
    host == "169.254.169.254"
        || host == "fd00:ec2::254"
        || host.starts_with("fd00:ec2:")
        || host == "metadata.google.internal"
        || host == "metadata"
        || host == "169.254.169.253"
}

/// Validates a URL against SSRF attacks.
///
/// Enforces:
/// - Only `http` / `https` schemes
/// - URL must have a hostname
/// - Blocks cloud metadata service IPs/hostnames
/// - Depending on `policy`, blocks or warns on private/localhost IPs
/// - Max URL length of 2048 characters
///
/// # Errors
///
/// Returns an error if the URL is invalid, uses a disallowed scheme,
/// or targets a blocked host.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::{validate_url_for_ssrf, SsrfPolicy};
///
/// assert!(validate_url_for_ssrf("https://api.example.com/v1", SsrfPolicy::BlockPrivate).is_ok());
/// assert!(validate_url_for_ssrf("http://169.254.169.254/metadata", SsrfPolicy::BlockPrivate).is_err());
/// assert!(validate_url_for_ssrf("file:///etc/passwd", SsrfPolicy::BlockPrivate).is_err());
/// ```
pub fn validate_url_for_ssrf(url_str: &str, policy: SsrfPolicy) -> Result<String, String> {
    if url_str.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL too long: {} characters (max {})",
            url_str.len(),
            MAX_URL_LENGTH
        ));
    }

    let parsed = url::Url::parse(url_str).map_err(|e| format!("Invalid URL format: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "Invalid URL scheme '{}': only 'http' and 'https' are allowed",
                scheme
            ));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a hostname".to_string())?;

    if is_cloud_metadata(host) {
        return Err(format!(
            "Access to cloud metadata service URLs is blocked for security: {}",
            host
        ));
    }

    if is_private_or_localhost(host) {
        match policy {
            SsrfPolicy::BlockPrivate => {
                return Err(format!(
                    "Access to private/localhost URLs is blocked: {}",
                    host
                ));
            }
            SsrfPolicy::WarnOnPrivate => {
                tracing::warn!(
                    "URL uses localhost or private IP address: {}. \
                     Ensure this is intentional.",
                    host
                );
            }
        }
    }

    Ok(url_str.to_string())
}

/// Escapes a string for safe inclusion in a SPARQL string literal.
///
/// Escapes characters per SPARQL 1.1 grammar: `\`, `"`, `'`, `\n`, `\r`, `\t`, `\0`.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::escape_sparql_literal;
///
/// assert_eq!(escape_sparql_literal("hello"), "hello");
/// assert_eq!(escape_sparql_literal(r#"say "hi""#), r#"say \"hi\""#);
/// assert_eq!(escape_sparql_literal("line1\nline2"), "line1\\nline2");
/// ```
#[must_use]
pub fn escape_sparql_literal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\'' => result.push_str("\\'"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\0' => result.push_str("\\0"),
            _ => result.push(ch),
        }
    }
    result
}

/// Percent-encodes characters outside `[A-Za-z0-9._~-]` for safe IRI construction.
///
/// This is more aggressive than standard URL encoding — it ensures the result
/// is safe for use in RDF IRIs.
///
/// # Examples
///
/// ```
/// use narsil_mcp::validation::sanitize_iri_component;
///
/// assert_eq!(sanitize_iri_component("hello"), "hello");
/// assert_eq!(sanitize_iri_component("hello world"), "hello%20world");
/// assert_eq!(sanitize_iri_component("a/b:c#d"), "a%2Fb%3Ac%23d");
/// ```
#[must_use]
pub fn sanitize_iri_component(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Validates that an LSP server path is safe to execute.
///
/// Blocks shell metacharacters and requires the path to be either a bare command name
/// or an absolute path (no relative traversal).
///
/// # Errors
///
/// Returns an error if the path contains shell metacharacters or is a relative path
/// with traversal components.
pub fn validate_lsp_server_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("LSP server path cannot be empty".to_string());
    }

    for ch in path.chars() {
        if SHELL_METACHARACTERS.contains(&ch) {
            return Err(format!(
                "LSP server path contains forbidden character: {:?}",
                ch
            ));
        }
    }

    // If it looks like a path (contains separator), it must be absolute
    if path.contains('/') || path.contains('\\') {
        if path.contains("..") {
            return Err("LSP server path cannot contain '..' (path traversal)".to_string());
        }
        if !path.starts_with('/') && !path.starts_with('\\') {
            // Allow drive letters on Windows (e.g., C:\...)
            let has_drive_letter = path.len() >= 3
                && path.as_bytes()[0].is_ascii_alphabetic()
                && path.as_bytes()[1] == b':';
            if !has_drive_letter {
                return Err("LSP server path with directories must be absolute".to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // validate_git_ref tests
    // ========================================================================

    #[test]
    fn test_validate_git_ref_valid_branch() {
        assert!(validate_git_ref("main").is_ok());
        assert!(validate_git_ref("feature/my-branch").is_ok());
        assert!(validate_git_ref("release-1.0").is_ok());
        assert!(validate_git_ref("v2.3.4").is_ok());
    }

    #[test]
    fn test_validate_git_ref_valid_commit_hash() {
        assert!(validate_git_ref("abc123def456").is_ok());
        assert!(validate_git_ref("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2").is_ok());
    }

    #[test]
    fn test_validate_git_ref_rejects_dash_prefix() {
        assert!(validate_git_ref("--exec=evil").is_err());
        assert!(validate_git_ref("-n").is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_null_bytes() {
        assert!(validate_git_ref("main\0evil").is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_shell_metacharacters() {
        assert!(validate_git_ref(";whoami").is_err());
        assert!(validate_git_ref("branch|cat /etc/passwd").is_err());
        assert!(validate_git_ref("branch&bg").is_err());
        assert!(validate_git_ref("`id`").is_err());
        assert!(validate_git_ref("$(whoami)").is_err());
        assert!(validate_git_ref("branch>file").is_err());
        assert!(validate_git_ref("branch'inject").is_err());
        assert!(validate_git_ref("branch\"inject").is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_double_dot() {
        assert!(validate_git_ref("main..evil").is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_empty() {
        assert!(validate_git_ref("").is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_too_long() {
        let long = "a".repeat(MAX_GIT_REF_LENGTH + 1);
        assert!(validate_git_ref(&long).is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_control_chars() {
        assert!(validate_git_ref("branch\nnewline").is_err());
        assert!(validate_git_ref("branch\rcarriage").is_err());
        assert!(validate_git_ref("branch\ttab").is_err());
    }

    // ========================================================================
    // validate_github_component tests
    // ========================================================================

    #[test]
    fn test_validate_github_component_valid() {
        assert!(validate_github_component("postrv").is_ok());
        assert!(validate_github_component("my-repo").is_ok());
        assert!(validate_github_component("repo.v2").is_ok());
        assert!(validate_github_component("under_score").is_ok());
    }

    #[test]
    fn test_validate_github_component_rejects_special_chars() {
        assert!(validate_github_component("owner;rm").is_err());
        assert!(validate_github_component("owner|pipe").is_err());
        assert!(validate_github_component("owner name").is_err());
    }

    #[test]
    fn test_validate_github_component_rejects_path_traversal() {
        assert!(validate_github_component("../../etc").is_err());
        assert!(validate_github_component("..").is_err());
    }

    #[test]
    fn test_validate_github_component_rejects_slashes() {
        assert!(validate_github_component("owner/repo").is_err());
    }

    #[test]
    fn test_validate_github_component_rejects_empty() {
        assert!(validate_github_component("").is_err());
    }

    // ========================================================================
    // validate_url_for_ssrf tests
    // ========================================================================

    #[test]
    fn test_validate_url_accepts_https() {
        assert!(
            validate_url_for_ssrf("https://api.example.com/v1", SsrfPolicy::BlockPrivate).is_ok()
        );
        assert!(
            validate_url_for_ssrf("http://api.example.com/v1", SsrfPolicy::BlockPrivate).is_ok()
        );
    }

    #[test]
    fn test_validate_url_rejects_bad_schemes() {
        assert!(validate_url_for_ssrf("file:///etc/passwd", SsrfPolicy::BlockPrivate).is_err());
        assert!(validate_url_for_ssrf("ftp://evil.com/file", SsrfPolicy::BlockPrivate).is_err());
        assert!(validate_url_for_ssrf("gopher://evil.com", SsrfPolicy::BlockPrivate).is_err());
    }

    #[test]
    fn test_validate_url_blocks_cloud_metadata() {
        assert!(validate_url_for_ssrf(
            "http://169.254.169.254/latest/meta-data/",
            SsrfPolicy::BlockPrivate
        )
        .is_err());
        assert!(validate_url_for_ssrf(
            "http://metadata.google.internal/computeMetadata/v1/",
            SsrfPolicy::BlockPrivate
        )
        .is_err());
        assert!(
            validate_url_for_ssrf("http://169.254.169.253/metadata", SsrfPolicy::BlockPrivate)
                .is_err()
        );
    }

    #[test]
    fn test_validate_url_blocks_private_ips_when_policy_blocks() {
        assert!(validate_url_for_ssrf("http://10.0.0.1/api", SsrfPolicy::BlockPrivate).is_err());
        assert!(validate_url_for_ssrf("http://192.168.1.1/api", SsrfPolicy::BlockPrivate).is_err());
        assert!(validate_url_for_ssrf("http://172.16.0.1/api", SsrfPolicy::BlockPrivate).is_err());
        assert!(
            validate_url_for_ssrf("http://127.0.0.1:8080/api", SsrfPolicy::BlockPrivate).is_err()
        );
        assert!(
            validate_url_for_ssrf("http://localhost:8080/api", SsrfPolicy::BlockPrivate).is_err()
        );
    }

    #[test]
    fn test_validate_url_allows_private_ips_when_policy_warns() {
        assert!(
            validate_url_for_ssrf("http://localhost:8080/api", SsrfPolicy::WarnOnPrivate).is_ok()
        );
        assert!(
            validate_url_for_ssrf("http://127.0.0.1:8080/api", SsrfPolicy::WarnOnPrivate).is_ok()
        );
    }

    #[test]
    fn test_validate_url_rejects_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        assert!(validate_url_for_ssrf(&long_url, SsrfPolicy::BlockPrivate).is_err());
    }

    // ========================================================================
    // escape_sparql_literal tests
    // ========================================================================

    #[test]
    fn test_escape_sparql_basic_strings() {
        assert_eq!(escape_sparql_literal("hello world"), "hello world");
        assert_eq!(escape_sparql_literal(""), "");
    }

    #[test]
    fn test_escape_sparql_backslash_and_quotes() {
        assert_eq!(escape_sparql_literal(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(escape_sparql_literal(r"back\slash"), r"back\\slash");
        assert_eq!(escape_sparql_literal("it's"), "it\\'s");
    }

    #[test]
    fn test_escape_sparql_newlines_and_tabs() {
        assert_eq!(escape_sparql_literal("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_sparql_literal("col1\tcol2"), "col1\\tcol2");
        assert_eq!(escape_sparql_literal("cr\rhere"), "cr\\rhere");
    }

    #[test]
    fn test_escape_sparql_injection_attempts() {
        // Attempt to break out of a SPARQL string literal
        let malicious = r#"" } DELETE WHERE { ?s ?p ?o } #"#;
        let escaped = escape_sparql_literal(malicious);
        assert!(!escaped.contains(r#"""#) || escaped.contains(r#"\""#));
        assert!(escaped.starts_with("\\\""));
    }

    #[test]
    fn test_escape_sparql_null_bytes() {
        assert_eq!(escape_sparql_literal("null\0here"), "null\\0here");
    }

    // ========================================================================
    // sanitize_iri_component tests
    // ========================================================================

    #[test]
    fn test_sanitize_iri_basic() {
        assert_eq!(sanitize_iri_component("hello"), "hello");
        assert_eq!(sanitize_iri_component("test-case_v1.0"), "test-case_v1.0");
    }

    #[test]
    fn test_sanitize_iri_special_chars() {
        assert_eq!(sanitize_iri_component("a/b"), "a%2Fb");
        assert_eq!(sanitize_iri_component("a:b"), "a%3Ab");
        assert_eq!(sanitize_iri_component("a#b"), "a%23b");
        assert_eq!(sanitize_iri_component("hello world"), "hello%20world");
    }

    #[test]
    fn test_sanitize_iri_unicode() {
        let result = sanitize_iri_component("café");
        assert!(result.starts_with("caf"));
        assert!(result.contains('%'));
    }

    #[test]
    fn test_sanitize_iri_injection_attempts() {
        let result = sanitize_iri_component("> <http://evil.com> .");
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
        assert!(!result.contains(' '));
    }

    // ========================================================================
    // validate_lsp_server_path tests
    // ========================================================================

    #[test]
    fn test_validate_lsp_path_rejects_malicious() {
        assert!(validate_lsp_server_path(";whoami").is_err());
        assert!(validate_lsp_server_path("$(cat /etc/passwd)").is_err());
        assert!(validate_lsp_server_path("`id`").is_err());
    }

    #[test]
    fn test_validate_lsp_path_rejects_relative_traversal() {
        assert!(validate_lsp_server_path("../../bin/evil").is_err());
        assert!(validate_lsp_server_path("relative/path").is_err());
    }

    #[test]
    fn test_validate_lsp_path_accepts_valid() {
        assert!(validate_lsp_server_path("rust-analyzer").is_ok());
        assert!(validate_lsp_server_path("/usr/bin/rust-analyzer").is_ok());
        assert!(validate_lsp_server_path("clangd").is_ok());
    }
}
