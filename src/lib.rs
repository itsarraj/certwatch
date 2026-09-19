pub mod certinfo;
pub mod expiry;
pub mod tls;

const DEFAULT_PORT: u16 = 443;

/// Parses a `host` or `host:port` string, defaulting to 443. Pure, kept
/// separate from CLI parsing so the "what does 'example.com:8443' mean"
/// logic is unit-testable on its own.
pub fn parse_target(s: &str) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (s.to_string(), DEFAULT_PORT), // ':' wasn't a port separator (e.g. no port at all)
        },
        None => (s.to_string(), DEFAULT_PORT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_hostname_defaults_to_443() {
        assert_eq!(
            parse_target("example.com"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn explicit_port_is_used() {
        assert_eq!(
            parse_target("example.com:8443"),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn non_numeric_suffix_after_colon_falls_back_to_default_port() {
        // Not a real case we expect, but must degrade sanely rather than
        // silently connecting to the wrong thing.
        assert_eq!(parse_target("weird:host").1, DEFAULT_PORT);
    }
}
