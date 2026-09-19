use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_after: SystemTime,
}

/// Parses the fields we care about out of a leaf certificate's raw DER
/// bytes. Pure once you have the bytes — the actual network fetch lives
/// in `tls.rs`, so this is testable against any real certificate's DER
/// without a live connection.
pub fn parse_cert(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).context("parsing X.509 certificate DER")?;
    let not_after_asn1 = cert.validity().not_after;
    let not_after =
        SystemTime::UNIX_EPOCH + Duration::from_secs(not_after_asn1.timestamp().max(0) as u64);
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen_test_helpers::self_signed_der;

    #[test]
    fn parses_subject_issuer_and_not_after_from_a_real_cert() {
        let (der, expected_not_after) = self_signed_der("certwatch-test.example", 30);
        let info = parse_cert(&der).unwrap();
        assert!(info.subject.contains("certwatch-test.example"));
        // A self-signed cert is its own issuer.
        assert_eq!(info.subject, info.issuer);

        let diff = info
            .not_after
            .duration_since(expected_not_after)
            .unwrap_or_else(|e| e.duration());
        assert!(
            diff.as_secs() < 5,
            "parsed not_after should match what was generated, within a few seconds of rounding"
        );
    }

    #[test]
    fn garbage_bytes_are_a_clean_error_not_a_panic() {
        assert!(parse_cert(b"not a certificate").is_err());
    }

    /// A tiny self-signed-cert generator used only by this module's own
    /// tests, kept inline rather than as a real dependency — `certwatch`
    /// itself never generates certificates, only reads them.
    mod rcgen_test_helpers {
        use std::time::{Duration, SystemTime};

        pub fn self_signed_der(cn: &str, days_valid: i64) -> (Vec<u8>, SystemTime) {
            use rcgen::{CertificateParams, DnType, KeyPair};
            let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, cn);
            let now = time::OffsetDateTime::now_utc();
            let not_after = now + time::Duration::days(days_valid);
            params.not_before = now - time::Duration::days(1);
            params.not_after = not_after;
            let key = KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            let not_after_std =
                SystemTime::UNIX_EPOCH + Duration::from_secs(not_after.unix_timestamp() as u64);
            (cert.der().to_vec(), not_after_std)
        }
    }
}
