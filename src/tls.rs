use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

/// **Deliberately accepts every certificate, valid or not.** A tool whose
/// entire purpose is to find *invalid* certificates (expired, self-signed,
/// wrong host) cannot use normal trust validation — that would make the
/// handshake itself fail on exactly the certificates this needs to
/// inspect. This verifier only ever gets used to complete a handshake so
/// the real leaf certificate can be read back and judged on its own
/// merits (`certinfo.rs`/`expiry.rs`); it is never used to decide whether
/// anything is actually trustworthy, and must never be reused anywhere
/// that matters.
#[derive(Debug)]
struct AcceptAnyCert(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Connects to `host:port`, completes a TLS handshake (accepting any
/// certificate — see `AcceptAnyCert`), and returns the leaf certificate's
/// raw DER bytes.
pub fn fetch_leaf_cert_der(host: &str, port: u16) -> Result<Vec<u8>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = Arc::new(AcceptAnyCert(provider.clone()));

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .context("configuring TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("'{host}' is not a valid server name"))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("creating TLS client connection")?;

    let mut sock =
        TcpStream::connect((host, port)).with_context(|| format!("connecting to {host}:{port}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // Drives the handshake to completion directly. An earlier version of
    // this tried to force it via `Stream::write_all(b"")`, which turned
    // out to be a no-op (zero-length writes never touch the underlying
    // socket) — caught by live-testing against real servers, not by the
    // unit tests, which is exactly why that verification step exists.
    conn.complete_io(&mut sock)
        .context("completing TLS handshake")?;

    let certs = conn
        .peer_certificates()
        .context("no peer certificates presented")?;
    let leaf = certs.first().context("peer certificate chain was empty")?;
    Ok(leaf.to_vec())
}
