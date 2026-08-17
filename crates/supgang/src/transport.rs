//! Bounded QUIC/TLS configuration with signed-record certificate pinning.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::ids::TransportKeyId;

/// Supgang's TLS application protocol identifier.
pub const ALPN: &[u8] = b"supgang/1";
/// Maximum accepted bidirectional streams on one peer connection.
pub const MAX_BIDIRECTIONAL_STREAMS: u32 = 4;
/// Maximum accepted one-way control streams on one peer connection.
pub const MAX_UNIDIRECTIONAL_STREAMS: u32 = 2;
/// Maximum idle period before transport teardown.
pub const MAX_IDLE_SECONDS: u64 = 45;
/// Per-stream receive budget.
pub const STREAM_RECEIVE_BYTES: u32 = 64 * 1024;
/// Per-connection receive budget.
pub const CONNECTION_RECEIVE_BYTES: u32 = 256 * 1024;
/// Maximum serialized transport certificate size accepted from protected storage.
pub const MAX_TRANSPORT_CERTIFICATE_BYTES: usize = 8 * 1024;
/// Maximum serialized transport private-key size accepted from protected storage.
pub const MAX_TRANSPORT_PRIVATE_KEY_BYTES: usize = 4 * 1024;

/// A generated self-signed transport certificate and its protected private key.
pub struct TransportIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl core::fmt::Debug for TransportIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TransportIdentity")
            .field("transport_key_id", &self.key_id())
            .field("certificate_bytes", &self.certificate_der.len())
            .field("private_key_der", &"<redacted>")
            .finish()
    }
}

impl Drop for TransportIdentity {
    fn drop(&mut self) {
        self.private_key_der.zeroize();
    }
}

impl TransportIdentity {
    /// Generates a transport identity with no host or user data in its subject.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected audited cryptographic provider cannot
    /// generate or serialize the certificate key.
    pub fn generate() -> Result<Self, TransportError> {
        let certified = rcgen::generate_simple_self_signed(["supgang.invalid".to_owned()])
            .map_err(|_| TransportError::Certificate)?;
        Self::from_der(certified.cert.der().to_vec(), certified.signing_key.serialize_der())
    }

    /// Restores a certificate and private key from protected storage.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, mismatched, or unsupported key material.
    pub fn from_der(certificate_der: Vec<u8>, mut private_key_der: Vec<u8>) -> Result<Self, TransportError> {
        if certificate_der.is_empty()
            || certificate_der.len() > MAX_TRANSPORT_CERTIFICATE_BYTES
            || private_key_der.is_empty()
            || private_key_der.len() > MAX_TRANSPORT_PRIVATE_KEY_BYTES
        {
            private_key_der.zeroize();
            return Err(TransportError::InvalidIdentity);
        }
        let identity = Self {
            certificate_der,
            private_key_der,
        };
        if identity.server_config().is_err() {
            return Err(TransportError::InvalidIdentity);
        }
        Ok(identity)
    }

    /// Returns the pin placed in a signed endpoint record.
    #[must_use]
    pub fn key_id(&self) -> TransportKeyId {
        TransportKeyId::from_public_material(&self.certificate_der)
    }

    /// Returns public certificate bytes for persistence or test inspection.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub(crate) fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    /// Builds a TLS 1.3-only, zero-early-data, resource-bounded QUIC server.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, certificate, TLS, or QUIC setting.
    pub fn server_config(&self) -> Result<ServerConfig, TransportError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TransportError::Configuration)?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(self.certificate_der.clone())],
                PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into(),
            )
            .map_err(|_| TransportError::Configuration)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| TransportError::Configuration)?;
        let mut server = ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(Arc::new(bounded_transport()?));
        Ok(server)
    }
}

/// Builds a client that accepts only the certificate pinned by a signed record.
///
/// # Errors
///
/// Returns an error if TLS or QUIC configuration fails.
pub fn pinned_client_config(expected: TransportKeyId) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PinnedServerVerifier {
        provider: Arc::clone(&provider),
        expected,
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TransportError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls).map_err(|_| TransportError::Configuration)?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(bounded_transport()?));
    Ok(client)
}

/// Opens a combined client/server endpoint on an explicit local socket address.
///
/// # Errors
///
/// Returns an error if certificate generation, configuration, or UDP binding fails.
pub fn bind(address: SocketAddr) -> Result<(Endpoint, TransportIdentity), TransportError> {
    let identity = TransportIdentity::generate()?;
    let endpoint = Endpoint::server(identity.server_config()?, address)?;
    Ok((endpoint, identity))
}

/// Builds the service's explicit single-threaded asynchronous runtime.
///
/// A single owner is sufficient for the bounded personal-hive control plane
/// and avoids an implicit worker pool.
///
/// # Errors
///
/// Returns an error when the operating system cannot initialize the runtime.
pub fn build_runtime() -> Result<tokio::runtime::Runtime, TransportError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(TransportError::Runtime)
}

/// A transport identity, configuration, or socket failure.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Certificate generation failed.
    #[error("transport certificate generation failed")]
    Certificate,
    /// Persisted certificate or key bytes were empty, oversized, or invalid.
    #[error("protected transport identity is invalid")]
    InvalidIdentity,
    /// TLS or QUIC configuration rejected a security or resource setting.
    #[error("secure transport configuration failed")]
    Configuration,
    /// UDP endpoint creation or binding failed.
    #[error("transport socket operation failed")]
    Endpoint(#[from] std::io::Error),
    /// The asynchronous I/O runtime could not start.
    #[error("transport runtime initialization failed")]
    Runtime(std::io::Error),
}

#[derive(Debug)]
struct PinnedServerVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected: TransportKeyId,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && TransportKeyId::from_public_material(end_entity.as_ref()) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Supgang transport certificate pin mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn bounded_transport() -> Result<TransportConfig, TransportError> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_BIDIRECTIONAL_STREAMS.into());
    transport.max_concurrent_uni_streams(MAX_UNIDIRECTIONAL_STREAMS.into());
    transport.stream_receive_window(STREAM_RECEIVE_BYTES.into());
    transport.receive_window(CONNECTION_RECEIVE_BYTES.into());
    let idle = quinn::IdleTimeout::try_from(Duration::from_secs(MAX_IDLE_SECONDS))
        .map_err(|_| TransportError::Configuration)?;
    transport.max_idle_timeout(Some(idle));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::{TransportIdentity, build_runtime, pinned_client_config};
    use crate::ids::TransportKeyId;

    #[test]
    fn correct_pin_connects_and_wrong_pin_fails() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = build_runtime()?;
        runtime.block_on(async {
            let identity = TransportIdentity::generate()?;
            let server =
                quinn::Endpoint::server(identity.server_config()?, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
            let server_address = server.local_addr()?;
            let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
            client.set_default_client_config(pinned_client_config(identity.key_id())?);
            let accepting_server = server.clone();
            let accepted = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let incoming = accepting_server
                        .accept()
                        .await
                        .ok_or("server closed before accepting")?;
                    incoming.await.map_err(|error| error.to_string())
                })
                .await
                .map_err(|_| "server handshake timed out".to_owned())?
            });
            let connected = tokio::time::timeout(
                Duration::from_secs(5),
                client
                    .connect(server_address, "supgang.invalid")
                    .map_err(|error| error.to_string())?,
            );
            let client_connection = connected.await.map_err(|_| "client handshake timed out")??;
            let server_connection = accepted.await.map_err(|error| error.to_string())??;
            let mut notice_send = client_connection.open_uni().await?;
            notice_send.write_all(b"notice").await?;
            notice_send.finish()?;
            let mut notice_receive = server_connection.accept_uni().await?;
            let mut notice = [0_u8; 6];
            notice_receive.read_exact(&mut notice).await?;
            assert_eq!(&notice, b"notice");
            assert!(notice_send.stopped().await?.is_none());

            let mut wrong_client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
            wrong_client.set_default_client_config(pinned_client_config(TransportKeyId::from_bytes([0; 32]))?);
            let rejecting_server = server.clone();
            let wrong_accept = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let incoming = rejecting_server
                        .accept()
                        .await
                        .ok_or("server closed before rejecting")?;
                    let _result = incoming.await;
                    Ok::<(), String>(())
                })
                .await
                .map_err(|_| "server rejection timed out".to_owned())?
            });
            let wrong_connect = tokio::time::timeout(
                Duration::from_secs(5),
                wrong_client
                    .connect(server_address, "supgang.invalid")
                    .map_err(|error| error.to_string())?,
            );
            assert!(
                wrong_connect
                    .await
                    .map_err(|_| "wrong-pin handshake timed out")?
                    .is_err()
            );
            wrong_accept.await.map_err(|error| error.to_string())??;
            server.close(0_u8.into(), b"test complete");
            client.wait_idle().await;
            wrong_client.wait_idle().await;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
