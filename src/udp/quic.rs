use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;
use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use quinn::rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use quinn::rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use quinn::{rustls, ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::{CertificateParams, PKCS_ED25519};
use crate::udp::messages::PublicKey;

pub fn quinn_cert_from_key(signing_key: &SigningKey) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let pkcs8_bytes = signing_key.to_pkcs8_der()?;
    let priv_key_der = PrivateKeyDer::Pkcs8(pkcs8_bytes.as_bytes().into());

    let keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_bytes.as_bytes().into(), &PKCS_ED25519)?;
    let params = CertificateParams::new(vec!["reprise-p2p".to_string()])?;
    let cert = params.self_signed(&keypair)?;

    Ok((cert.der().clone(), priv_key_der.clone_key()))
}

pub async fn make_quin_endpoint(signing_key: &SigningKey, socket: std::net::UdpSocket, expected_pubkey: PublicKey) -> anyhow::Result<Endpoint> {
    let endpoint_config = EndpointConfig::default();
    let (cert, key) = quinn_cert_from_key(&signing_key)?;

    let expected_pubkey = VerifyingKey::from_bytes(&expected_pubkey)?;
    let verifier = Arc::new(PeerPublicKeyVerifier::new(expected_pubkey));

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    let rustls_server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(vec![cert.clone()], key.clone_key())?;

    let quic_server_config = QuicServerConfig::try_from(rustls_server_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport));

    let ep = Endpoint::new(endpoint_config, Some(server_config), socket, Arc::new(TokioRuntime))?;
    Ok(ep)
}

pub async fn establish_client_quic_connection(ep: Endpoint) -> anyhow::Result<Connection> {
    let incoming = ep.accept().await.context("Failed to accept QUIC connection")?;
    let con = incoming.await?;
    Ok(con)
}

pub async fn establish_server_quic_connection(
    mut ep: Endpoint,
    signing_key: &SigningKey,
    remote_addr: SocketAddrV4,
    remote_pubkey: PublicKey,
) -> anyhow::Result<Connection> {
    let expected_pubkey = VerifyingKey::from_bytes(&remote_pubkey)?;
    let verifier = Arc::new(PeerPublicKeyVerifier::new(expected_pubkey));

    let (cert, key) = quinn_cert_from_key(&signing_key)?;
    let rustls_client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)?;

    let quic_client_config = QuicClientConfig::try_from(rustls_client_config)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));

    ep.set_default_client_config(client_config);

    let connecting = ep.connect(remote_addr.into(), "reprise-p2p")?;
    let con = connecting.await?;
    Ok(con)
}

#[derive(Debug)]
pub struct PeerPublicKeyVerifier {
    expected_pubkey: VerifyingKey,
}

impl PeerPublicKeyVerifier {
    pub fn new(expected_pubkey: VerifyingKey) -> Self {
        Self { expected_pubkey }
    }
}

impl ServerCertVerifier for PeerPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, x509) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("Failed to parse X.509 cert".into()))?;

        let peer_pubkey_bytes = x509.tbs_certificate.subject_pki.subject_public_key.data;

        if peer_pubkey_bytes.as_ref() != self.expected_pubkey.as_bytes() {
            return Err(rustls::Error::General("Peer public key mismatch!".into()));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for PeerPublicKeyVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, x509) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("Failed to parse X.509 cert".into()))?;

        let peer_pubkey_bytes = x509.tbs_certificate.subject_pki.subject_public_key.data;

        if peer_pubkey_bytes.as_ref() != self.expected_pubkey.as_bytes() {
            return Err(rustls::Error::General("Peer public key mismatch!".into()));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
