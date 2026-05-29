use ed25519_dalek::VerifyingKey;
use quinn::rustls;
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use quinn::rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use quinn::rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

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

    // --- Дальше идет стандартный бойлерплейт для делегирования проверки подписи ---

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

    // Та самая проверка сертификата клиента сервером
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

    // --- Бойлерплейт проверки подписей (полностью копируем из ServerCertVerifier) ---

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
