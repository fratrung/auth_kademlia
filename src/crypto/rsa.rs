/// RSA-PKCS1v15-SHA256 signature verifier and signer.
///
/// Mirrors Python's `RSASignatureVerifier` and `RSASigner` using PyCryptodome:
///
/// ```python
/// class RSASignatureVerifier:
///     def verify(public_key, signature, message):
///         rsa_key = RSA.import_key(public_key)   # accepts DER or PEM
///         h = SHA256.new(message)
///         pkcs1_15.new(rsa_key).verify(h, signature)
///         return True
///
/// class RSASigner:
///     def sign(private_key, message):
///         rsa_key = RSA.import_key(private_key)
///         h = SHA256.new(message)
///         return pkcs1_15.new(rsa_key).sign(h)
/// ```
///
/// Both DER (PKCS#8) and PEM key formats are accepted, matching Python's
/// `RSA.import_key()` which handles both transparently.
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

// ─────────────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────────────

pub struct RSASignatureVerifier;

impl SignatureVerifier for RSASignatureVerifier {
    /// Verify an RSA-PKCS1v15-SHA256 signature.
    ///
    /// `public_key` may be DER-encoded (PKCS#8 SubjectPublicKeyInfo) or
    /// PEM-encoded — matching Python's `RSA.import_key()` behaviour.
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        let rsa_pub = load_public_key(public_key)?;
        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(rsa_pub);
        let sig = Signature::try_from(signature)
            .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

/// Load an RSA public key from DER or PEM bytes.
fn load_public_key(key: &[u8]) -> Result<RsaPublicKey, VerifierError> {
    // Try DER first (most common in automated systems).
    if let Ok(pk) = RsaPublicKey::from_public_key_der(key) {
        return Ok(pk);
    }
    // Fall back to PEM.
    let pem =
        std::str::from_utf8(key).map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
    RsaPublicKey::from_public_key_pem(pem)
        .map_err(|e| VerifierError::VerificationFailed(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer
// ─────────────────────────────────────────────────────────────────────────────

pub struct RSASigner;

impl Signer for RSASigner {
    /// Sign `message` with an RSA private key (PKCS1v15, SHA-256).
    ///
    /// `private_key` may be DER-encoded (PKCS#8) or PEM-encoded.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let rsa_priv = load_private_key(private_key)?;
        let signing_key: SigningKey<Sha256> = SigningKey::new(rsa_priv);
        let mut rng = rand::thread_rng();
        let sig = signing_key.sign_with_rng(&mut rng, message);
        Ok(sig.to_bytes().to_vec())
    }
}

/// Load an RSA private key from DER or PEM bytes.
fn load_private_key(key: &[u8]) -> Result<RsaPrivateKey, VerifierError> {
    if let Ok(pk) = RsaPrivateKey::from_pkcs8_der(key) {
        return Ok(pk);
    }
    let pem =
        std::str::from_utf8(key).map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
    RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| VerifierError::VerificationFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    fn generate_rsa_keypair_der() -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let priv_der = priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let pub_der = pub_key.to_public_key_der().unwrap().as_bytes().to_vec();
        (pub_der, priv_der)
    }

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let (pub_der, priv_der) = generate_rsa_keypair_der();
        let msg = b"hello rsa";
        let signer = RSASigner;
        let sig = signer.sign(&priv_der, msg).unwrap();
        let verifier = RSASignatureVerifier;
        assert!(verifier.verify(&pub_der, &sig, msg).unwrap());
    }

    #[test]
    fn rsa_tampered_message_fails() {
        let (pub_der, priv_der) = generate_rsa_keypair_der();
        let sig = RSASigner.sign(&priv_der, b"original").unwrap();
        let verifier = RSASignatureVerifier;
        assert!(!verifier.verify(&pub_der, &sig, b"tampered").unwrap());
    }
}
