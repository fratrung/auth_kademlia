use rsa::{RsaPublicKey, RsaPrivateKey, pkcs8::DecodePublicKey, pkcs8::DecodePrivateKey};
use rsa::pkcs1v15::{Signature, VerifyingKey, SigningKey};
use rsa::signature::{Verifier, RandomizedSigner};
use sha2::Sha256;
use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct RSASignatureVerifier;
pub struct RSASigner;

impl SignatureVerifier for RSASignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        // Prova prima DER (PKCS#8), poi PEM come fallback
        let rsa_pub = match RsaPublicKey::from_public_key_der(public_key) {
            Ok(key) => key,
            Err(_) => {
                // Try PEM format
                let pem_str = std::str::from_utf8(public_key)
                    .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
                RsaPublicKey::from_public_key_pem(pem_str)
                    .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?
            }
        };

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(rsa_pub);
        let sig = Signature::try_from(signature)
            .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;

        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

impl Signer for RSASigner {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        use rsa::signature::SignatureEncoding;

        let rsa_priv = RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
        let signing_key: SigningKey<Sha256> = SigningKey::new(rsa_priv);
        let mut rng = rand::thread_rng();
        let sig = signing_key.sign_with_rng(&mut rng, message);
        Ok(sig.to_bytes().to_vec())
    }
}
