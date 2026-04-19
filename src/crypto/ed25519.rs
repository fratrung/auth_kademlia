use ed25519_dalek::{Signature, VerifyingKey, Verifier, SigningKey};
use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct Ed25519SignatureVerifier;
pub struct Ed25519Signer;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
            VerifierError::InvalidKeyLength(public_key.len())
        })?;
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            VerifierError::VerificationFailed("Signature must be 64 bytes".to_string())
        })?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
        let sig = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        use ed25519_dalek::Signer as DalekSigner;

        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            VerifierError::InvalidKeyLength(private_key.len())
        })?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}
