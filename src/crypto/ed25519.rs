use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::Verifier as DalekVerifier;
/// Ed25519 signature verifier and signer.
///
/// Mirrors Python's `Ed25519SignatureVerifier` and `Ed25519Signer`:
///
/// ```python
/// class Ed25519SignatureVerifier:
///     def verify(public_key, message, signature):
///         pub_key = Ed25519PublicKey.from_public_bytes(public_key)
///         pub_key.verify(signature, message)   # raises InvalidSignature on failure
///         return True
///
/// class Ed25519Signer:
///     def sign(private_key, message):
///         priv_key = Ed25519PrivateKey.from_private_bytes(private_key)
///         return priv_key.sign(message)
/// ```
///
/// Public keys are 32 bytes; signatures are 64 bytes.
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct Ed25519SignatureVerifier;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        // Public key must be exactly 32 bytes.
        let key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| VerifierError::InvalidKeyLength(public_key.len()))?;

        // Signature must be exactly 64 bytes.
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
            VerifierError::VerificationFailed(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ))
        })?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;

        let sig = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

pub struct Ed25519Signer;

impl Signer for Ed25519Signer {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        // ed25519-dalek expects 32-byte seeds (the private scalar).
        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| VerifierError::InvalidKeyLength(private_key.len()))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = random_signing_key();
        let pk = sk.verifying_key();
        let msg = b"hello ed25519";

        let signer = Ed25519Signer;
        let sig = signer.sign(sk.as_bytes(), msg).unwrap();

        let verifier = Ed25519SignatureVerifier;
        assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let sk = random_signing_key();
        let pk = sk.verifying_key();

        let sig = Ed25519Signer.sign(sk.as_bytes(), b"original").unwrap();
        let verifier = Ed25519SignatureVerifier;
        assert!(!verifier.verify(pk.as_bytes(), &sig, b"tampered").unwrap());
    }

    #[test]
    fn wrong_pubkey_length_errors() {
        let verifier = Ed25519SignatureVerifier;
        assert!(verifier.verify(&[0u8; 31], &[0u8; 64], b"msg").is_err());
    }

    #[test]
    fn wrong_sig_length_errors() {
        let sk = random_signing_key();
        let pk = sk.verifying_key();
        let verifier = Ed25519SignatureVerifier;
        assert!(verifier.verify(pk.as_bytes(), &[0u8; 63], b"msg").is_err());
    }
}
