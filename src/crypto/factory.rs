/// Signature verifier and signer factories.
///
/// Mirrors Python's `SignatureVerifierFactory` and `SignerFactory`:
///
/// ```python
/// class SignatureVerifierFactory:
///     def get_verifier(algorithm):
///         base = algorithm.split("-")[0]   # "Dilithium-2" → "Dilithium"
///         if base == "RSA":      return RSASignatureVerifier()
///         if base == "Dilithium": return DilithiumSignatureVerifier()
///         if base == "Ed25519":  return Ed25519SignatureVerifier()
/// ```
///
/// The full algorithm string (e.g. `"Dilithium-2"`) is accepted; only the
/// prefix before `-` is used to select the implementation. The security level
/// suffix is used separately by `resolve_alg_and_length` when slicing records.
use crate::crypto::dilithium::{DilithiumSignatureVerifier, DilithiumSigner};
use crate::crypto::ed25519::{Ed25519SignatureVerifier, Ed25519Signer};
use crate::crypto::rsa::{RSASignatureVerifier, RSASigner};
use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct SignatureVerifierFactory;
pub struct SignerFactory;

impl SignatureVerifierFactory {
    /// Return the correct `SignatureVerifier` for `algorithm`.
    ///
    /// Accepts strings like `"Dilithium-2"`, `"Dilithium-3"`, `"Ed25519"`,
    /// `"RSA"`. The part before `-` selects the implementation.
    pub fn get_verifier(algorithm: &str) -> Result<Box<dyn SignatureVerifier>, VerifierError> {
        let base = algorithm.split('-').next().unwrap_or("").trim();
        match base {
            "RSA"       => Ok(Box::new(RSASignatureVerifier)),
            "Ed25519"   => Ok(Box::new(Ed25519SignatureVerifier)),
            "Dilithium" => Ok(Box::new(DilithiumSignatureVerifier)),
            other       => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl SignerFactory {
    /// Return the correct `Signer` for `algorithm`.
    pub fn get_signer(algorithm: &str) -> Result<Box<dyn Signer>, VerifierError> {
        let base = algorithm.split('-').next().unwrap_or("").trim();
        match base {
            "RSA"       => Ok(Box::new(RSASigner)),
            "Ed25519"   => Ok(Box::new(Ed25519Signer)),
            "Dilithium" => Ok(Box::new(DilithiumSigner)),
            other       => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium2;

    #[test]
    fn factory_returns_dilithium_verifier() {
        // "Dilithium-2" prefix → DilithiumSignatureVerifier
        let verifier = SignatureVerifierFactory::get_verifier("Dilithium-2").unwrap();
        let (pk, sk) = dilithium2::keypair();
        let msg = b"factory test";
        let sig = dilithium2::detached_sign(msg, &sk);
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
        assert!(verifier.verify(pk.as_bytes(), sig.as_bytes(), msg).unwrap());
    }

    #[test]
    fn factory_returns_ed25519_verifier() {
        let verifier = SignatureVerifierFactory::get_verifier("Ed25519").unwrap();
        // Just check it constructs without error; full test in ed25519.rs
        let _ = verifier;
    }

    #[test]
    fn factory_unknown_algorithm_errors() {
        assert!(SignatureVerifierFactory::get_verifier("ECDSA").is_err());
        assert!(SignerFactory::get_signer("ECDSA").is_err());
    }

    #[test]
    fn signer_factory_dilithium() {
        let signer = SignerFactory::get_signer("Dilithium-2").unwrap();
        let (pk, sk) = dilithium2::keypair();
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        let msg = b"signer factory test";
        let sig = signer.sign(sk.as_bytes(), msg).unwrap();
        let verifier = SignatureVerifierFactory::get_verifier("Dilithium-2").unwrap();
        assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
    }
}
