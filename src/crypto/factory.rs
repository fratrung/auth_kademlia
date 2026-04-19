use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};
use crate::crypto::ed25519::{Ed25519SignatureVerifier, Ed25519Signer};
use crate::crypto::rsa::{RSASignatureVerifier, RSASigner};
use crate::crypto::dilithium::{DilithiumSignatureVerifier, DilithiumSigner};

pub struct SignatureVerifierFactory;
pub struct SignerFactory;

impl SignatureVerifierFactory {
    /// Restituisce il verifier corretto per l'algoritmo dato.
    /// Accetta stringhe come "Ed25519", "RSA", "Dilithium-3"
    pub fn get_verifier(algorithm: &str) -> Result<Box<dyn SignatureVerifier>, VerifierError> {
        let base = algorithm.split('-').next().unwrap_or("");
        match base {
            "RSA" => Ok(Box::new(RSASignatureVerifier)),
            "Ed25519" => Ok(Box::new(Ed25519SignatureVerifier)),
            "Dilithium" => Ok(Box::new(DilithiumSignatureVerifier)),
            other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl SignerFactory {
    pub fn get_signer(algorithm: &str) -> Result<Box<dyn Signer>, VerifierError> {
        let base = algorithm.split('-').next().unwrap_or("");
        match base {
            "RSA" => Ok(Box::new(RSASigner)),
            "Ed25519" => Ok(Box::new(Ed25519Signer)),
            "Dilithium" => Ok(Box::new(DilithiumSigner)),
            other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}
