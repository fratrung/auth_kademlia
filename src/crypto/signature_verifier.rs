use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Lunghezze delle firme per ogni algoritmo supportato.
/// Per Dilithium: security_level -> signature_length
/// Matches Python's SIGNATURE_ALG_LENGTHS
#[derive(Debug, Clone)]
pub enum AlgLength {
    Fixed(usize),
    Leveled(HashMap<u8, usize>), // security_level -> sig_length
}

pub fn signature_alg_lengths() -> HashMap<&'static str, AlgLength> {
    let mut map = HashMap::new();
    map.insert("RSA", AlgLength::Fixed(256));
    map.insert("Ed25519", AlgLength::Fixed(64));

    let mut dilithium_levels = HashMap::new();
    dilithium_levels.insert(2u8, 2420usize);
    dilithium_levels.insert(3u8, 3293usize);
    dilithium_levels.insert(5u8, 4595usize);
    map.insert("Dilithium", AlgLength::Leveled(dilithium_levels));

    map
}

/// Risolve l'algoritmo e la lunghezza della firma dalla stringa
/// Es: "Ed25519" -> ("Ed25519", 64)
/// Es: "Dilithium-3" -> ("Dilithium", 3293)
pub fn resolve_alg_and_length(algorithm_str: &str) -> Result<(String, usize), VerifierError> {
    let parts: Vec<&str> = algorithm_str.splitn(2, '-').collect();
    let alg = parts[0];
    let level: Option<u8> = parts.get(1).and_then(|s| s.parse().ok());

    let lengths = signature_alg_lengths();
    match lengths.get(alg) {
        None => Err(VerifierError::UnsupportedAlgorithm(alg.to_string())),
        Some(AlgLength::Fixed(len)) => Ok((alg.to_string(), *len)),
        Some(AlgLength::Leveled(map)) => {
            let lvl = level.ok_or_else(|| {
                VerifierError::UnsupportedAlgorithm(format!(
                    "{} requires a security level (e.g. Dilithium-3)",
                    alg
                ))
            })?;
            let len = map.get(&lvl).ok_or_else(|| {
                VerifierError::UnsupportedAlgorithm(format!(
                    "Unknown Dilithium level: {}",
                    lvl
                ))
            })?;
            Ok((alg.to_string(), *len))
        }
    }
}

/// Trait base per tutti i verifier
pub trait SignatureVerifier: Send + Sync {
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError>;
}

/// Trait base per tutti i signer
pub trait Signer: Send + Sync {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError>;
}

