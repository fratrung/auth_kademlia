/// Base traits, error types, and algorithm registry for signature verification.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid key length: {0} bytes")]
    InvalidKeyLength(usize),

    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

/// Stateless signature verifier
pub trait SignatureVerifier: Send + Sync {
    /// Return `true` if `signature` over `message` is valid for `public_key`.
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError>;
}

pub trait Signer: Send + Sync {
    /// Sign `message` with `private_key` and return the raw signature bytes.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError>;
}

/// Resolve an algorithm string (e.g. `"Dilithium-3"`) into
/// `(base_algorithm_name, signature_byte_length)`.
pub fn resolve_alg_and_length(algorithm_str: &str) -> Result<(String, usize), VerifierError> {
    let mut parts = algorithm_str.splitn(2, '-');
    let alg = parts.next().unwrap_or("").trim();
    let level_str = parts.next(); // e.g. "2", "3", "5" for Dilithium

    match alg {
        "RSA" => Ok(("RSA".to_string(), 256)),
        "Ed25519" => Ok(("Ed25519".to_string(), 64)),
        "Dilithium" => {
            let level: u8 = level_str
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| {
                    VerifierError::UnsupportedAlgorithm(format!(
                        "Dilithium requires a security level suffix, e.g. 'Dilithium-2'. Got: '{}'",
                        algorithm_str
                    ))
                })?;
            let sig_len = match level {
                2 => 2420,
                3 => 3293,
                5 => 4595,
                _ => {
                    return Err(VerifierError::UnsupportedAlgorithm(format!(
                        "Unknown Dilithium security level: {}",
                        level
                    )))
                }
            };
            Ok(("Dilithium".to_string(), sig_len))
        }

        other => Err(VerifierError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Infer the Dilithium security level from the public key length.
pub fn dilithium_level_from_pubkey_len(len: usize) -> Option<u8> {
    match len {
        1312 => Some(2),
        1952 => Some(3),
        2592 => Some(5),
        _ => None,
    }
}

/// Infer the Dilithium security level from the private key length.
pub fn dilithium_level_from_privkey_len(len: usize) -> Option<u8> {
    match len {
        2560 => Some(2),
        4032 => Some(3),
        4896 => Some(5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rsa() {
        let (alg, len) = resolve_alg_and_length("RSA").unwrap();
        assert_eq!(alg, "RSA");
        assert_eq!(len, 256);
    }

    #[test]
    fn resolve_ed25519() {
        let (alg, len) = resolve_alg_and_length("Ed25519").unwrap();
        assert_eq!(alg, "Ed25519");
        assert_eq!(len, 64);
    }

    #[test]
    fn resolve_dilithium_levels() {
        assert_eq!(
            resolve_alg_and_length("Dilithium-2").unwrap(),
            ("Dilithium".into(), 2420)
        );
        assert_eq!(
            resolve_alg_and_length("Dilithium-3").unwrap(),
            ("Dilithium".into(), 3293)
        );
        assert_eq!(
            resolve_alg_and_length("Dilithium-5").unwrap(),
            ("Dilithium".into(), 4595)
        );
    }

    #[test]
    fn resolve_dilithium_no_level_errors() {
        assert!(resolve_alg_and_length("Dilithium").is_err());
    }

    #[test]
    fn resolve_unknown_errors() {
        assert!(resolve_alg_and_length("ECDSA").is_err());
    }

    #[test]
    fn pubkey_level_inference() {
        assert_eq!(dilithium_level_from_pubkey_len(1312), Some(2));
        assert_eq!(dilithium_level_from_pubkey_len(1952), Some(3));
        assert_eq!(dilithium_level_from_pubkey_len(2592), Some(5));
        assert_eq!(dilithium_level_from_pubkey_len(999), None);
    }
}
