/// Dilithium post-quantum signature verifier.
///
/// NOTA: la libreria `dilithium` pura in Rust non è ancora su crates.io con
/// un'API stabile. Le opzioni consigliate sono:
///   1. `pqcrypto-dilithium`  (bindings C via liboqs)
///   2. `oqs` crate (Open Quantum Safe)
///   3. Chiamare il codice Python via FFI/subprocess durante la transizione
///
/// Questo modulo usa l'approccio `oqs` come implementazione di riferimento.
/// Per attivarlo aggiungere in Cargo.toml:
///   oqs = { version = "0.9", features = ["dilithium2","dilithium3","dilithium5"] }
///
/// Per ora l'implementazione è uno stub che ritorna Err se non compilato
/// con la feature "dilithium_oqs".

use crate::crypto::signature_verifier::{SignatureVerifier, Signer, VerifierError};

pub struct DilithiumSignatureVerifier;
pub struct DilithiumSigner;

/// Determina il security level dalla lunghezza della chiave pubblica
/// Matches Python: {(1312, 2528): 2, (1952, 4000): 3, (2592, 4864): 5}
fn security_level_from_pub_key_len(len: usize) -> Option<u8> {
    match len {
        1312 => Some(2),
        1952 => Some(3),
        2592 => Some(5),
        _ => None,
    }
}

/// Determina il security level dalla lunghezza della chiave privata
fn security_level_from_priv_key_len(len: usize) -> Option<u8> {
    match len {
        2528 => Some(2),
        4000 => Some(3),
        4864 => Some(5),
        _ => None,
    }
}

impl SignatureVerifier for DilithiumSignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        _signature: &[u8],
        _message: &[u8],
    ) -> Result<bool, VerifierError> {
        let level = security_level_from_pub_key_len(public_key.len()).ok_or_else(|| {
            VerifierError::InvalidKeyLength(public_key.len())
        })?;

        #[cfg(feature = "dilithium_oqs")]
        {
            use oqs::sig::{Algorithm, Sig};
            let alg = match level {
                2 => Algorithm::Dilithium2,
                3 => Algorithm::Dilithium3,
                5 => Algorithm::Dilithium5,
                _ => unreachable!(),
            };
            let scheme = Sig::new(alg)
                .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
            let pk = scheme.public_key_from_bytes(public_key)
                .ok_or_else(|| VerifierError::VerificationFailed("Invalid public key".to_string()))?;
            let sig = scheme.signature_from_bytes(signature)
                .ok_or_else(|| VerifierError::VerificationFailed("Invalid signature".to_string()))?;
            return scheme.verify(message, sig, pk)
                .map(|_| true)
                .map_err(|e| VerifierError::VerificationFailed(e.to_string()));
        }

        #[cfg(not(feature = "dilithium_oqs"))]
        {
            log::warn!(
                "Dilithium{} verify called but feature 'dilithium_oqs' is not enabled. \
                 Add `oqs` crate to Cargo.toml to enable post-quantum verification.",
                level
            );
            Err(VerifierError::UnsupportedAlgorithm(
                "Dilithium requires feature 'dilithium_oqs'".to_string(),
            ))
        }
    }
}

impl Signer for DilithiumSigner {
    fn sign(&self, private_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let level = security_level_from_priv_key_len(private_key.len()).ok_or_else(|| {
            VerifierError::InvalidKeyLength(private_key.len())
        })?;

        #[cfg(feature = "dilithium_oqs")]
        {
            use oqs::sig::{Algorithm, Sig};
            let alg = match level {
                2 => Algorithm::Dilithium2,
                3 => Algorithm::Dilithium3,
                5 => Algorithm::Dilithium5,
                _ => unreachable!(),
            };
            let scheme = Sig::new(alg)
                .map_err(|e| VerifierError::VerificationFailed(e.to_string()))?;
            let sk = scheme.secret_key_from_bytes(private_key)
                .ok_or_else(|| VerifierError::VerificationFailed("Invalid secret key".to_string()))?;
            return scheme.sign(message, sk)
                .map(|s| s.into_vec())
                .map_err(|e| VerifierError::VerificationFailed(e.to_string()));
        }

        #[cfg(not(feature = "dilithium_oqs"))]
        {
            log::warn!(
                "Dilithium{} sign called but feature 'dilithium_oqs' is not enabled.",
                level
            );
            Err(VerifierError::UnsupportedAlgorithm(
                "Dilithium requires feature 'dilithium_oqs'".to_string(),
            ))
        }
    }
}
