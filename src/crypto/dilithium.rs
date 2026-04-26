/// Dilithium post-quantum signature verifier and signer.
///
/// Mirrors Python's `DilithiumSignatureVerifier` and `DilithiumSigner`:
///
/// ```python
/// LENGTH_SECURITY_LEVEL = { (1312, 2560): 2, (1952, 4032): 3, (2592, 4896): 5 }
///
/// class DilithiumSignatureVerifier:
///     def verify(public_key, signature, message):
///         level = infer from len(public_key)
///         return DilithiumN.verify(public_key, message, signature)
///
/// class DilithiumSigner:
///     def sign(private_key, message):
///         level = infer from len(private_key)
///         return DilithiumN.sign(private_key, message)
/// ```
///
/// Security level is inferred automatically from the key length,
/// exactly as in the Python implementation.
/// 
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
};

use crate::crypto::signature_verifier::{
    dilithium_level_from_privkey_len, dilithium_level_from_pubkey_len, Signer,
    SignatureVerifier, VerifierError,
};

pub struct DilithiumSignatureVerifier;

impl SignatureVerifier for DilithiumSignatureVerifier {
    /// Verify a Dilithium detached signature.
    ///
    /// The security level is inferred from `public_key.len()`:
    /// - 1312 bytes → Dilithium2
    /// - 1952 bytes → Dilithium3
    /// - 2592 bytes → Dilithium5
    fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, VerifierError> {
        let level = dilithium_level_from_pubkey_len(public_key.len())
            .ok_or(VerifierError::InvalidKeyLength(public_key.len()))?;

        match level {
            2 => verify_d2(public_key, signature, message),
            3 => verify_d3(public_key, signature, message),
            5 => verify_d5(public_key, signature, message),
            _ => unreachable!(),
        }
    }
}

fn verify_d2(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<bool, VerifierError> {
    let pk = dilithium2::PublicKey::from_bytes(pk)
        .map_err(|_| VerifierError::InvalidKeyLength(pk.len()))?;
    let sig = dilithium2::DetachedSignature::from_bytes(sig)
        .map_err(|_| VerifierError::VerificationFailed("invalid signature bytes".into()))?;
    Ok(dilithium2::verify_detached_signature(&sig, msg, &pk).is_ok())
}

fn verify_d3(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<bool, VerifierError> {
    let pk = dilithium3::PublicKey::from_bytes(pk)
        .map_err(|_| VerifierError::InvalidKeyLength(pk.len()))?;
    let sig = dilithium3::DetachedSignature::from_bytes(sig)
        .map_err(|_| VerifierError::VerificationFailed("invalid signature bytes".into()))?;
    Ok(dilithium3::verify_detached_signature(&sig, msg, &pk).is_ok())
}

fn verify_d5(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<bool, VerifierError> {
    let pk = dilithium5::PublicKey::from_bytes(pk)
        .map_err(|_| VerifierError::InvalidKeyLength(pk.len()))?;
    let sig = dilithium5::DetachedSignature::from_bytes(sig)
        .map_err(|_| VerifierError::VerificationFailed("invalid signature bytes".into()))?;
    Ok(dilithium5::verify_detached_signature(&sig, msg, &pk).is_ok())
}

pub struct DilithiumSigner;

impl Signer for DilithiumSigner {
    /// Sign `message` with a Dilithium private key.
    ///
    /// The security level is inferred from `private_key.len()`:
    /// - 2560 bytes → Dilithium2
    /// - 4032 bytes → Dilithium3
    /// - 4896 bytes → Dilithium5
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let level = dilithium_level_from_privkey_len(private_key.len())
            .ok_or(VerifierError::InvalidKeyLength(private_key.len()))?;

        match level {
            2 => sign_d2(private_key, message),
            3 => sign_d3(private_key, message),
            5 => sign_d5(private_key, message),
            _ => unreachable!(),
        }
    }
}

fn sign_d2(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, VerifierError> {
    let sk = dilithium2::SecretKey::from_bytes(sk)
        .map_err(|_| VerifierError::InvalidKeyLength(sk.len()))?;
    Ok(dilithium2::detached_sign(msg, &sk).as_bytes().to_vec())
}

fn sign_d3(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, VerifierError> {
    let sk = dilithium3::SecretKey::from_bytes(sk)
        .map_err(|_| VerifierError::InvalidKeyLength(sk.len()))?;
    Ok(dilithium3::detached_sign(msg, &sk).as_bytes().to_vec())
}

fn sign_d5(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, VerifierError> {
    let sk = dilithium5::SecretKey::from_bytes(sk)
        .map_err(|_| VerifierError::InvalidKeyLength(sk.len()))?;
    Ok(dilithium5::detached_sign(msg, &sk).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dilithium2_sign_verify_roundtrip() {
        let (pk, sk) = dilithium2::keypair();
        let msg = b"test message for dilithium2";
        let signer = DilithiumSigner;
        let sig = signer.sign(sk.as_bytes(), msg).unwrap();
        let verifier = DilithiumSignatureVerifier;
        assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
    }

    #[test]
    fn dilithium3_sign_verify_roundtrip() {
        let (pk, sk) = dilithium3::keypair();
        let msg = b"test message for dilithium3";
        let signer = DilithiumSigner;
        let sig = signer.sign(sk.as_bytes(), msg).unwrap();
        let verifier = DilithiumSignatureVerifier;
        assert!(verifier.verify(pk.as_bytes(), &sig, msg).unwrap());
    }

    #[test]
    fn dilithium2_tampered_message_fails() {
        let (pk, sk) = dilithium2::keypair();
        let sig = DilithiumSigner.sign(sk.as_bytes(), b"original").unwrap();
        let verifier = DilithiumSignatureVerifier;
        assert!(!verifier.verify(pk.as_bytes(), &sig, b"tampered").unwrap());
    }

    #[test]
    fn wrong_key_length_errors() {
        let verifier = DilithiumSignatureVerifier;
        assert!(verifier.verify(&[0u8; 100], &[0u8; 2420], b"msg").is_err());
    }
}
