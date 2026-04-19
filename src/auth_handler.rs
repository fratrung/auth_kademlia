use std::path::PathBuf;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde_json::Value;
use thiserror::Error;

use crate::crypto::factory::SignatureVerifierFactory;
use crate::crypto::signature_verifier::{resolve_alg_and_length, VerifierError};

#[derive(Debug, Error)]
pub enum AuthHandlerError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] VerifierError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Missing field: {0}")]
    MissingField(String),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Invalid value format")]
    InvalidFormat,
}

/// Corrisponde a SignatureVerifierHandler (Python) — trait astratto
pub trait SignatureVerifierHandler: Send + Sync {
    fn handle_signature_verification(&self, value: &[u8]) -> Result<bool, AuthHandlerError>;
    fn handle_update_verification(
        &self,
        value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError>;
    fn handle_signature_delete_operation(
        &self,
        value: &[u8],
        auth_signature: &[u8],
        delete_msg: &[u8],
    ) -> Result<bool, AuthHandlerError>;
    fn handle_issuer_node_signature_verification(
        &self,
        value: &[u8],
    ) -> Result<bool, AuthHandlerError>;
}

// ---------------------------------------------------------------------------
// Helpers condivisi (equivale ai metodi privati di DIDSignatureVerifierHandler)
// ---------------------------------------------------------------------------

/// Estrae la stringa algoritmo dai primi 12 byte (null-padded)
fn get_alg_string(value: &[u8]) -> Result<String, AuthHandlerError> {
    if value.len() < 12 {
        return Err(AuthHandlerError::InvalidFormat);
    }
    let raw = &value[..12];
    let trimmed = raw.iter().position(|&b| b == 0).map_or(raw, |i| &raw[..i]);
    Ok(std::str::from_utf8(trimmed)?.to_string())
}

/// Divide il valore in (signature, data) dato l'offset dell'algoritmo
fn extract_data(value: &[u8], sig_length: usize) -> Result<(&[u8], &[u8]), AuthHandlerError> {
    let sig_start = 12;
    let data_start = sig_start + sig_length;
    if value.len() < data_start {
        return Err(AuthHandlerError::InvalidFormat);
    }
    Ok((&value[sig_start..data_start], &value[data_start..]))
}

/// Decodifica base64url con padding automatico
fn decode_b64(key: &str) -> Result<Vec<u8>, AuthHandlerError> {
    let padding = (4 - key.len() % 4) % 4;
    let padded = format!("{}{}", key, "=".repeat(padding));
    Ok(URL_SAFE.decode(padded)?)
}

/// Estrae la chiave pubblica dal DID Document JSON
fn public_key_from_did_doc(data: &[u8]) -> Result<Vec<u8>, AuthHandlerError> {
    let doc: Value = serde_json::from_slice(data)?;
    let x = doc["verificationMethod"][0]["publicKeyJwk"]["x"]
        .as_str()
        .ok_or_else(|| AuthHandlerError::MissingField("publicKeyJwk.x".to_string()))?;
    decode_b64(x)
}

// ---------------------------------------------------------------------------
// DIDSignatureVerifierHandler
// ---------------------------------------------------------------------------

pub struct DIDSignatureVerifierHandler {
    /// Percorso alla chiave pubblica dell'issuer node (hardcoded nel Python originale)
    issuer_pub_key_path: PathBuf,
}

impl DIDSignatureVerifierHandler {
    pub fn new(issuer_pub_key_path: PathBuf) -> Self {
        Self { issuer_pub_key_path }
    }

    /// Carica la chiave pubblica dilithium dell'issuer node da file
    fn load_issuer_node_public_key(&self) -> Result<Vec<u8>, AuthHandlerError> {
        Ok(std::fs::read(&self.issuer_pub_key_path)?)
    }

    /// Verifica la firma sul valore con la chiave pubblica estratta dal DID Document
    fn verify_self_signed(&self, value: &[u8]) -> Result<bool, AuthHandlerError> {
        let alg_str = get_alg_string(value)?;
        let (_alg, sig_len) = resolve_alg_and_length(&alg_str)?;
        let (signature, data) = extract_data(value, sig_len)?;
        let pub_key = public_key_from_did_doc(data)?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg_str)?;
        Ok(verifier.verify(&pub_key, signature, data)?)
    }

    /// Key rotation: verifica che il nuovo valore sia firmato con la vecchia chiave,
    /// poi verifica la firma intrinseca del nuovo valore.
    fn handle_key_rotation(
        &self,
        value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        // Estrai chiave pubblica dal vecchio DID Document
        let old_alg_str = get_alg_string(old_value)?;
        let (_old_alg, old_sig_len) = resolve_alg_and_length(&old_alg_str)?;
        let (_old_sig, old_data) = extract_data(old_value, old_sig_len)?;
        let old_pub_key = public_key_from_did_doc(old_data)?;

        // Verifica che auth_signature sul nuovo value sia valida con la vecchia chiave
        let verifier = SignatureVerifierFactory::get_verifier(&old_alg_str)?;
        let is_auth_valid = verifier.verify(&old_pub_key, auth_signature, value)?;
        if !is_auth_valid {
            return Ok(false);
        }

        // Verifica la firma intrinseca del nuovo valore
        self.verify_self_signed(value)
    }
}

impl SignatureVerifierHandler for DIDSignatureVerifierHandler {
    /// Verifica che il valore sia firmato dalla chiave pubblica nel DID Document embedded.
    fn handle_signature_verification(&self, value: &[u8]) -> Result<bool, AuthHandlerError> {
        self.verify_self_signed(value)
    }

    /// Verifica un update (key rotation): la nuova versione deve essere firmata
    /// con la chiave privata corrispondente alla chiave pubblica nel DID Document corrente.
    fn handle_update_verification(
        &self,
        value: &[u8],
        old_value: &[u8],
        auth_signature: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        self.handle_key_rotation(value, old_value, auth_signature)
    }

    /// Verifica l'operazione di delete: auth_signature sul delete_msg
    /// deve essere valida con la chiave pubblica nel DID Document.
    fn handle_signature_delete_operation(
        &self,
        value: &[u8],
        auth_signature: &[u8],
        delete_msg: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        let alg_str = get_alg_string(value)?;
        let (_alg, sig_len) = resolve_alg_and_length(&alg_str)?;
        let (_signature, data) = extract_data(value, sig_len)?;
        let pub_key = public_key_from_did_doc(data)?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg_str)?;
        Ok(verifier.verify(&pub_key, auth_signature, delete_msg)?)
    }

    /// Verifica che il valore sia firmato dalla chiave pubblica dell'issuer node.
    fn handle_issuer_node_signature_verification(
        &self,
        value: &[u8],
    ) -> Result<bool, AuthHandlerError> {
        let alg_str = get_alg_string(value)?;
        let (_alg, sig_len) = resolve_alg_and_length(&alg_str)?;
        let (signature, data) = extract_data(value, sig_len)?;
        let issuer_pub_key = self.load_issuer_node_public_key()?;
        let verifier = SignatureVerifierFactory::get_verifier(&alg_str)?;
        Ok(verifier.verify(&issuer_pub_key, signature, data)?)
    }
}
