use crate::error::DIDTDWError;
use crate::types::{DIDLogEntry, Proof, ProofPurpose,DIDParameters};
use crate::utils::{calculate_entry_hash, SHA2_256};
use base58::{ToBase58, FromBase58};
use chrono::Utc;
use serde_json::json;
use serde_json_canonicalizer::to_string as jcs_canonicalize;
use reqwest::Client;
use multihash::Multihash;
use sha2::{Sha256, Digest};
use crate::did_tdw::TdwDid;
use crate::{generate_scid, DIDDocument};
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::{Store, StoreKeyMethod, PassKey};

pub struct DidOperations {
    store: Store,
    client: Client,
}

impl DidOperations {
    pub fn new(store: Store, client: Client) -> Self {
        DidOperations {
            store,
            client,
        }
    }
    pub fn generate_proof(&self, entry: &DIDLogEntry, key: &LocalKey) -> Result<Proof, DIDTDWError> {
        let mut entry_without_proof = entry.clone();
        entry_without_proof.proof = vec![];

        let canonical_json = serde_json_canonicalizer::to_string(&entry_without_proof)
            .map_err(|e| DIDTDWError::JCSCanonalizationError(e.to_string()))?;

        let signature = key.sign_message(canonical_json.as_bytes(), None)
            .map_err(|e| DIDTDWError::KeyManagementError(e.to_string()))?;

        Ok(Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            verification_method: key.to_jwk_public(None)?,
            proof_purpose: ProofPurpose::Authentication,
            proof_value: signature.to_base58(),
            challenge: None,
        })
    }

    pub fn verify_proof(&self, entry: &DIDLogEntry) -> Result<bool, DIDTDWError> {
        // Remove the proof field for canonicalization
        let mut entry_without_proof = entry.clone();
        entry_without_proof.proof = vec![];

        // Canonicalize the entry
        let canonical_json = jcs_canonicalize(&entry_without_proof)
            .map_err(|e| DIDTDWError::JCSCanonalizationError(e.to_string()))?;

        // TODO: Implement actual signature verification logic here
        // For now, we'll just return true as a placeholder
        Ok(true)
    }
    fn generate_placeholder_proof(&self, challenge: &str) -> Proof {
        Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            verification_method: "did:example:123#key-1".to_string(), // Placeholder
            proof_purpose: ProofPurpose::Authentication,
            proof_value: "z3yLZXgQzBGyj1YGrBQLwQJ8C4Sp4S9PcTQmzstxcnjBjkMr2NkGnF1H2x9bP5wDzh3d9oGSuJ6WdCxwVEA9Tic1y".to_string(), // Placeholder
            challenge: Some(challenge.to_string()),
        }
    }

    pub fn generate_entry_hash(&self, entry: &DIDLogEntry) -> Result<String, DIDTDWError> {
        calculate_entry_hash(entry)
    }
    pub async fn create_did(&self, domain: String, enable_pre_rotation: bool) -> Result<(TdwDid, DIDLogEntry), DIDTDWError> {
        // Generate the main key pair
        let main_key = LocalKey::generate(KeyAlg::Ed25519, false)
            .map_err(|e| DIDTDWError::KeyManagementError(e.to_string()))?;

        // Create initial DIDDocument with a placeholder DID
        let initial_doc = DIDDocument::new(&format!("did:tdw:{{SCID}}:{}", domain));

        // Prepare parameters
        let mut params = DIDParameters {
            method: "did:tdw:0.4".to_string(),
            scid: None,
            update_keys: Some(vec![main_key.to_jwk_public(Some(KeyAlg::Ed25519))?]),
            prerotation: Some(enable_pre_rotation),
            next_key_hashes: None,
            portable: None,
            witness: None,
            deactivated: None,
            ttl: None,
        };

        if enable_pre_rotation {
            let (next_key_hash, _) = self.generate_pre_rotation_key(KeyAlg::Ed25519).await?;
            params.next_key_hashes = Some(vec![next_key_hash]);
        }

        // Create a preliminary proof for SCID generation
        let preliminary_proof = self.generate_proof(&DIDLogEntry {
            version_id: "{SCID}".to_string(),
            version_time: Utc::now(),
            parameters: params.clone(),
            state: initial_doc.clone(),
            proof: vec![],
        }, &main_key)?;

        // Create a preliminary log entry for SCID generation
        let preliminary_entry = DIDLogEntry {
            version_id: "{SCID}".to_string(),
            version_time: Utc::now(),
            parameters: params.clone(),
            state: initial_doc,
            proof: vec![preliminary_proof],
        };

        // Generate SCID
        let scid = generate_scid(&preliminary_entry)?;

        // Create TdwDid
        let did = TdwDid::new(scid.clone(), domain, None, None);

        // Update SCID in parameters
        params.scid = Some(scid.clone());

        // Create final DIDDocument with the actual DID
        let document = DIDDocument::new(&did.to_string());

        // Generate the entry hash for the version ID
        let entry_hash = self.generate_entry_hash(&preliminary_entry)?;
        let version_id = format!("1-{}", entry_hash);

        // Create final proof
        let final_proof = self.generate_proof(&DIDLogEntry {
            version_id: version_id.clone(),
            version_time: Utc::now(),
            parameters: params.clone(),
            state: document.clone(),
            proof: vec![],
        }, &main_key)?;

        // Create final log entry
        let log_entry = DIDLogEntry {
            version_id,
            version_time: Utc::now(),
            parameters: params,
            state: document,
            proof: vec![final_proof],
        };

        Ok((did, log_entry))
    }

    async fn generate_pre_rotation_key(&self, key_alg: KeyAlg) -> Result<(String, String), DIDTDWError> {
        let next_key = LocalKey::generate(key_alg, false)?;

        let public_key_jwk = next_key.to_jwk_public(Some(key_alg))?;

        let key_hash = self.hash_key(&public_key_jwk)?;

        // Store the key securely
        let key_name = format!("prerotation_{}", Utc::now().timestamp());
        let mut session = self.store.session(None).await?;
        session.insert_key(&key_name, &next_key, None, None, None).await?;

        Ok((key_hash, key_name))
    }

    fn hash_key(&self, key_jwk: &str) -> Result<String, DIDTDWError> {
        let hash = Sha256::digest(key_jwk.as_bytes());
        let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
            .map_err(|e| DIDTDWError::MultihashError(e.to_string()))?;
        Ok(multihash.to_bytes().to_base58())
    }

}

