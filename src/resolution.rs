use std::collections::HashSet;
use crate::error::DIDTDWError;
use crate::types::{DIDDocument, DIDLogEntry, DIDLog, Proof, DIDParameters};
use crate::did_tdw::TdwDid;
use crate::utils::{SHA2_256, verify_scid};
use crate::operations::DidOperations;
use reqwest::Client;
use serde_json::Value;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use base58::{ToBase58};
use multihash::Multihash;
pub struct DidResolver {
    client: Client,
    active_parameters: DIDParameters,
    processed_documents: Vec<(String, DateTime<Utc>, DIDDocument)>,
    current_version: u64,
    pre_rotation_active: bool,
    next_key_hashes: HashSet<String>,
    did_operations: DidOperations,
}
impl DidResolver {
    pub fn new(did_operations: DidOperations) -> Self {
        DidResolver {
            client: Client::new(),
            active_parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: None,
                update_keys: None,
                prerotation: None,
                next_key_hashes: None,
                portable: None,
                witness: None,
                deactivated: None,
                ttl: None,
            },
            processed_documents: Vec::new(),
            current_version: 0,
            pre_rotation_active: false,
            next_key_hashes: HashSet::new(),
            did_operations,
        }
    }

    async fn fetch_did_log(&self, url: &str) -> Result<DIDLog, DIDTDWError> {
        let response = self.client.get(url).send().await?;

        let log_content = response.text().await?;

        // Parse the log content into DIDLog
        // This is a simplified version; you might need to implement custom parsing
        let entries: Vec<DIDLogEntry> = log_content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(DIDLog { entries })
    }

    fn process_log_entry(&mut self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        self.update_parameters(&entry.parameters)?;
        self.verify_proof(entry)?;
        self.verify_version_id_and_hash(entry)?;
        self.check_version_time(entry)?;

        if self.current_version == 0 {
            self.verify_scid(entry)?;
        }

        self.handle_pre_rotation(entry)?;

        self.processed_documents.push((entry.version_id.clone(), entry.version_time, entry.state.clone()));
        self.current_version += 1;

        Ok(())
    }

    fn update_parameters(&mut self, new_params: &DIDParameters) -> Result<(), DIDTDWError> {
        // Method is not optional, so we always update it
        self.active_parameters.method = new_params.method.clone();

        if let Some(scid) = &new_params.scid {
            self.active_parameters.scid = Some(scid.clone());
        }

        if let Some(update_keys) = &new_params.update_keys {
            self.active_parameters.update_keys = Some(update_keys.clone());
        }

        if let Some(prerotation) = new_params.prerotation {
            self.active_parameters.prerotation = Some(prerotation);
            self.pre_rotation_active = prerotation;
        }

        if let Some(next_key_hashes) = &new_params.next_key_hashes {
            self.active_parameters.next_key_hashes = Some(next_key_hashes.clone());
            self.next_key_hashes = next_key_hashes.iter().cloned().collect();
        }

        if let Some(portable) = new_params.portable {
            self.active_parameters.portable = Some(portable);
        }

        if let Some(witness) = &new_params.witness {
            self.active_parameters.witness = Some(witness.clone());
        }

        if let Some(deactivated) = new_params.deactivated {
            self.active_parameters.deactivated = Some(deactivated);
        }

        if let Some(ttl) = new_params.ttl {
            self.active_parameters.ttl = Some(ttl);
        }

        Ok(())
    }

    fn verify_proof(&self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        match self.did_operations.verify_proof(entry) {
            Ok(true) => Ok(()),
            Ok(false) => Err(DIDTDWError::InvalidProof),
            Err(e) => Err(e),
        }
    }

    fn verify_version_id_and_hash(&self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        let parts: Vec<&str> = entry.version_id.split('-').collect();
        if parts.len() != 2 {
            return Err(DIDTDWError::InvalidVersionId);
        }

        let version_number = parts[0].parse::<u64>()
            .map_err(|_| DIDTDWError::InvalidVersionId)?;

        if version_number != self.current_version + 1 {
            return Err(DIDTDWError::InvalidVersionNumber);
        }

        let calculated_hash = self.did_operations.generate_entry_hash(entry)?;
        if calculated_hash != parts[1] {
            return Err(DIDTDWError::InvalidEntryHash);
        }

        Ok(())
    }

    fn check_version_time(&self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        if let Some(last_entry) = self.processed_documents.last() {
            if entry.version_time <= last_entry.1 {
                return Err(DIDTDWError::InvalidVersionTime);
            }
        }
        if entry.version_time > Utc::now() {
            return Err(DIDTDWError::FutureVersionTime);
        }
        Ok(())
    }

    fn verify_scid(&self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        let scid = self.active_parameters.scid
            .as_ref()
            .ok_or(DIDTDWError::MissingSCID)?;
        if !verify_scid(scid, entry)? {
            return Err(DIDTDWError::InvalidSCID);
        }
        Ok(())
    }

    fn handle_pre_rotation(&self, entry: &DIDLogEntry) -> Result<(), DIDTDWError> {
        if entry.parameters.prerotation.unwrap_or(false) {
            let current_update_keys = entry.parameters.update_keys
                .as_ref()
                .ok_or(DIDTDWError::InvalidLogEntry)?;
            let previous_next_key_hashes = self.active_parameters.next_key_hashes
                .as_ref()
                .ok_or(DIDTDWError::InvalidLogEntry)?;

            // Verify that all current update keys have their hashes in the previous nextKeyHashes
            for key in current_update_keys {
                let key_hash = self.hash_key(key)?;
                if !previous_next_key_hashes.contains(&key_hash) {
                    return Err(DIDTDWError::InvalidPreRotationKey);
                }
            }

            // Verify that a new nextKeyHashes is provided
            if entry.parameters.next_key_hashes.is_none() {
                return Err(DIDTDWError::MissingNextKeyHashes);
            }
        }

        Ok(())
    }

    fn hash_key(&self, key_jwk: &str) -> Result<String, DIDTDWError> {
        let hash = Sha256::digest(key_jwk.as_bytes());
        let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
            .map_err(|e| DIDTDWError::MultihashError(e.to_string()))?;
        Ok(multihash.to_bytes().to_base58())
    }

    pub fn get_did_document(&self, version_id: Option<&str>, version_time: Option<DateTime<Utc>>) -> Result<DIDDocument, DIDTDWError> {
        if let Some(vid) = version_id {
            self.processed_documents.iter()
                .find(|(id, _, _)| id == vid)
                .map(|(_, _, doc)| doc.clone())
                .ok_or(DIDTDWError::VersionNotFound)
        } else if let Some(vtime) = version_time {
            self.processed_documents.iter()
                .rev()
                .find(|(_, time, _)| time <= &vtime)
                .map(|(_, _, doc)| doc.clone())
                .ok_or(DIDTDWError::VersionNotFound)
        } else {
            self.processed_documents.last()
                .map(|(_, _, doc)| doc.clone())
                .ok_or(DIDTDWError::NoDocumentFound)
        }
    }
}

pub async fn resolve_did(did: &str, version_id: Option<&str>, version_time: Option<DateTime<Utc>>) -> Result<DIDDocument, DIDTDWError> {
    let tdw_did = TdwDid::parse_and_validate_tdw_did(did)?;
    let url = tdw_did.to_url()?;

    // Create a Client for HTTP requests
    let client = Client::new();

    // Create a Store for key management (you'll need to implement this)
    let store = create_store()?;

    // Create DidOperations instance
    let did_operations = DidOperations::new(store, client.clone());

    // Create DidResolver instance
    let mut resolver = DidResolver::new(did_operations);

    let did_log = resolver.fetch_did_log(url.as_str()).await?;

    for entry in did_log.entries {
        resolver.process_log_entry(&entry)?;
    }

    resolver.get_did_document(version_id, version_time)
}


fn create_store() -> Result<aries_askar::Store, DIDTDWError> {
    // ToDO: Implement this function

    unimplemented!("Store creation not implemented")
}