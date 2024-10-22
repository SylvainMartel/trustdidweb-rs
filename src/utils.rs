use crate::error::DIDTDWError;
use crate::types::{DIDDocument, DIDLogEntry};
use base58::{ToBase58, FromBase58};
use serde::de::Error;
use sha2::{Sha256, Digest};
use serde_json::json;
use serde_json_canonicalizer::to_string as jcs_canonicalize;
use multihash::Multihash;

const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SHA2_256: u64 = 0x12;
pub fn generate_scid(entry: &DIDLogEntry) -> Result<String, DIDTDWError> {
    // Create a copy of the entry with the SCID placeholder
    let mut entry_copy = entry.clone();
    entry_copy.version_id = "{SCID}".to_string();
    entry_copy.parameters.scid = Some("{SCID}".to_string());

    // Serialize the entry to JSON, excluding the proof
    let entry_json = serde_json::json!({
        "versionId": entry_copy.version_id,
        "versionTime": entry_copy.version_time.to_rfc3339(),
        "parameters": entry_copy.parameters,
        "state": entry_copy.state,
    });

    // Canonicalize the JSON
    let canonical_json = jcs_canonicalize(&entry_json)
        .map_err(|e| DIDTDWError::SerializationError(serde_json::Error::custom(e)))?;

    // Calculate the SHA-256 hash
    let hash = Sha256::digest(canonical_json.as_bytes());

    // Create a multihash from the SHA-256 hash
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|e| DIDTDWError::MultihashError(e.to_string()))?;

    // Encode the multihash using base58btc
    Ok(multihash.to_bytes().to_base58())
}

pub fn calculate_entry_hash(entry: &DIDLogEntry) -> Result<String, DIDTDWError> {
    // Create a copy of the entry without the proof
    let entry_without_proof = DIDLogEntry {
        version_id: entry.version_id.clone(),
        version_time: entry.version_time,
        parameters: entry.parameters.clone(),
        state: entry.state.clone(),
        proof: vec![],
    };

    // Canonicalize the JSON
    let canonical_json = jcs_canonicalize(&entry_without_proof)
        .map_err(|e| DIDTDWError::JCSCanonalizationError(e.to_string()))?;

    // Calculate the SHA-256 hash
    let hash = Sha256::digest(canonical_json.as_bytes());

    // Create a multihash
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|e| DIDTDWError::MultihashError(e.to_string()))?;

    // Encode the multihash using base58btc
    Ok(multihash.to_bytes().to_base58())
}
fn replace_scid_in_diddoc(doc: &mut DIDDocument, placeholder: &str) {
    doc.id = doc.id.replace(SCID_PLACEHOLDER, placeholder);

}

pub fn verify_scid(scid: &str, entry: &DIDLogEntry) -> Result<bool, DIDTDWError> {
    // 1. Generate the SCID from the provided entry
    let generated_scid = generate_scid(entry)?;

    // 2. Compare the generated SCID with the provided SCID
    Ok(scid == generated_scid)
}

pub fn generate_key_hash(public_key: &str) -> Result<String, DIDTDWError> {
    let hash = Sha256::digest(public_key.as_bytes());
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash).map_err(|e| DIDTDWError::MultihashError(e.to_string()))?;
    Ok(multihash.to_bytes().to_base58())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DIDLogEntry, DIDDocument, Proof, ProofPurpose, DIDParameters};
    use chrono::Utc;

    fn create_sample_entry() -> DIDLogEntry {
        DIDLogEntry {
            version_id: "1-QmQq6Kg4ZZ1p49znzxnWmes4LkkWgMWLrnrfPre8UD56bz".to_string(),
            version_time: Utc::now(),
            parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: Some("QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ".to_string()),
                update_keys: Some(vec![
                    "z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string()
                ]),
                prerotation: Some(true),
                next_key_hashes: Some(vec![
                    "QmXC3vvStVVzCBHRHGUsksGxn6BNmkdETXJGDBXwNSTL33".to_string()
                ]),
                portable: None,
                witness: None,
                deactivated: None,
                ttl: None,
            },
            state: DIDDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_string()],
                id: "did:tdw:QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ:domain.example".to_string(),
                verification_method: None,
                authentication: None,
                assertion_method: None,
                service: None,
                deactivated: None,
                also_known_as: None,
            },
            proof: vec![Proof {
                proof_type: "DataIntegrityProof".to_string(),
                created: Utc::now(),
                verification_method: "did:key:z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R#z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R".to_string(),
                proof_purpose: ProofPurpose::Authentication,
                proof_value: "z2fPF6fMewtV15kji2N432R7RjmmFs8p7MiSHSTM9FoVmJPtc3JUuZ472pZKoWgZDuT75EDwkGmZbK8ZKVF55pXvx".to_string(),
                challenge: None,
            }],
        }
    }



    #[test]
    fn test_calculate_entry_hash_consistency() {
        let sample_entry = create_sample_entry();

        // Generate hash twice for same input
        let first_hash = calculate_entry_hash(&sample_entry).unwrap();
        let second_hash = calculate_entry_hash(&sample_entry).unwrap();

        // Verify hashes are identical
        assert_eq!(first_hash, second_hash, "Hash should be deterministic");
    }

    #[test]
    fn test_calculate_entry_hash_proof_independence() {
        let mut first_entry = create_sample_entry();
        let mut second_entry = create_sample_entry();

        // Modify proof in second entry
        second_entry.proof[0].proof_value = "different_proof_value".to_string();

        // Generate hashes
        let first_hash = calculate_entry_hash(&first_entry).unwrap();
        let second_hash = calculate_entry_hash(&second_entry).unwrap();

        // Verify hashes are identical despite different proofs
        assert_eq!(first_hash, second_hash, "Hash should be independent of proof field");
    }

    #[test]
    fn test_calculate_entry_hash_state_dependence() {
        let mut first_entry = create_sample_entry();
        let mut second_entry = create_sample_entry();

        // Modify state in second entry
        second_entry.state.id = "did:tdw:different:domain.example".to_string();

        // Generate hashes
        let first_hash = calculate_entry_hash(&first_entry).unwrap();
        let second_hash = calculate_entry_hash(&second_entry).unwrap();

        // Verify hashes are different due to different states
        assert_ne!(first_hash, second_hash, "Hash should change when state changes");
    }

    #[test]
    fn test_calculate_entry_hash_parameters_dependence() {
        let mut first_entry = create_sample_entry();
        let mut second_entry = create_sample_entry();

        // Modify parameters in second entry
        if let Some(update_keys) = &mut second_entry.parameters.update_keys {
            update_keys.push("z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf".to_string());
        }

        // Generate hashes
        let first_hash = calculate_entry_hash(&first_entry).unwrap();
        let second_hash = calculate_entry_hash(&second_entry).unwrap();

        // Verify hashes are different due to different parameters
        assert_ne!(first_hash, second_hash, "Hash should change when parameters change");
    }

    #[test]
    fn test_calculate_entry_hash_version_id_dependence() {
        let mut first_entry = create_sample_entry();
        let mut second_entry = create_sample_entry();

        // Modify version_id in second entry
        second_entry.version_id = "2-different_hash".to_string();

        // Generate hashes
        let first_hash = calculate_entry_hash(&first_entry).unwrap();
        let second_hash = calculate_entry_hash(&second_entry).unwrap();

        // Verify hashes are different due to different version IDs
        assert_ne!(first_hash, second_hash, "Hash should change when version_id changes");
    }


}