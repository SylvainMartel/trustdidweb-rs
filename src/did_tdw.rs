use crate::error::DIDTDWError;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct TdwDid {
    pub scid: String,
    pub domain: String,
    pub port: Option<u16>,
    pub path: Option<String>,
}

impl TdwDid {
    /// Creates a new TdwDid instance
    pub fn new(scid: String, domain: String, port: Option<u16>, path: Option<String>) -> Self {
        Self { scid, domain, port, path }
    }

    /// Converts the TdwDid to its string representation
    pub fn to_string(&self) -> String {
        let mut did = format!("did:tdw:{}:{}", self.scid, self.domain);
        if let Some(port) = self.port {
            did.push_str(&format!(":{}", port));
        }
        if let Some(path) = &self.path {
            did.push_str(&format!("/{}", path));
        }
        did
    }

    /// Converts the TdwDid to its corresponding HTTPS URL
    pub fn to_url(&self) -> Result<Url, DIDTDWError> {
        let mut url = format!("https://{}", self.domain);
        if let Some(port) = self.port {
            url.push_str(&format!(":{}", port));
        }
        if let Some(path) = &self.path {
            url.push_str(&format!("/{}", path));
        } else {
            url.push_str("/.well-known");
        }
        url.push_str("/did.jsonl");
        Ok(Url::parse(&url)?)
    }
    /// Parses and validates a TDW DID string
    pub fn parse_and_validate_tdw_did(did: &str) -> Result<Self, DIDTDWError> {
        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 4 || parts[0] != "did" || parts[1] != "tdw" {
            return Err(DIDTDWError::InvalidDIDFormat);
        }

        let scid = parts[2].to_string();
        let domain_and_rest = parts[3..].join(":");

        // Split by '/' to separate domain (and port) from path
        let mut domain_parts = domain_and_rest.splitn(2, '/');
        let domain_and_port = domain_parts.next().unwrap();
        let path = domain_parts.next().map(|s| s.to_string());

        // Handle port
        let (domain, port) = if domain_and_port.contains(':') {
            let dp: Vec<&str> = domain_and_port.split(':').collect();
            (dp[0].to_string(), Some(dp[1].parse().map_err(|_| DIDTDWError::InvalidDIDFormat)?))
        } else {
            (domain_and_port.to_string(), None)
        };

        Ok(Self::new(scid, domain, port, path))
    }
}
pub struct UrlOptions {
    pub version_id: Option<String>,
    pub version_time: Option<String>,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdw_did_parsing() {
        let did = "did:tdw:abc123:example.com:8080/path/to/resource";
        let parsed = TdwDid::parse_and_validate_tdw_did(did).unwrap();
        assert_eq!(parsed.scid, "abc123");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.path, Some("path/to/resource".to_string()));

        let did_no_port = "did:tdw:abc123:example.com/path/to/resource";
        let parsed_no_port = TdwDid::parse_and_validate_tdw_did(did_no_port).unwrap();
        assert_eq!(parsed_no_port.scid, "abc123");
        assert_eq!(parsed_no_port.domain, "example.com");
        assert_eq!(parsed_no_port.port, None);
        assert_eq!(parsed_no_port.path, Some("path/to/resource".to_string()));

        let did_no_path = "did:tdw:abc123:example.com";
        let parsed_no_path = TdwDid::parse_and_validate_tdw_did(did_no_path).unwrap();
        assert_eq!(parsed_no_path.scid, "abc123");
        assert_eq!(parsed_no_path.domain, "example.com");
        assert_eq!(parsed_no_path.port, None);
        assert_eq!(parsed_no_path.path, None);

        let did_with_port_no_path = "did:tdw:abc123:example.com:8080";
        let parsed_with_port_no_path = TdwDid::parse_and_validate_tdw_did(did_with_port_no_path).unwrap();
        assert_eq!(parsed_with_port_no_path.scid, "abc123");
        assert_eq!(parsed_with_port_no_path.domain, "example.com");
        assert_eq!(parsed_with_port_no_path.port, Some(8080));
        assert_eq!(parsed_with_port_no_path.path, None);
    }

    #[test]
    fn test_tdw_did_to_string() {
        let did = TdwDid::new(
            "abc123".to_string(),
            "example.com".to_string(),
            Some(8080),
            Some("path/to/resource".to_string()),
        );
        assert_eq!(did.to_string(), "did:tdw:abc123:example.com:8080/path/to/resource");
    }

    #[test]
    fn test_tdw_did_to_url() {
        let did = TdwDid::new(
            "abc123".to_string(),
            "example.com".to_string(),
            Some(8080),
            Some("path/to/resource".to_string()),
        );
        assert_eq!(
            did.to_url().unwrap().to_string(),
            "https://example.com:8080/path/to/resource/did.jsonl"
        );

        let did_no_path = TdwDid::new(
            "abc123".to_string(),
            "example.com".to_string(),
            None,
            None,
        );
        assert_eq!(
            did_no_path.to_url().unwrap().to_string(),
            "https://example.com/.well-known/did.jsonl"
        );
    }
}



