//! RFC 3161 timestamp parsing utilities
//!
//! This module provides utilities for parsing RFC 3161 timestamp tokens
//! and extracting the timestamp value.

use crate::error::{Error, Result};
use x509_cert::der::{Decode, Reader, SliceReader};

/// Parse an RFC 3161 timestamp response to extract the timestamp
///
/// This extracts the GeneralizedTime from TSTInfo in the timestamp response.
/// The structure is:
/// ```text
/// TimeStampResp ::= SEQUENCE {
///   status PKIStatusInfo,
///   timeStampToken TimeStampToken OPTIONAL }
///
/// TimeStampToken ::= ContentInfo
/// ContentInfo ::= SEQUENCE {
///   contentType OBJECT IDENTIFIER (id-signedData),
///   content [0] EXPLICIT SignedData }
///
/// SignedData ::= SEQUENCE {
///   version INTEGER,
///   digestAlgorithms SET OF AlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   ... }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType OBJECT IDENTIFIER (id-ct-TSTInfo),
///   eContent [0] EXPLICIT OCTET STRING }
///
/// TSTInfo ::= SEQUENCE {
///   version INTEGER,
///   policy TSAPolicyId,
///   messageImprint MessageImprint,
///   serialNumber INTEGER,
///   genTime GeneralizedTime,  <-- This is what we extract!
///   ... }
/// ```
pub fn parse_timestamp(timestamp_bytes: &[u8]) -> Result<i64> {
    let mut reader = SliceReader::new(timestamp_bytes)
        .map_err(|e| Error::Parse(format!("failed to create DER reader: {}", e)))?;

    // Read TimeStampResp SEQUENCE
    let _tsr_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode TimeStampResp header: {}", e)))?;

    // Skip PKIStatusInfo (first field)
    let status_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode status header: {}", e)))?;
    reader
        .read_slice(status_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip status: {}", e)))?;

    // Read TimeStampToken (ContentInfo) SEQUENCE
    let _content_info_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode ContentInfo header: {}", e)))?;

    // Skip contentType OID
    let oid_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode OID header: {}", e)))?;
    reader
        .read_slice(oid_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip OID: {}", e)))?;

    // Read [0] EXPLICIT tag for content
    let _explicit_tag = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode explicit tag: {}", e)))?;

    // Read SignedData SEQUENCE
    let _signed_data_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode SignedData header: {}", e)))?;

    // Skip version INTEGER
    let version_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode version: {}", e)))?;
    reader
        .read_slice(version_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip version: {}", e)))?;

    // Skip digestAlgorithms SET
    let digest_algs_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode digestAlgorithms: {}", e)))?;
    reader
        .read_slice(digest_algs_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip digestAlgorithms: {}", e)))?;

    // Read EncapsulatedContentInfo SEQUENCE
    let _encap_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode EncapsulatedContentInfo: {}", e)))?;

    // Skip eContentType OID
    let econtent_oid_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode eContentType OID: {}", e)))?;
    reader
        .read_slice(econtent_oid_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip eContentType OID: {}", e)))?;

    // Read eContent [0] EXPLICIT tag
    let _econtent_tag = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode eContent tag: {}", e)))?;

    // Read OCTET STRING wrapper
    let _octet_string_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode OCTET STRING: {}", e)))?;

    // Now we're at TSTInfo SEQUENCE
    let _tst_info_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode TSTInfo: {}", e)))?;

    // Skip version INTEGER
    let tst_version_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode TSTInfo version: {}", e)))?;
    reader
        .read_slice(tst_version_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip TSTInfo version: {}", e)))?;

    // Skip policy OID
    let policy_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode policy: {}", e)))?;
    reader
        .read_slice(policy_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip policy: {}", e)))?;

    // Skip messageImprint SEQUENCE
    let msg_imprint_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode messageImprint: {}", e)))?;
    reader
        .read_slice(msg_imprint_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip messageImprint: {}", e)))?;

    // Skip serialNumber INTEGER
    let serial_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode serialNumber: {}", e)))?;
    reader
        .read_slice(serial_header.length)
        .map_err(|e| Error::Parse(format!("failed to skip serialNumber: {}", e)))?;

    // Read genTime (GeneralizedTime)
    let gentime_header = x509_cert::der::Header::decode(&mut reader)
        .map_err(|e| Error::Parse(format!("failed to decode genTime: {}", e)))?;

    let gentime_len: usize = gentime_header
        .length
        .try_into()
        .map_err(|_| Error::Parse("invalid genTime length".to_string()))?;

    let gentime_bytes = reader
        .read_slice(
            gentime_len
                .try_into()
                .map_err(|_| Error::Parse("failed to convert genTime length".to_string()))?,
        )
        .map_err(|e| Error::Parse(format!("failed to read genTime: {}", e)))?;

    // Parse GeneralizedTime (format: YYYYMMDDHHMMSSZ or with fractional seconds)
    let gentime_str = std::str::from_utf8(gentime_bytes)
        .map_err(|e| Error::Parse(format!("invalid genTime UTF-8: {}", e)))?;

    // Parse the timestamp using our utility function
    parse_generalized_time(gentime_str)
}

/// Parse a GeneralizedTime string to Unix timestamp
///
/// Format: YYYYMMDDHHMMSSz or YYYYMMDDHHMMSS.fffZ
pub fn parse_generalized_time(time_str: &str) -> Result<i64> {
    // Remove trailing 'Z' if present
    let time_str = time_str.trim_end_matches('Z').trim_end_matches('z');

    // Split on '.' to separate fractional seconds if present
    let parts: Vec<&str> = time_str.split('.').collect();
    let base_time = parts[0];

    // Ensure we have at least 14 characters (YYYYMMDDHHmmss)
    if base_time.len() < 14 {
        return Err(Error::Parse(format!(
            "invalid GeneralizedTime format: {}",
            time_str
        )));
    }

    // Parse components
    let year: i32 = base_time[0..4]
        .parse()
        .map_err(|_| Error::Parse("invalid year in GeneralizedTime".to_string()))?;
    let month: u32 = base_time[4..6]
        .parse()
        .map_err(|_| Error::Parse("invalid month in GeneralizedTime".to_string()))?;
    let day: u32 = base_time[6..8]
        .parse()
        .map_err(|_| Error::Parse("invalid day in GeneralizedTime".to_string()))?;
    let hour: u32 = base_time[8..10]
        .parse()
        .map_err(|_| Error::Parse("invalid hour in GeneralizedTime".to_string()))?;
    let minute: u32 = base_time[10..12]
        .parse()
        .map_err(|_| Error::Parse("invalid minute in GeneralizedTime".to_string()))?;
    let second: u32 = base_time[12..14]
        .parse()
        .map_err(|_| Error::Parse("invalid second in GeneralizedTime".to_string()))?;

    // Create NaiveDateTime
    use chrono::{NaiveDate, TimeZone};
    let naive_date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| Error::Parse(format!("invalid date: {}-{}-{}", year, month, day)))?;

    let naive_datetime = naive_date
        .and_hms_opt(hour, minute, second)
        .ok_or_else(|| Error::Parse(format!("invalid time: {}:{}:{}", hour, minute, second)))?;

    // Convert to UTC timestamp
    let datetime = chrono::Utc.from_utc_datetime(&naive_datetime);
    Ok(datetime.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_generalized_time() {
        // Standard format
        let result = parse_generalized_time("20231215120000Z");
        assert!(result.is_ok());

        // Format without Z
        let result = parse_generalized_time("20231215120000");
        assert!(result.is_ok());

        // With fractional seconds
        let result = parse_generalized_time("20231215120000.123Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_generalized_time_invalid() {
        // Too short
        let result = parse_generalized_time("2023");
        assert!(result.is_err());

        // Invalid date
        let result = parse_generalized_time("20231332120000Z");
        assert!(result.is_err());
    }
}
