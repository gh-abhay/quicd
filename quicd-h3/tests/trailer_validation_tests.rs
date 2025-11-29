//! Trailer validation comprehensive tests (ISSUE #2)
//! RFC 9110 Section 6.5 and RFC 9114 Section 4.3

use quicd_h3::validation::{validate_trailer_headers, validate_trailer_section_size};

#[test]
fn test_trailers_valid_basic() {
    // Basic valid trailers
    let trailers = vec![
        (String::from("server-timing"), String::from("cache;dur=50")),
        (String::from("x-custom"), String::from("value")),
    ];
    
    assert!(validate_trailer_headers(&trailers).is_ok());
}

#[test]
fn test_trailers_reject_pseudo_headers() {
    // RFC 9114: Pseudo-headers not allowed in trailers
    let trailers = vec![
        (String::from(":status"), String::from("200")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pseudo-header"));
}

#[test]
fn test_trailers_reject_content_length() {
    // RFC 9110: Content-Length forbidden in trailers
    let trailers = vec![
        (String::from("content-length"), String::from("100")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
}

#[test]
fn test_trailers_reject_transfer_encoding() {
    // RFC 9110: Transfer-Encoding forbidden in trailers
    let trailers = vec![
        (String::from("transfer-encoding"), String::from("chunked")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
}

#[test]
fn test_trailers_reject_host() {
    // RFC 9110: Host forbidden in trailers
    let trailers = vec![
        (String::from("host"), String::from("example.com")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
}

#[test]
fn test_trailers_reject_duplicate_names() {
    // ISSUE #2: Duplicate trailer names should be rejected
    let trailers = vec![
        (String::from("server-timing"), String::from("cache;dur=50")),
        (String::from("server-timing"), String::from("db;dur=100")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Duplicate"));
}

#[test]
fn test_trailers_case_insensitive_duplicate() {
    // Header names are case-insensitive for duplicate detection
    let trailers = vec![
        (String::from("Server-Timing"), String::from("cache;dur=50")),
        (String::from("server-timing"), String::from("db;dur=100")),
    ];
    
    let result = validate_trailer_headers(&trailers);
    assert!(result.is_err());
}

#[test]
fn test_trailers_empty_allowed() {
    // Empty trailer section is valid
    let trailers: Vec<(String, String)> = vec![];
    assert!(validate_trailer_headers(&trailers).is_ok());
}

#[test]
fn test_trailer_section_size_within_limit() {
    // Trailer section within size limit should be accepted
    let trailers = vec![
        (String::from("x-trailer"), String::from("value")),
    ];
    let max_size = 1000;
    
    assert!(validate_trailer_section_size(&trailers, max_size).is_ok());
}

#[test]
fn test_trailer_section_size_exceeds_limit() {
    // Trailer section exceeding limit should be rejected
    let large_value = "x".repeat(1000);
    let trailers = vec![
        (String::from("x-large"), large_value),
    ];
    let max_size = 100;
    
    let result = validate_trailer_section_size(&trailers, max_size);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
}

#[test]
fn test_trailer_section_size_zero_limit() {
    // Zero limit means unlimited
    let large_value = "x".repeat(100000);
    let trailers = vec![
        (String::from("x-huge"), large_value),
    ];
    let max_size = 0;
    
    assert!(validate_trailer_section_size(&trailers, max_size).is_ok());
}

#[test]
fn test_trailer_section_size_exact_limit() {
    // Exactly at limit should be accepted
    let trailers = vec![
        (String::from("x"), String::from("value")),
    ];
    // RFC 9114 Section 4.2.2: size = name.len() + value.len() + 32 overhead
    // x(1) + value(5) + 32 = 38
    let max_size = 38;
    
    assert!(validate_trailer_section_size(&trailers, max_size).is_ok());
}
