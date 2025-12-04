//! Content-Length validation comprehensive tests (ISSUE #1)
//! RFC 9110 Section 8.6 and RFC 9114 Section 4.1.2

use quicd_h3::validation::validate_content_length_uniqueness;

#[test]
fn test_content_length_single_valid() {
    // Single Content-Length header should be accepted
    let headers = vec![(String::from("content-length"), String::from("100"))];

    assert!(validate_content_length_uniqueness(&headers).is_ok());
}

#[test]
fn test_content_length_duplicate_same_value() {
    // RFC 9110: Even identical values are rejected (strict interpretation)
    let headers = vec![
        (String::from("content-length"), String::from("100")),
        (String::from("content-length"), String::from("100")),
    ];

    let result = validate_content_length_uniqueness(&headers);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("multiple Content-Length"));
}

#[test]
fn test_content_length_duplicate_different_values() {
    // Different values definitely rejected
    let headers = vec![
        (String::from("content-length"), String::from("100")),
        (String::from("content-length"), String::from("200")),
    ];

    let result = validate_content_length_uniqueness(&headers);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("multiple Content-Length"));
}

#[test]
fn test_content_length_case_insensitive() {
    // Header names are case-insensitive
    let headers = vec![
        (String::from("Content-Length"), String::from("100")),
        (String::from("content-length"), String::from("100")),
    ];

    let result = validate_content_length_uniqueness(&headers);
    assert!(result.is_err());
}

#[test]
fn test_content_length_with_transfer_encoding() {
    // RFC 9110 Section 6.3: Content-Length must be removed if Transfer-Encoding present
    // This is tested elsewhere, but should integrate with duplicate checking

    let headers = vec![
        (String::from("content-length"), String::from("100")),
        (String::from("transfer-encoding"), String::from("chunked")),
    ];

    // This test would need the full validation pipeline
    // For now, just verify duplicate checking works independently
    assert!(validate_content_length_uniqueness(&headers).is_ok());
}

#[test]
fn test_content_length_zero_valid() {
    // Content-Length: 0 is valid
    let headers = vec![(String::from("content-length"), String::from("0"))];

    assert!(validate_content_length_uniqueness(&headers).is_ok());
}

#[test]
fn test_content_length_invalid_format() {
    // Invalid format should be caught elsewhere, but duplicate check should not crash
    let headers = vec![(String::from("content-length"), String::from("invalid"))];

    // Duplicate check only looks for multiple headers, not validity
    assert!(validate_content_length_uniqueness(&headers).is_ok());
}

#[test]
fn test_content_length_three_duplicates() {
    // Three identical values still rejected
    let headers = vec![
        (String::from("content-length"), String::from("100")),
        (String::from("content-length"), String::from("100")),
        (String::from("content-length"), String::from("100")),
    ];

    let result = validate_content_length_uniqueness(&headers);
    assert!(result.is_err());
}
