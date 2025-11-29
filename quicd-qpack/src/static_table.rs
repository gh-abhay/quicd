//! QPACK static table per RFC 9204 Appendix A.
//! Contains 99 predefined header field entries.

use std::collections::HashMap;

/// Static table entry.
#[derive(Debug, Clone, Copy)]
pub struct StaticEntry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

/// QPACK static table with 99 entries (indexes 0-98).
/// Note: RFC 9204 uses 0-based indexing for static table.
pub static STATIC_TABLE: &[StaticEntry] = &[
    StaticEntry { name: b":authority", value: b"" },                          // 0
    StaticEntry { name: b":path", value: b"/" },                              // 1
    StaticEntry { name: b"age", value: b"0" },                                // 2
    StaticEntry { name: b"content-disposition", value: b"" },                 // 3
    StaticEntry { name: b"content-length", value: b"0" },                     // 4
    StaticEntry { name: b"cookie", value: b"" },                              // 5
    StaticEntry { name: b"date", value: b"" },                                // 6
    StaticEntry { name: b"etag", value: b"" },                                // 7
    StaticEntry { name: b"if-modified-since", value: b"" },                   // 8
    StaticEntry { name: b"if-none-match", value: b"" },                       // 9
    StaticEntry { name: b"last-modified", value: b"" },                       // 10
    StaticEntry { name: b"link", value: b"" },                                // 11
    StaticEntry { name: b"location", value: b"" },                            // 12
    StaticEntry { name: b"referer", value: b"" },                             // 13
    StaticEntry { name: b"set-cookie", value: b"" },                          // 14
    StaticEntry { name: b":method", value: b"CONNECT" },                      // 15
    StaticEntry { name: b":method", value: b"DELETE" },                       // 16
    StaticEntry { name: b":method", value: b"GET" },                          // 17
    StaticEntry { name: b":method", value: b"HEAD" },                         // 18
    StaticEntry { name: b":method", value: b"OPTIONS" },                      // 19
    StaticEntry { name: b":method", value: b"POST" },                         // 20
    StaticEntry { name: b":method", value: b"PUT" },                          // 21
    StaticEntry { name: b":scheme", value: b"http" },                         // 22
    StaticEntry { name: b":scheme", value: b"https" },                        // 23
    StaticEntry { name: b":status", value: b"103" },                          // 24
    StaticEntry { name: b":status", value: b"200" },                          // 25
    StaticEntry { name: b":status", value: b"304" },                          // 26
    StaticEntry { name: b":status", value: b"404" },                          // 27
    StaticEntry { name: b":status", value: b"503" },                          // 28
    StaticEntry { name: b"accept", value: b"*/*" },                           // 29
    StaticEntry { name: b"accept", value: b"application/dns-message" },       // 30
    StaticEntry { name: b"accept-encoding", value: b"gzip, deflate, br" },    // 31
    StaticEntry { name: b"accept-ranges", value: b"bytes" },                  // 32
    StaticEntry { name: b"access-control-allow-headers", value: b"cache-control" }, // 33
    StaticEntry { name: b"access-control-allow-headers", value: b"content-type" },  // 34
    StaticEntry { name: b"access-control-allow-origin", value: b"*" },        // 35
    StaticEntry { name: b"cache-control", value: b"max-age=0" },              // 36
    StaticEntry { name: b"cache-control", value: b"max-age=2592000" },        // 37
    StaticEntry { name: b"cache-control", value: b"max-age=604800" },         // 38
    StaticEntry { name: b"cache-control", value: b"no-cache" },               // 39
    StaticEntry { name: b"cache-control", value: b"no-store" },               // 40
    StaticEntry { name: b"cache-control", value: b"public, max-age=31536000" }, // 41
    StaticEntry { name: b"content-encoding", value: b"br" },                  // 42
    StaticEntry { name: b"content-encoding", value: b"gzip" },                // 43
    StaticEntry { name: b"content-type", value: b"application/dns-message" }, // 44
    StaticEntry { name: b"content-type", value: b"application/javascript" },  // 45
    StaticEntry { name: b"content-type", value: b"application/json" },        // 46
    StaticEntry { name: b"content-type", value: b"application/x-www-form-urlencoded" }, // 47
    StaticEntry { name: b"content-type", value: b"image/gif" },               // 48
    StaticEntry { name: b"content-type", value: b"image/jpeg" },              // 49
    StaticEntry { name: b"content-type", value: b"image/png" },               // 50
    StaticEntry { name: b"content-type", value: b"text/css" },                // 51
    StaticEntry { name: b"content-type", value: b"text/html; charset=utf-8" }, // 52
    StaticEntry { name: b"content-type", value: b"text/plain" },              // 53
    StaticEntry { name: b"content-type", value: b"text/plain;charset=utf-8" }, // 54
    StaticEntry { name: b"range", value: b"bytes=0-" },                       // 55
    StaticEntry { name: b"strict-transport-security", value: b"max-age=31536000" }, // 56
    StaticEntry { name: b"strict-transport-security", value: b"max-age=31536000; includesubdomains" }, // 57
    StaticEntry { name: b"strict-transport-security", value: b"max-age=31536000; includesubdomains; preload" }, // 58
    StaticEntry { name: b"vary", value: b"accept-encoding" },                 // 59
    StaticEntry { name: b"vary", value: b"origin" },                          // 60
    StaticEntry { name: b"x-content-type-options", value: b"nosniff" },       // 61
    StaticEntry { name: b"x-xss-protection", value: b"1; mode=block" },       // 62
    StaticEntry { name: b":status", value: b"100" },                          // 63
    StaticEntry { name: b":status", value: b"204" },                          // 64
    StaticEntry { name: b":status", value: b"206" },                          // 65
    StaticEntry { name: b":status", value: b"302" },                          // 66
    StaticEntry { name: b":status", value: b"400" },                          // 67
    StaticEntry { name: b":status", value: b"403" },                          // 68
    StaticEntry { name: b":status", value: b"421" },                          // 69
    StaticEntry { name: b":status", value: b"425" },                          // 70
    StaticEntry { name: b":status", value: b"500" },                          // 71
    StaticEntry { name: b"accept-language", value: b"" },                     // 72
    StaticEntry { name: b"access-control-allow-credentials", value: b"FALSE" }, // 73
    StaticEntry { name: b"access-control-allow-credentials", value: b"TRUE" }, // 74
    StaticEntry { name: b"access-control-allow-headers", value: b"*" },       // 75
    StaticEntry { name: b"access-control-allow-methods", value: b"get" },     // 76
    StaticEntry { name: b"access-control-allow-methods", value: b"get, post, options" }, // 77
    StaticEntry { name: b"access-control-allow-methods", value: b"options" }, // 78
    StaticEntry { name: b"access-control-expose-headers", value: b"content-length" }, // 79
    StaticEntry { name: b"access-control-request-headers", value: b"content-type" }, // 80
    StaticEntry { name: b"access-control-request-method", value: b"get" },    // 81
    StaticEntry { name: b"access-control-request-method", value: b"post" },   // 82
    StaticEntry { name: b"alt-svc", value: b"clear" },                        // 83
    StaticEntry { name: b"authorization", value: b"" },                       // 84
    StaticEntry { name: b"content-security-policy", value: b"script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    StaticEntry { name: b"early-data", value: b"1" },                         // 86
    StaticEntry { name: b"expect-ct", value: b"" },                           // 87
    StaticEntry { name: b"forwarded", value: b"" },                           // 88
    StaticEntry { name: b"if-range", value: b"" },                            // 89
    StaticEntry { name: b"origin", value: b"" },                              // 90
    StaticEntry { name: b"purpose", value: b"prefetch" },                     // 91
    StaticEntry { name: b"server", value: b"" },                              // 92
    StaticEntry { name: b"timing-allow-origin", value: b"*" },                // 93
    StaticEntry { name: b"upgrade-insecure-requests", value: b"1" },          // 94
    StaticEntry { name: b"user-agent", value: b"" },                          // 95
    StaticEntry { name: b"x-forwarded-for", value: b"" },                     // 96
    StaticEntry { name: b"x-frame-options", value: b"deny" },                 // 97
    StaticEntry { name: b"x-frame-options", value: b"sameorigin" },           // 98
];

/// Lookup maps for fast static table access.
pub struct StaticTableLookup {
    /// Map from (name, value) to index.
    exact_match: HashMap<(&'static [u8], &'static [u8]), usize>,
    /// Map from name to first matching index.
    name_match: HashMap<&'static [u8], usize>,
}

impl StaticTableLookup {
    fn new() -> Self {
        let mut exact_match = HashMap::new();
        let mut name_match = HashMap::new();
        
        for (idx, entry) in STATIC_TABLE.iter().enumerate() {
            exact_match.insert((entry.name, entry.value), idx);
            name_match.entry(entry.name).or_insert(idx);
        }
        
        Self { exact_match, name_match }
    }
}

lazy_static::lazy_static! {
    static ref LOOKUP: StaticTableLookup = StaticTableLookup::new();
}

/// Find exact match in static table.
/// Returns Some(index) if found, None otherwise.
#[inline]
pub fn find_exact(name: &[u8], value: &[u8]) -> Option<usize> {
    LOOKUP.exact_match.get(&(name, value)).copied()
}

/// Find name-only match in static table.
/// Returns Some(index) of first matching entry, None otherwise.
#[inline]
pub fn find_name(name: &[u8]) -> Option<usize> {
    LOOKUP.name_match.get(name).copied()
}

/// Get static table entry by index.
/// Returns None if index is out of bounds.
#[inline]
pub fn get(index: usize) -> Option<&'static StaticEntry> {
    STATIC_TABLE.get(index)
}

/// Total number of static table entries.
#[inline]
pub const fn len() -> usize {
    99
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_static_table_size() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(len(), 99);
    }
    
    #[test]
    fn test_exact_match() {
        assert_eq!(find_exact(b":method", b"GET"), Some(17));
        assert_eq!(find_exact(b":status", b"200"), Some(25));
        assert_eq!(find_exact(b":authority", b""), Some(0));
    }
    
    #[test]
    fn test_name_match() {
        assert_eq!(find_name(b":method"), Some(15)); // First :method entry
        assert_eq!(find_name(b"content-type"), Some(44)); // First content-type entry
    }
    
    #[test]
    fn test_get_entry() {
        let entry = get(17).unwrap();
        assert_eq!(entry.name, b":method");
        assert_eq!(entry.value, b"GET");
        
        assert!(get(99).is_none());
    }
}
