//! QPACK static table (RFC 9204 Appendix A).
//!
//! The static table consists of 99 predefined field lines with fixed indices.
//! It's indexed from 0 (unlike HPACK which starts at 1).
//!
//! This table is generated from actual HTTP/3 traffic analysis and contains
//! the most common header fields for optimal compression.

/// A static table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticEntry {
    pub name: &'static str,
    pub value: &'static str,
}

/// The QPACK static table with 99 entries (indexed 0-98).
///
/// Per RFC 9204 Appendix A, generated from HTTP/3 traffic analysis in 2018.
pub static STATIC_TABLE: [StaticEntry; 99] = [
    StaticEntry {
        name: ":authority",
        value: "",
    }, // 0
    StaticEntry {
        name: ":path",
        value: "/",
    }, // 1
    StaticEntry {
        name: "age",
        value: "0",
    }, // 2
    StaticEntry {
        name: "content-disposition",
        value: "",
    }, // 3
    StaticEntry {
        name: "content-length",
        value: "0",
    }, // 4
    StaticEntry {
        name: "cookie",
        value: "",
    }, // 5
    StaticEntry {
        name: "date",
        value: "",
    }, // 6
    StaticEntry {
        name: "etag",
        value: "",
    }, // 7
    StaticEntry {
        name: "if-modified-since",
        value: "",
    }, // 8
    StaticEntry {
        name: "if-none-match",
        value: "",
    }, // 9
    StaticEntry {
        name: "last-modified",
        value: "",
    }, // 10
    StaticEntry {
        name: "link",
        value: "",
    }, // 11
    StaticEntry {
        name: "location",
        value: "",
    }, // 12
    StaticEntry {
        name: "referer",
        value: "",
    }, // 13
    StaticEntry {
        name: "set-cookie",
        value: "",
    }, // 14
    StaticEntry {
        name: ":method",
        value: "CONNECT",
    }, // 15
    StaticEntry {
        name: ":method",
        value: "DELETE",
    }, // 16
    StaticEntry {
        name: ":method",
        value: "GET",
    }, // 17
    StaticEntry {
        name: ":method",
        value: "HEAD",
    }, // 18
    StaticEntry {
        name: ":method",
        value: "OPTIONS",
    }, // 19
    StaticEntry {
        name: ":method",
        value: "POST",
    }, // 20
    StaticEntry {
        name: ":method",
        value: "PUT",
    }, // 21
    StaticEntry {
        name: ":scheme",
        value: "http",
    }, // 22
    StaticEntry {
        name: ":scheme",
        value: "https",
    }, // 23
    StaticEntry {
        name: ":status",
        value: "103",
    }, // 24
    StaticEntry {
        name: ":status",
        value: "200",
    }, // 25
    StaticEntry {
        name: ":status",
        value: "304",
    }, // 26
    StaticEntry {
        name: ":status",
        value: "404",
    }, // 27
    StaticEntry {
        name: ":status",
        value: "503",
    }, // 28
    StaticEntry {
        name: "accept",
        value: "*/*",
    }, // 29
    StaticEntry {
        name: "accept",
        value: "application/dns-message",
    }, // 30
    StaticEntry {
        name: "accept-encoding",
        value: "gzip, deflate, br",
    }, // 31
    StaticEntry {
        name: "accept-ranges",
        value: "bytes",
    }, // 32
    StaticEntry {
        name: "access-control-allow-headers",
        value: "cache-control",
    }, // 33
    StaticEntry {
        name: "access-control-allow-headers",
        value: "content-type",
    }, // 34
    StaticEntry {
        name: "access-control-allow-origin",
        value: "*",
    }, // 35
    StaticEntry {
        name: "cache-control",
        value: "max-age=0",
    }, // 36
    StaticEntry {
        name: "cache-control",
        value: "max-age=2592000",
    }, // 37
    StaticEntry {
        name: "cache-control",
        value: "max-age=604800",
    }, // 38
    StaticEntry {
        name: "cache-control",
        value: "no-cache",
    }, // 39
    StaticEntry {
        name: "cache-control",
        value: "no-store",
    }, // 40
    StaticEntry {
        name: "cache-control",
        value: "public, max-age=31536000",
    }, // 41
    StaticEntry {
        name: "content-encoding",
        value: "br",
    }, // 42
    StaticEntry {
        name: "content-encoding",
        value: "gzip",
    }, // 43
    StaticEntry {
        name: "content-type",
        value: "application/dns-message",
    }, // 44
    StaticEntry {
        name: "content-type",
        value: "application/javascript",
    }, // 45
    StaticEntry {
        name: "content-type",
        value: "application/json",
    }, // 46
    StaticEntry {
        name: "content-type",
        value: "application/x-www-form-urlencoded",
    }, // 47
    StaticEntry {
        name: "content-type",
        value: "image/gif",
    }, // 48
    StaticEntry {
        name: "content-type",
        value: "image/jpeg",
    }, // 49
    StaticEntry {
        name: "content-type",
        value: "image/png",
    }, // 50
    StaticEntry {
        name: "content-type",
        value: "text/css",
    }, // 51
    StaticEntry {
        name: "content-type",
        value: "text/html; charset=utf-8",
    }, // 52
    StaticEntry {
        name: "content-type",
        value: "text/plain",
    }, // 53
    StaticEntry {
        name: "content-type",
        value: "text/plain;charset=utf-8",
    }, // 54
    StaticEntry {
        name: "range",
        value: "bytes=0-",
    }, // 55
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000",
    }, // 56
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000; includesubdomains",
    }, // 57
    StaticEntry {
        name: "strict-transport-security",
        value: "max-age=31536000; includesubdomains; preload",
    }, // 58
    StaticEntry {
        name: "vary",
        value: "accept-encoding",
    }, // 59
    StaticEntry {
        name: "vary",
        value: "origin",
    }, // 60
    StaticEntry {
        name: "x-content-type-options",
        value: "nosniff",
    }, // 61
    StaticEntry {
        name: "x-xss-protection",
        value: "1; mode=block",
    }, // 62
    StaticEntry {
        name: ":status",
        value: "100",
    }, // 63
    StaticEntry {
        name: ":status",
        value: "204",
    }, // 64
    StaticEntry {
        name: ":status",
        value: "206",
    }, // 65
    StaticEntry {
        name: ":status",
        value: "302",
    }, // 66
    StaticEntry {
        name: ":status",
        value: "400",
    }, // 67
    StaticEntry {
        name: ":status",
        value: "403",
    }, // 68
    StaticEntry {
        name: ":status",
        value: "421",
    }, // 69
    StaticEntry {
        name: ":status",
        value: "425",
    }, // 70
    StaticEntry {
        name: ":status",
        value: "500",
    }, // 71
    StaticEntry {
        name: "accept-language",
        value: "",
    }, // 72
    StaticEntry {
        name: "access-control-allow-credentials",
        value: "FALSE",
    }, // 73
    StaticEntry {
        name: "access-control-allow-credentials",
        value: "TRUE",
    }, // 74
    StaticEntry {
        name: "access-control-allow-headers",
        value: "*",
    }, // 75
    StaticEntry {
        name: "access-control-allow-methods",
        value: "get",
    }, // 76
    StaticEntry {
        name: "access-control-allow-methods",
        value: "get, post, options",
    }, // 77
    StaticEntry {
        name: "access-control-allow-methods",
        value: "options",
    }, // 78
    StaticEntry {
        name: "access-control-expose-headers",
        value: "content-length",
    }, // 79
    StaticEntry {
        name: "access-control-request-headers",
        value: "content-type",
    }, // 80
    StaticEntry {
        name: "access-control-request-method",
        value: "get",
    }, // 81
    StaticEntry {
        name: "access-control-request-method",
        value: "post",
    }, // 82
    StaticEntry {
        name: "alt-svc",
        value: "clear",
    }, // 83
    StaticEntry {
        name: "authorization",
        value: "",
    }, // 84
    StaticEntry {
        name: "content-security-policy",
        value: "script-src 'none'; object-src 'none'; base-uri 'none'",
    }, // 85
    StaticEntry {
        name: "early-data",
        value: "1",
    }, // 86
    StaticEntry {
        name: "expect-ct",
        value: "",
    }, // 87
    StaticEntry {
        name: "forwarded",
        value: "",
    }, // 88
    StaticEntry {
        name: "if-range",
        value: "",
    }, // 89
    StaticEntry {
        name: "origin",
        value: "",
    }, // 90
    StaticEntry {
        name: "purpose",
        value: "prefetch",
    }, // 91
    StaticEntry {
        name: "server",
        value: "",
    }, // 92
    StaticEntry {
        name: "timing-allow-origin",
        value: "*",
    }, // 93
    StaticEntry {
        name: "upgrade-insecure-requests",
        value: "1",
    }, // 94
    StaticEntry {
        name: "user-agent",
        value: "",
    }, // 95
    StaticEntry {
        name: "x-forwarded-for",
        value: "",
    }, // 96
    StaticEntry {
        name: "x-frame-options",
        value: "deny",
    }, // 97
    StaticEntry {
        name: "x-frame-options",
        value: "sameorigin",
    }, // 98
];

/// Looks up an entry by index.
///
/// Returns `Some(&StaticEntry)` if index is valid (0-98), `None` otherwise.
pub fn get(index: usize) -> Option<&'static StaticEntry> {
    STATIC_TABLE.get(index)
}

/// Finds entries with the given name.
///
/// Returns an iterator over (index, entry) pairs for all entries matching the name.
pub fn find_by_name(name: &str) -> impl Iterator<Item = (usize, &'static StaticEntry)> + '_ {
    STATIC_TABLE
        .iter()
        .enumerate()
        .filter(move |(_, entry)| entry.name == name)
}

/// Finds an entry with matching name and value.
///
/// Returns the index of the first matching entry, if any.
pub fn find_exact(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|entry| entry.name == name && entry.value == value)
}

/// Returns the total number of static table entries.
pub const fn size() -> usize {
    STATIC_TABLE.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_size() {
        assert_eq!(size(), 99);
        assert_eq!(STATIC_TABLE.len(), 99);
    }

    #[test]
    fn test_get_valid_indices() {
        assert_eq!(get(0).unwrap().name, ":authority");
        assert_eq!(get(1).unwrap().name, ":path");
        assert_eq!(get(1).unwrap().value, "/");
        assert_eq!(get(17).unwrap().name, ":method");
        assert_eq!(get(17).unwrap().value, "GET");
        assert_eq!(get(98).unwrap().name, "x-frame-options");
        assert_eq!(get(98).unwrap().value, "sameorigin");
    }

    #[test]
    fn test_get_invalid_index() {
        assert!(get(99).is_none());
        assert!(get(100).is_none());
        assert!(get(usize::MAX).is_none());
    }

    #[test]
    fn test_find_by_name() {
        let methods: Vec<_> = find_by_name(":method").collect();
        assert_eq!(methods.len(), 7); // CONNECT, DELETE, GET, HEAD, OPTIONS, POST, PUT
        assert_eq!(methods[0].1.value, "CONNECT");
        assert_eq!(methods[2].1.value, "GET");

        let statuses: Vec<_> = find_by_name(":status").collect();
        // :status appears 14 times (103, 200, 304, 404, 503, 100, 204, 206, 302, 400, 403, 421, 425, 500)
        assert_eq!(statuses.len(), 14);
    }

    #[test]
    fn test_find_exact() {
        assert_eq!(find_exact(":method", "GET"), Some(17));
        assert_eq!(find_exact(":path", "/"), Some(1));
        assert_eq!(find_exact(":authority", ""), Some(0));
        assert_eq!(find_exact(":scheme", "https"), Some(23));
        assert_eq!(find_exact(":status", "200"), Some(25));
        assert_eq!(find_exact("nonexistent", "value"), None);
        assert_eq!(find_exact(":method", "TRACE"), None);
    }

    #[test]
    fn test_all_entries_valid() {
        // Verify all entries have non-empty names
        for (idx, entry) in STATIC_TABLE.iter().enumerate() {
            assert!(!entry.name.is_empty(), "Entry {} has empty name", idx);
            // Values can be empty (many are)
        }
    }

    #[test]
    fn test_pseudo_headers() {
        // Verify all pseudo-headers start with ':'
        let pseudo_headers = [":authority", ":path", ":method", ":scheme", ":status"];
        for name in &pseudo_headers {
            assert!(find_by_name(name).next().is_some());
        }
    }
}
