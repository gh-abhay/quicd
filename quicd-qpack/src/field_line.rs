//! Field line representation.
//!
//! Represents an HTTP header or trailer field as a name-value pair.

use bytes::Bytes;
use std::fmt;

/// An HTTP field line (name-value pair).
#[derive(Clone, PartialEq, Eq)]
pub struct FieldLine {
    pub name: Bytes,
    pub value: Bytes,
}

impl FieldLine {
    /// Creates a new field line.
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns the size of this field line for dynamic table accounting.
    ///
    /// Per RFC 9204 Section 3.2.1: size = name_len + value_len + 32
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

impl fmt::Debug for FieldLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FieldLine({:?}: {:?})",
            String::from_utf8_lossy(&self.name),
            String::from_utf8_lossy(&self.value)
        )
    }
}

impl From<(&'static str, &'static str)> for FieldLine {
    fn from((name, value): (&'static str, &'static str)) -> Self {
        Self::new(name, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_line_size() {
        let field = FieldLine::new("name", "value");
        assert_eq!(field.size(), 4 + 5 + 32);
    }

    #[test]
    fn test_field_line_from_tuple() {
        let field: FieldLine = (":method", "GET").into();
        assert_eq!(&field.name[..], b":method");
        assert_eq!(&field.value[..], b"GET");
    }
}
