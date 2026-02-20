//! Shared key encoding helpers used across module key builders.

/// Cosmos SDK-style length-prefix encoding: 1 byte length + raw bytes.
///
/// # Panics
///
/// Panics if `data.len() > 255`.
pub fn len_prefix(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 255, "len_prefix: data exceeds 255 bytes");
    let mut out = Vec::with_capacity(1 + data.len());
    #[expect(clippy::cast_possible_truncation)]
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// Replace `/` with `|` in key parts to prevent path collisions.
pub fn sanitize_key_part(part: &str) -> String {
    part.replace('/', "|")
}

/// Restore `|` back to `/` in key parts.
pub fn unsanitize_key_part(part: &str) -> String {
    part.replace('|', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_prefix_basic() {
        let result = len_prefix(b"hello");
        assert_eq!(result[0], 5);
        assert_eq!(&result[1..], b"hello");
    }

    #[test]
    fn len_prefix_empty() {
        let result = len_prefix(b"");
        assert_eq!(result, vec![0]);
    }

    #[test]
    #[should_panic(expected = "len_prefix: data exceeds 255 bytes")]
    fn len_prefix_overflow() {
        len_prefix(&[0u8; 256]);
    }

    #[test]
    fn sanitize_roundtrip() {
        let original = "bulletin/namespace1";
        let sanitized = sanitize_key_part(original);
        assert_eq!(sanitized, "bulletin|namespace1");
        assert_eq!(unsanitize_key_part(&sanitized), original);
    }

    #[test]
    fn sanitize_no_slashes() {
        let original = "simple_key";
        assert_eq!(sanitize_key_part(original), original);
    }
}
