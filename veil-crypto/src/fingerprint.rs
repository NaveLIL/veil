use sha2::{Digest, Sha256};

/// Emoji set for visual fingerprints (32 unique emoji).
const FINGERPRINT_EMOJI: [&str; 32] = [
    "🔒", "🛡️", "🗝️", "⚡", "🌊", "🔥", "❄️", "🌿", "🌙", "⭐", "🎯", "🎲", "🧩", "🏔️", "🌸", "🦋",
    "🐺", "🦅", "🐋", "🦁", "🌍", "💎", "🔮", "🎭", "🏛️", "⚓", "🚀", "🎵", "📡", "🧬", "⚔️", "🏴",
];

/// Generate a visual fingerprint from two identity keys.
///
/// The fingerprint is symmetric: fp(A,B) == fp(B,A).
/// This is used for contact verification (Signal-style safety numbers).
///
/// Returns a pair of (emoji_string, hex_string).
pub fn generate(key_a: &[u8; 32], key_b: &[u8; 32]) -> (String, String) {
    // Sort keys to ensure symmetry
    let (first, second) = if key_a <= key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    // Hash: SHA256(version || key1 || key2)
    let mut hasher = Sha256::new();
    hasher.update(b"veil-fingerprint-v1");
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Emoji: take 5-bit chunks from the hash → 32 emoji
    let mut emoji = String::new();
    for i in 0..32usize {
        let byte_idx = (i * 5) / 8;
        let bit_offset = (i * 5) % 8;

        let value: u8 = if bit_offset <= 3 {
            (hash[byte_idx] >> (3 - bit_offset as u8)) & 0x1F
        } else if byte_idx + 1 < hash.len() {
            let combined = ((hash[byte_idx] as u16) << 8) | (hash[byte_idx + 1] as u16);
            ((combined >> (11 - bit_offset)) & 0x1F) as u8
        } else {
            hash[byte_idx] & 0x1F
        };

        emoji.push_str(FINGERPRINT_EMOJI[value as usize % 32]);
    }

    // Hex: full SHA256 hash
    let hex_str = hex::encode(hash);

    (emoji, hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_symmetric() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let (emoji_ab, hex_ab) = generate(&key_a, &key_b);
        let (emoji_ba, hex_ba) = generate(&key_b, &key_a);

        assert_eq!(emoji_ab, emoji_ba, "Fingerprint must be symmetric (emoji)");
        assert_eq!(hex_ab, hex_ba, "Fingerprint must be symmetric (hex)");
    }

    #[test]
    fn test_fingerprint_different_keys() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let key_c = [3u8; 32];

        let (_, hex_ab) = generate(&key_a, &key_b);
        let (_, hex_ac) = generate(&key_a, &key_c);

        assert_ne!(
            hex_ab, hex_ac,
            "Different key pairs must produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_not_empty() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let (emoji, hex_str) = generate(&key_a, &key_b);

        assert!(!emoji.is_empty());
        assert_eq!(hex_str.len(), 64, "SHA256 hex should be 64 chars");
    }
}
