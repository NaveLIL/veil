use sha2::{Digest, Sha256};

/// Emoji set for visual fingerprints (32 unique emoji).
const FINGERPRINT_EMOJI: [&str; 32] = [
    "🔒", "🛡️", "🗝️", "⚡", "🌊", "🔥", "❄️", "🌿", "🌙", "⭐", "🎯", "🎲", "🧩", "🏔️", "🌸", "🦋",
    "🐺", "🦅", "🐋", "🦁", "🌍", "💎", "🔮", "🎭", "🏛️", "⚓", "🚀", "🎵", "📡", "🧬", "⚔️", "🏴",
];

#[derive(Clone, Copy)]
pub struct AccountFingerprintTuple<'a> {
    pub user_id: &'a str,
    pub identity_key: &'a [u8; 32],
    pub signing_key: &'a [u8; 32],
}

fn encode_account_tuple(account: AccountFingerprintTuple<'_>) -> Vec<u8> {
    let user_id = account.user_id.as_bytes();
    let mut encoded = Vec::with_capacity(4 + user_id.len() + 64);
    encoded.extend_from_slice(&(user_id.len() as u32).to_be_bytes());
    encoded.extend_from_slice(user_id);
    encoded.extend_from_slice(account.identity_key);
    encoded.extend_from_slice(account.signing_key);
    encoded
}

fn render_digest(hash: &[u8; 32]) -> (String, String) {
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
        emoji.push_str(FINGERPRINT_EMOJI[value as usize]);
    }
    (emoji, hex::encode(hash))
}

/// Generate the symmetric account fingerprint used for out-of-band identity
/// verification. It binds the exact server origin and both account tuples:
/// canonical user ID, X25519 identity key, and Ed25519 signing key.
pub fn generate_account_v2(
    canonical_server_origin: &str,
    account_a: AccountFingerprintTuple<'_>,
    account_b: AccountFingerprintTuple<'_>,
) -> (String, String) {
    let mut first = encode_account_tuple(account_a);
    let mut second = encode_account_tuple(account_b);
    if second < first {
        std::mem::swap(&mut first, &mut second);
    }

    let origin = canonical_server_origin.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"veil-account-fingerprint-v2\0");
    hasher.update((origin.len() as u32).to_be_bytes());
    hasher.update(origin);
    hasher.update((first.len() as u32).to_be_bytes());
    hasher.update(&first);
    hasher.update((second.len() as u32).to_be_bytes());
    hasher.update(&second);
    let digest: [u8; 32] = hasher.finalize().into();
    render_digest(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://chat.example.test:443";

    fn account<'a>(
        user_id: &'a str,
        identity_key: &'a [u8; 32],
        signing_key: &'a [u8; 32],
    ) -> AccountFingerprintTuple<'a> {
        AccountFingerprintTuple {
            user_id,
            identity_key,
            signing_key,
        }
    }

    #[test]
    fn account_v2_is_symmetric() {
        let ik_a = [1u8; 32];
        let sk_a = [2u8; 32];
        let ik_b = [3u8; 32];
        let sk_b = [4u8; 32];
        let a = account("550e8400-e29b-41d4-a716-446655440001", &ik_a, &sk_a);
        let b = account("550e8400-e29b-41d4-a716-446655440002", &ik_b, &sk_b);

        let (emoji_ab, hex_ab) = generate_account_v2(ORIGIN, a, b);
        let (emoji_ba, hex_ba) = generate_account_v2(ORIGIN, b, a);

        assert_eq!(emoji_ab, emoji_ba);
        assert_eq!(hex_ab, hex_ba);
    }

    #[test]
    fn account_v2_binds_origin_users_and_typed_key_pairs() {
        let ik_a = [1u8; 32];
        let sk_a = [2u8; 32];
        let ik_b = [3u8; 32];
        let sk_b = [4u8; 32];
        let changed = [5u8; 32];
        let a = account("550e8400-e29b-41d4-a716-446655440001", &ik_a, &sk_a);
        let b = account("550e8400-e29b-41d4-a716-446655440002", &ik_b, &sk_b);
        let (_, baseline) = generate_account_v2(ORIGIN, a, b);

        for different in [
            generate_account_v2(ORIGIN, a, account(b.user_id, &changed, &sk_b)).1,
            generate_account_v2(ORIGIN, a, account(b.user_id, &ik_b, &changed)).1,
            generate_account_v2(ORIGIN, account(a.user_id, &ik_a, &changed), b).1,
            generate_account_v2(
                ORIGIN,
                a,
                account("550e8400-e29b-41d4-a716-446655440003", &ik_b, &sk_b),
            )
            .1,
            generate_account_v2("https://other.example.test:443", a, b).1,
            generate_account_v2(ORIGIN, a, account(b.user_id, &sk_b, &ik_b)).1,
        ] {
            assert_ne!(baseline, different);
        }
    }

    #[test]
    fn account_v2_is_not_the_removed_x25519_only_v1_digest() {
        let ik_a = [1u8; 32];
        let sk_a = [2u8; 32];
        let ik_b = [3u8; 32];
        let sk_b = [4u8; 32];
        let (emoji, hex_str) = generate_account_v2(
            ORIGIN,
            account("550e8400-e29b-41d4-a716-446655440001", &ik_a, &sk_a),
            account("550e8400-e29b-41d4-a716-446655440002", &ik_b, &sk_b),
        );
        let mut legacy = Sha256::new();
        legacy.update(b"veil-fingerprint-v1");
        legacy.update(ik_a);
        legacy.update(ik_b);

        assert!(!emoji.is_empty());
        assert_eq!(hex_str.len(), 64);
        assert_ne!(hex_str, hex::encode(legacy.finalize()));
    }
}
