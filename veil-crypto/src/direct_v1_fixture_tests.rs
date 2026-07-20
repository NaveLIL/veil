use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::{
    keys::IdentityKeyPair,
    ratchet::{MessageHeader, RatchetSession},
    x3dh::{self, OneTimePreKey, PreKeyBundle, SignedPreKey},
};

const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const CONVERSATION_ID: &str = "11111111-2222-4333-8444-555555555555";
const TEXT: &str = "veil direct v1";
const SIGNED_PREKEY_ID: u32 = 0x0102_0304;
const ONE_TIME_PREKEY_ID: u32 = 0x0506_0708;
const X3DH_INFO: &[u8] = b"veil-x3dh-v1";
const RATCHET_INFO: &[u8] = b"veil-ratchet-v1";
const CLIENT_AD_DOMAIN: &[u8] = b"veil-ratchet-message-v1";
const RATCHET_AD_DOMAIN: &[u8] = b"veil-double-ratchet-v2";
const REVIEWED_FIXTURE_SHA256: &str =
    "dad0a84e5d7366e5189b24c9fb230c4bdd4cc67245607c148b3e3003d9915c2e";

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct PendingInitialHeaderFixture {
    ephemeral_public: [u8; 32],
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
}

struct OracleIdentity {
    x25519_secret: [u8; 32],
    x25519_public: [u8; 32],
    ed25519_secret: [u8; 32],
    ed25519_public: [u8; 32],
}

struct FixtureArtifacts {
    value: Value,
    responder_before: Vec<u8>,
    ratchet_header: MessageHeader,
    transport: Vec<u8>,
    client_ad: Vec<u8>,
    inner_plaintext: Vec<u8>,
}

fn sequence<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(index as u8))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn independent_identity(mnemonic: &str) -> OracleIdentity {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(b"veil-identity-v1:");
    salt_hasher.update(mnemonic.as_bytes());
    let salt = salt_hasher.finalize();
    let params = Params::new(65_536, 3, 4, Some(64)).expect("reviewed identity KDF params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(mnemonic.as_bytes(), &salt, &mut seed)
        .expect("fixture mnemonic must derive");

    let mut x25519_secret = [0u8; 32];
    let mut ed25519_secret = [0u8; 32];
    x25519_secret.copy_from_slice(&seed[..32]);
    ed25519_secret.copy_from_slice(&seed[32..]);
    let x25519_public = *X25519PublicKey::from(&X25519StaticSecret::from(x25519_secret)).as_bytes();
    let ed25519_public = Ed25519SigningKey::from_bytes(&ed25519_secret)
        .verifying_key()
        .to_bytes();
    seed.zeroize();

    OracleIdentity {
        x25519_secret,
        x25519_public,
        ed25519_secret,
        ed25519_public,
    }
}

fn independent_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; len];
    hkdf.expand(info, &mut output).expect("reviewed HKDF size");
    output
}

fn independent_hmac(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn independent_x25519(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    *X25519StaticSecret::from(*secret)
        .diffie_hellman(&X25519PublicKey::from(*public))
        .as_bytes()
}

fn independent_pad(plaintext: &[u8]) -> Vec<u8> {
    let total = (plaintext.len() + 4).div_ceil(256) * 256;
    let mut padded = vec![0u8; total];
    padded[..4].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
    padded[4..4 + plaintext.len()].copy_from_slice(plaintext);
    padded
}

fn independent_encrypt(
    message_key: &[u8; 32],
    nonce: &[u8; 24],
    padded_plaintext: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(message_key).expect("32-byte fixture key");
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: padded_plaintext,
                aad: associated_data,
            },
        )
        .expect("fixed fixture encryption")
}

fn client_associated_data(
    alice_identity: &[u8; 32],
    bob_identity: &[u8; 32],
    initial_prefix: &[u8],
) -> Vec<u8> {
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(CLIENT_AD_DOMAIN);
    associated_data.extend_from_slice(&(CONVERSATION_ID.len() as u32).to_be_bytes());
    associated_data.extend_from_slice(CONVERSATION_ID.as_bytes());
    associated_data.extend_from_slice(alice_identity);
    associated_data.extend_from_slice(bob_identity);
    associated_data.extend_from_slice(&(initial_prefix.len() as u32).to_be_bytes());
    associated_data.extend_from_slice(initial_prefix);
    associated_data
}

fn final_ratchet_aad(client_ad: &[u8], ratchet_header: &[u8]) -> Vec<u8> {
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(RATCHET_AD_DOMAIN);
    associated_data.extend_from_slice(&(client_ad.len() as u32).to_be_bytes());
    associated_data.extend_from_slice(client_ad);
    associated_data.extend_from_slice(ratchet_header);
    associated_data
}

fn fixture_artifacts() -> FixtureArtifacts {
    let bob_spk_secret = sequence::<32>(0x00);
    let bob_opk_secret = sequence::<32>(0x20);
    let alice_x3dh_ephemeral_secret = sequence::<32>(0x40);
    let alice_initial_ratchet_secret = sequence::<32>(0x60);
    let xchacha_nonce = sequence::<24>(0x80);
    let bob_next_ratchet_secret = sequence::<32>(0xa0);

    let alice_oracle = independent_identity(ALICE_MNEMONIC);
    let bob_oracle = independent_identity(BOB_MNEMONIC);
    let alice = IdentityKeyPair::from_mnemonic(ALICE_MNEMONIC).expect("Alice fixture mnemonic");
    let bob = IdentityKeyPair::from_mnemonic(BOB_MNEMONIC).expect("Bob fixture mnemonic");
    assert_eq!(alice.x25519_public_bytes(), alice_oracle.x25519_public);
    assert_eq!(alice.ed25519_public_bytes(), alice_oracle.ed25519_public);
    assert_eq!(bob.x25519_public_bytes(), bob_oracle.x25519_public);
    assert_eq!(bob.ed25519_public_bytes(), bob_oracle.ed25519_public);

    let bob_spk_public =
        *X25519PublicKey::from(&X25519StaticSecret::from(bob_spk_secret)).as_bytes();
    let bob_opk_public =
        *X25519PublicKey::from(&X25519StaticSecret::from(bob_opk_secret)).as_bytes();
    let mut signature_input = b"veil-x3dh-spk-v1\0".to_vec();
    signature_input.extend_from_slice(&bob_spk_public);
    assert_eq!(
        x3dh::signed_prekey_signature_message(&bob_spk_public),
        signature_input,
        "production SPK encoder must match the independently composed v1 preimage"
    );
    let bob_signing = Ed25519SigningKey::from_bytes(&bob_oracle.ed25519_secret);
    let signed_prekey_signature = bob_signing.sign(&signature_input).to_bytes();
    assert_eq!(
        bob.ed25519_signing_key().sign(&signature_input).to_bytes(),
        signed_prekey_signature
    );

    let bundle = PreKeyBundle {
        identity_key: bob_oracle.x25519_public,
        signing_key: bob_oracle.ed25519_public,
        signed_prekey: bob_spk_public,
        signed_prekey_signature,
        signed_prekey_id: SIGNED_PREKEY_ID,
        one_time_prekey: Some(bob_opk_public),
        one_time_prekey_id: Some(ONE_TIME_PREKEY_ID),
    };
    let mut forged_bundle = bundle.clone();
    forged_bundle.signed_prekey_signature[0] ^= 0x80;
    assert!(x3dh::initiate_with_ephemeral_secret_for_test(
        &alice,
        &forged_bundle,
        &alice_x3dh_ephemeral_secret,
    )
    .is_err());

    let alice_x3dh = x3dh::initiate_with_ephemeral_secret_for_test(
        &alice,
        &bundle,
        &alice_x3dh_ephemeral_secret,
    )
    .expect("fixture X3DH initiator");
    let alice_ephemeral_public =
        *X25519PublicKey::from(&X25519StaticSecret::from(alice_x3dh_ephemeral_secret)).as_bytes();
    assert_eq!(alice_x3dh.ephemeral_public, alice_ephemeral_public);

    let dh1 = independent_x25519(&alice_oracle.x25519_secret, &bob_spk_public);
    let dh2 = independent_x25519(&alice_x3dh_ephemeral_secret, &bob_oracle.x25519_public);
    let dh3 = independent_x25519(&alice_x3dh_ephemeral_secret, &bob_spk_public);
    let dh4 = independent_x25519(&alice_x3dh_ephemeral_secret, &bob_opk_public);
    let mut x3dh_concat = Vec::with_capacity(128);
    for dh in [&dh1, &dh2, &dh3, &dh4] {
        x3dh_concat.extend_from_slice(dh);
    }
    let x3dh_secret_vec = independent_hkdf(&[0u8; 32], &x3dh_concat, X3DH_INFO, 32);
    let x3dh_secret: [u8; 32] = x3dh_secret_vec.try_into().expect("32-byte X3DH secret");
    let mut x3dh_ad = [0u8; 64];
    x3dh_ad[..32].copy_from_slice(&alice_oracle.x25519_public);
    x3dh_ad[32..].copy_from_slice(&bob_oracle.x25519_public);
    assert_eq!(alice_x3dh.shared_secret, x3dh_secret);
    assert_eq!(alice_x3dh.associated_data, x3dh_ad);

    let bob_spk = SignedPreKey {
        secret: X25519StaticSecret::from(bob_spk_secret),
        public: X25519PublicKey::from(bob_spk_public),
        id: SIGNED_PREKEY_ID,
        signature: signed_prekey_signature,
    };
    let bob_opk = OneTimePreKey {
        secret: X25519StaticSecret::from(bob_opk_secret),
        public: X25519PublicKey::from(bob_opk_public),
        id: ONE_TIME_PREKEY_ID,
    };
    let bob_x3dh = x3dh::respond(
        &bob,
        &bob_spk,
        Some(&bob_opk),
        &alice_oracle.x25519_public,
        &alice_ephemeral_public,
    )
    .expect("fixture X3DH responder");
    assert_eq!(bob_x3dh.shared_secret, x3dh_secret);
    assert_eq!(bob_x3dh.associated_data, x3dh_ad);

    let ratchet_dh = independent_x25519(&alice_initial_ratchet_secret, &bob_spk_public);
    let ratchet_kdf = independent_hkdf(&x3dh_secret, &ratchet_dh, RATCHET_INFO, 64);
    let ratchet_root: [u8; 32] = ratchet_kdf[..32].try_into().expect("root key");
    let sending_chain: [u8; 32] = ratchet_kdf[32..].try_into().expect("sending chain key");
    let message_key = independent_hmac(&sending_chain, b"\x01");
    let next_sending_chain = independent_hmac(&sending_chain, b"\x02");
    let alice_ratchet_public =
        *X25519PublicKey::from(&X25519StaticSecret::from(alice_initial_ratchet_secret)).as_bytes();
    let bob_next_ratchet_public =
        *X25519PublicKey::from(&X25519StaticSecret::from(bob_next_ratchet_secret)).as_bytes();
    let bob_next_ratchet_dh = independent_x25519(&bob_next_ratchet_secret, &alice_ratchet_public);
    let responder_post_kdf =
        independent_hkdf(&ratchet_root, &bob_next_ratchet_dh, RATCHET_INFO, 64);
    let responder_post_root: [u8; 32] = responder_post_kdf[..32]
        .try_into()
        .expect("responder post root key");
    let responder_post_sending_chain: [u8; 32] = responder_post_kdf[32..]
        .try_into()
        .expect("responder post sending chain key");
    let expected_ratchet_header = MessageHeader {
        ratchet_key: alice_ratchet_public,
        n: 0,
        pn: 0,
    };
    let mut ratchet_header_bytes = Vec::with_capacity(41);
    ratchet_header_bytes.push(0x02);
    ratchet_header_bytes.extend_from_slice(&alice_ratchet_public);
    ratchet_header_bytes.extend_from_slice(&0u32.to_be_bytes());
    ratchet_header_bytes.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        expected_ratchet_header.to_bytes(),
        ratchet_header_bytes,
        "production ratchet encoder must match literal v2 || key || nBE || pnBE"
    );
    assert_eq!(
        MessageHeader::from_bytes(&ratchet_header_bytes).expect("canonical ratchet header"),
        expected_ratchet_header
    );

    let mut initial_prefix = Vec::with_capacity(41);
    initial_prefix.push(0x01);
    initial_prefix.extend_from_slice(&alice_ephemeral_public);
    initial_prefix.extend_from_slice(&SIGNED_PREKEY_ID.to_be_bytes());
    initial_prefix.extend_from_slice(&ONE_TIME_PREKEY_ID.to_be_bytes());
    let mut full_header = initial_prefix.clone();
    full_header.extend_from_slice(&ratchet_header_bytes);

    let client_ad = client_associated_data(
        &alice_oracle.x25519_public,
        &bob_oracle.x25519_public,
        &initial_prefix,
    );
    let final_aad = final_ratchet_aad(&client_ad, &ratchet_header_bytes);
    assert_eq!(initial_prefix.len(), 41);
    assert_eq!(ratchet_header_bytes.len(), 41);
    assert_eq!(full_header.len(), 82);
    assert_eq!(client_ad.len(), 172);
    assert_eq!(final_aad.len(), 239);

    let mut inner_plaintext = Vec::with_capacity(1 + TEXT.len());
    inner_plaintext.push(0x00);
    inner_plaintext.extend_from_slice(TEXT.as_bytes());
    let padded_plaintext = independent_pad(&inner_plaintext);
    let ciphertext =
        independent_encrypt(&message_key, &xchacha_nonce, &padded_plaintext, &final_aad);
    let mut transport = Vec::with_capacity(24 + ciphertext.len());
    transport.extend_from_slice(&xchacha_nonce);
    transport.extend_from_slice(&ciphertext);
    assert_eq!(inner_plaintext.len(), 15);
    assert_eq!(padded_plaintext.len(), 256);
    assert_eq!(ciphertext.len(), 272);
    assert_eq!(transport.len(), 296);

    let pending_initial = PendingInitialHeaderFixture {
        ephemeral_public: alice_ephemeral_public,
        signed_prekey_id: SIGNED_PREKEY_ID,
        one_time_prekey_id: Some(ONE_TIME_PREKEY_ID),
    };
    let pending_initial_json =
        serde_json::to_vec(&pending_initial).expect("pending initial header JSON");

    let mut initiator = RatchetSession::init_initiator_with_secret_for_test(
        &x3dh_secret,
        &bob_spk_public,
        &alice_initial_ratchet_secret,
    );
    let initiator_before = initiator
        .serialize()
        .expect("initiator before serialization");
    let (production_header, _random_transport) = initiator
        .encrypt_with_ad(&inner_plaintext, &client_ad)
        .expect("production fixture header/state advance");
    assert_eq!(production_header, expected_ratchet_header);
    let initiator_after = initiator
        .serialize()
        .expect("initiator after serialization");
    let mut responder =
        RatchetSession::init_responder(&x3dh_secret, &bob_spk_secret, &bob_spk_public);
    let responder_before = responder
        .serialize()
        .expect("responder before serialization");
    assert_eq!(
        responder
            .decrypt_with_ad_and_next_ratchet_secret_for_test(
                &expected_ratchet_header,
                &transport,
                &client_ad,
                &bob_next_ratchet_secret,
            )
            .expect("deterministic production responder transition"),
        inner_plaintext
    );
    let responder_after = responder
        .serialize()
        .expect("responder after serialization");
    let responder_after_value: Value =
        serde_json::from_slice(&responder_after).expect("responder after JSON");
    assert_eq!(
        responder_after_value,
        json!({
            "dh_sending_secret": b64(&bob_next_ratchet_secret),
            "dh_sending_public": bob_next_ratchet_public,
            "dh_receiving": alice_ratchet_public,
            "root_key": responder_post_root,
            "sending_chain_key": responder_post_sending_chain,
            "receiving_chain_key": next_sending_chain,
            "send_count": 0,
            "recv_count": 1,
            "prev_send_count": 0,
            "skipped_keys": {}
        }),
        "independent primitive derivation must explain every responder post-state field"
    );
    let responder_after_before_reuse_attempt = responder_after.clone();
    let ignored_secret_error = responder
        .decrypt_with_ad_and_next_ratchet_secret_for_test(
            &expected_ratchet_header,
            &transport,
            &client_ad,
            &bob_next_ratchet_secret,
        )
        .expect_err("the fixed next secret must not be silently ignored without a DH step");
    assert!(ignored_secret_error.contains("must be consumed exactly once, got 0"));
    assert_eq!(
        responder
            .serialize()
            .expect("post-state after rejected reuse"),
        responder_after_before_reuse_attempt
    );

    let value = json!({
        "metadata": {
            "status": "EVIDENCE CHECKPOINT ONLY — Phase 5S remains open.",
            "schema": "veil.direct-v1.crypto-transcript",
            "version": 1,
            "encoding": "All *_b64 values use padded RFC 4648 standard Base64.",
            "immutability": "v1.json is byte-frozen by LF policy, SHA256SUMS, and a compiled digest assertion.",
            "security_notice": "Every secret and mnemonic is deterministic public test material and MUST NOT be used for a real identity or session.",
            "scope": [
                "One Alice-to-Bob Direct text message with an X3DH OPK and the authenticated Double Ratchet v2 wire header.",
                "Separately composed primitive recomputation plus production X3DH respond, header parse/serialize, rollback-safe decrypt, and exact initiator/responder pre/post session serialization evidence."
            ],
            "open_findings": [
                "VeilClient::establish_session accepts a peer_identity_key argument separately from bundle.identity_key without proving equality.",
                "Double Ratchet dh_ratchet_step_with_next_secret does not yet reject non-contributory X25519 results.",
                "VeilClient does not directly consume X3DHResult.associated_data when constructing Direct message AD.",
                "Direct message AD does not yet bind exact origin, user ID, or device ID.",
                "Non-empty skipped-key HashMap JSON is noncanonical and malformed entries are silently skipped during deserialization."
            ]
        },
        "inputs": {
            "alice_mnemonic": ALICE_MNEMONIC,
            "bob_mnemonic": BOB_MNEMONIC,
            "conversation_id": CONVERSATION_ID,
            "text": TEXT,
            "signed_prekey_id": SIGNED_PREKEY_ID,
            "one_time_prekey_id": ONE_TIME_PREKEY_ID,
            "bob_signed_prekey_secret_b64": b64(&bob_spk_secret),
            "bob_one_time_prekey_secret_b64": b64(&bob_opk_secret),
            "alice_x3dh_ephemeral_secret_b64": b64(&alice_x3dh_ephemeral_secret),
            "alice_initial_ratchet_secret_b64": b64(&alice_initial_ratchet_secret),
            "bob_next_ratchet_secret_b64": b64(&bob_next_ratchet_secret),
            "xchacha_nonce_b64": b64(&xchacha_nonce)
        },
        "expected": {
            "identities": {
                "alice": {
                    "x25519_public_b64": b64(&alice_oracle.x25519_public),
                    "ed25519_public_b64": b64(&alice_oracle.ed25519_public)
                },
                "bob": {
                    "x25519_public_b64": b64(&bob_oracle.x25519_public),
                    "ed25519_public_b64": b64(&bob_oracle.ed25519_public)
                }
            },
            "prekeys": {
                "signed_public_b64": b64(&bob_spk_public),
                "signed_signature_input_b64": b64(&signature_input),
                "signed_signature_b64": b64(&signed_prekey_signature),
                "one_time_public_b64": b64(&bob_opk_public)
            },
            "x3dh": {
                "alice_ephemeral_public_b64": b64(&alice_ephemeral_public),
                "dh1_b64": b64(&dh1),
                "dh2_b64": b64(&dh2),
                "dh3_b64": b64(&dh3),
                "dh4_b64": b64(&dh4),
                "dh_concat_b64": b64(&x3dh_concat),
                "shared_secret_b64": b64(&x3dh_secret),
                "associated_data_b64": b64(&x3dh_ad)
            },
            "ratchet": {
                "alice_initial_public_b64": b64(&alice_ratchet_public),
                "initial_dh_b64": b64(&ratchet_dh),
                "root_key_b64": b64(&ratchet_root),
                "sending_chain_key_b64": b64(&sending_chain),
                "message_key_b64": b64(&message_key),
                "next_sending_chain_key_b64": b64(&next_sending_chain),
                "bob_next_public_b64": b64(&bob_next_ratchet_public),
                "bob_next_dh_b64": b64(&bob_next_ratchet_dh),
                "responder_post_root_key_b64": b64(&responder_post_root),
                "responder_post_sending_chain_key_b64": b64(&responder_post_sending_chain),
                "responder_post_receiving_chain_key_b64": b64(&next_sending_chain)
            },
            "headers": {
                "pending_initial_json_b64": b64(&pending_initial_json),
                "initial_prefix_b64": b64(&initial_prefix),
                "ratchet_b64": b64(&ratchet_header_bytes),
                "full_b64": b64(&full_header)
            },
            "payload": {
                "inner_plaintext_b64": b64(&inner_plaintext),
                "padded_plaintext_b64": b64(&padded_plaintext),
                "client_associated_data_b64": b64(&client_ad),
                "final_aead_associated_data_b64": b64(&final_aad),
                "ciphertext_b64": b64(&ciphertext),
                "transport_b64": b64(&transport)
            },
            "sessions": {
                "initiator_before_message_json_b64": b64(&initiator_before),
                "initiator_after_message_json_b64": b64(&initiator_after),
                "responder_before_message_json_b64": b64(&responder_before),
                "responder_after_message_json_b64": b64(&responder_after)
            },
            "lengths": {
                "initial_prefix": initial_prefix.len(),
                "ratchet_header": ratchet_header_bytes.len(),
                "full_header": full_header.len(),
                "client_associated_data": client_ad.len(),
                "final_aead_associated_data": final_aad.len(),
                "inner_plaintext": inner_plaintext.len(),
                "padded_plaintext": padded_plaintext.len(),
                "ciphertext": ciphertext.len(),
                "transport": transport.len()
            }
        }
    });

    FixtureArtifacts {
        value,
        responder_before,
        ratchet_header: expected_ratchet_header,
        transport,
        client_ad,
        inner_plaintext,
    }
}

fn assert_failed_decrypt_does_not_mutate(
    artifacts: &FixtureArtifacts,
    rejected_header: &MessageHeader,
    rejected_transport: &[u8],
    rejected_associated_data: &[u8],
) {
    let mut responder =
        RatchetSession::deserialize(&artifacts.responder_before).expect("fixture responder state");
    assert!(responder
        .decrypt_with_ad(
            rejected_header,
            rejected_transport,
            rejected_associated_data,
        )
        .is_err());
    assert_eq!(
        responder.serialize().expect("responder after rejection"),
        artifacts.responder_before,
        "an unauthenticated packet must not mutate the responder ratchet"
    );
    assert_eq!(
        responder
            .decrypt_with_ad(
                &artifacts.ratchet_header,
                &artifacts.transport,
                &artifacts.client_ad,
            )
            .expect("authentic retry after rejection"),
        artifacts.inner_plaintext
    );
}

#[test]
fn direct_v1_fixture_matches_independent_primitives_and_production_boundaries() {
    let artifacts = fixture_artifacts();
    let fixture_bytes = include_bytes!("../../test-vectors/direct-v1/v1.json");
    assert!(
        !fixture_bytes.contains(&b'\r'),
        "fixture must contain LF only"
    );
    assert_eq!(fixture_bytes.last(), Some(&b'\n'));
    let digest = hex::encode(Sha256::digest(fixture_bytes));
    assert_eq!(digest, REVIEWED_FIXTURE_SHA256);
    assert_eq!(
        include_str!("../../test-vectors/direct-v1/SHA256SUMS"),
        format!("{REVIEWED_FIXTURE_SHA256}  v1.json\n")
    );
    let fixture: Value = serde_json::from_slice(fixture_bytes).expect("valid v1 fixture JSON");
    assert_eq!(fixture, artifacts.value);

    let mut wrong_ad = artifacts.client_ad.clone();
    wrong_ad[0] ^= 0x01;
    assert_failed_decrypt_does_not_mutate(
        &artifacts,
        &artifacts.ratchet_header,
        &artifacts.transport,
        &wrong_ad,
    );

    let mut wrong_header = artifacts.ratchet_header.clone();
    wrong_header.n = 1;
    assert_failed_decrypt_does_not_mutate(
        &artifacts,
        &wrong_header,
        &artifacts.transport,
        &artifacts.client_ad,
    );

    let mut wrong_transport = artifacts.transport.clone();
    *wrong_transport
        .last_mut()
        .expect("fixture authentication tag") ^= 0x01;
    assert_failed_decrypt_does_not_mutate(
        &artifacts,
        &artifacts.ratchet_header,
        &wrong_transport,
        &artifacts.client_ad,
    );
}
