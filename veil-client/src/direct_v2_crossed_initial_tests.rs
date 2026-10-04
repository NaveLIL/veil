//! Characterization of the unresolved crossed-INITIAL liveness limitation.
//! Both initiators commit before either receives the other's first packet.
//! A protocol fix must preserve these exact durable envelopes; replacing a
//! sticky session is not an acceptable way to make this test decrypt.

use super::*;
use std::path::{Path, PathBuf};

const ORIGIN: &str = "https://crossed-initial.example.test:443";
const CONVERSATION: &str = "90000000-0000-4000-8000-000000000001";
const ALICE: &str = "90000000-0000-4000-8000-000000000002";
const BOB: &str = "90000000-0000-4000-8000-000000000003";
const ALICE_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

struct TestDatabase(PathBuf);

impl Drop for TestDatabase {
    fn drop(&mut self) {
        for path in [
            self.0.clone(),
            self.0.with_extension("db-wal"),
            self.0.with_extension("db-shm"),
        ] {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn open_client(mnemonic: &str, path: &Path, user_id: &str) -> VeilClient {
    let mut client = VeilClient::new();
    client.init_with_mnemonic(mnemonic, path).unwrap();
    client.authenticated_user_id = Some(user_id.to_string());
    client.authenticated_server_origin = Some(ORIGIN.to_string());
    client
}

fn install_directory(client: &mut VeilClient, user_id: &str, response: &[u8]) {
    crate::direct::install_authenticated_direct_directory_page(
        client, ORIGIN, user_id, None, response,
    )
    .unwrap();
}

fn bundle(client: &mut VeilClient) -> x3dh::PreKeyBundle {
    let prekeys = client.generate_prekeys().unwrap();
    let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
    x3dh::PreKeyBundle {
        identity_key: client.identity_key().unwrap(),
        signing_key: client.signing_key().unwrap(),
        signed_prekey: prekeys.spk_public,
        signed_prekey_signature: prekeys.spk_signature,
        signed_prekey_id: prekeys.spk_id,
        one_time_prekey: Some(one_time_prekey),
        one_time_prekey_id: Some(one_time_prekey_id),
    }
}

fn coordinate(client: &VeilClient) -> DirectDeviceCoordinateV2 {
    let binding = client.device_identity.as_ref().unwrap().binding();
    DirectDeviceCoordinateV2 {
        device_id: binding.device_id,
        binding_version: binding.version,
        capabilities: binding.capabilities,
        status: binding.status,
        identity_key: binding.device_identity_key,
        signing_key: binding.device_signing_key,
        account_signature: binding.account_signature,
    }
}

fn security(
    sender: &VeilClient,
    target: &VeilClient,
    send: &proto::SendMessage,
) -> MessageSecurityContextV1 {
    let binding = sender.device_identity.as_ref().unwrap().binding();
    MessageSecurityContextV1::DirectV2(DirectMessageSecurityContextV2 {
        sender_user_id: sender.authenticated_user_id.as_ref().unwrap().clone(),
        sender_device_id: binding.device_id,
        sender_binding_version: binding.version,
        sender_device_identity_key: binding.device_identity_key,
        sender_device_signing_key: binding.device_signing_key,
        sender_device_capabilities: binding.capabilities,
        sender_device_binding_status: binding.status,
        sender_account_signature: binding.account_signature,
        target_device_id: target.device_id,
        target_binding_version: target.device_identity.as_ref().unwrap().binding().version,
        direct_session_id: send.direct_session_id.as_slice().try_into().unwrap(),
    })
}

fn durable_payload(client: &VeilClient, id: &str) -> Vec<u8> {
    client
        .db()
        .unwrap()
        .load_pending_direct_message_outbox_v1(
            &client.current_direct_outbox_scope_v1().unwrap(),
            10,
        )
        .unwrap()
        .into_iter()
        .find(|entry| entry.client_message_id == id)
        .unwrap()
        .exact_send_message_payload
        .clone()
}

#[derive(Debug, PartialEq, Eq)]
struct SessionFingerprint {
    ratchet_digest: [u8; 32],
    runtime_ratchet_digest: [u8; 32],
    revision: u64,
    session_id: [u8; 32],
    binding_digest: [u8; 32],
    pending_headers: Vec<([u8; 32], Vec<u8>)>,
    unused_opk_ids: Vec<u32>,
    durable_prekey_count: usize,
}

fn fingerprint(client: &VeilClient, peer: &[u8; 32]) -> SessionFingerprint {
    use sha2::Digest as _;
    let db = client.db().unwrap();
    let stored = db
        .load_ratchet_session_with_revision_v1(peer)
        .unwrap()
        .unwrap();
    let runtime = Zeroizing::new(
        client
            .ratchet_sessions
            .get(peer)
            .unwrap()
            .serialize()
            .unwrap(),
    );
    let bindings = db.load_all_direct_session_bindings_v2().unwrap();
    let binding = bindings
        .iter()
        .find(|entry| entry.peer_identity_key == *peer)
        .unwrap();
    let mut unused_opk_ids: Vec<_> = client.otk_secrets.keys().copied().collect();
    unused_opk_ids.sort_unstable();
    SessionFingerprint {
        ratchet_digest: sha2::Sha256::digest(&stored.session_data).into(),
        runtime_ratchet_digest: sha2::Sha256::digest(runtime.as_slice()).into(),
        revision: stored.revision,
        session_id: binding.session_id,
        binding_digest: sha2::Sha256::digest(&binding.binding_data).into(),
        pending_headers: db.load_pending_initial_headers().unwrap(),
        unused_opk_ids,
        durable_prekey_count: db.load_local_prekeys().unwrap().len(),
    }
}

fn assert_crossed_rejection(
    receiver: &mut VeilClient,
    sender_key: &[u8; 32],
    send: &proto::SendMessage,
    security: &MessageSecurityContextV1,
    before: &SessionFingerprint,
) {
    let error = receiver
        .decrypt_from_with_security_context(
            sender_key,
            CONVERSATION,
            &send.header,
            &send.ciphertext,
            Some(security),
        )
        .unwrap_err();
    assert!(
        error.contains("outer context differs from the sticky session"),
        "unexpected stop: {error}"
    );
    assert_eq!(
        &fingerprint(receiver, sender_key),
        before,
        "rejection must preserve ratchet, OPKs and pending INITIAL"
    );
    assert_eq!(
        receiver.direct_conversation_availability_v1(CONVERSATION),
        DirectConversationAvailabilityV1::Available,
        "the limitation is non-convergence, not a proven storage failure"
    );
}

#[tokio::test]
async fn crossed_initial_attempts_fail_closed_and_remain_nonconvergent_after_restart() {
    // Declare cleanup guards before clients so SQLCipher closes before removal.
    let alice_path = TestDatabase(
        std::env::temp_dir().join(format!("veil-crossed-alice-{}.db", uuid::Uuid::new_v4())),
    );
    let bob_path = TestDatabase(
        std::env::temp_dir().join(format!("veil-crossed-bob-{}.db", uuid::Uuid::new_v4())),
    );
    let mut alice = open_client(ALICE_MNEMONIC, &alice_path.0, ALICE);
    let mut bob = open_client(BOB_MNEMONIC, &bob_path.0, BOB);
    let alice_key = alice.identity_key().unwrap();
    let bob_key = bob.identity_key().unwrap();
    let alice_signing = alice.signing_key().unwrap();
    let bob_signing = bob.signing_key().unwrap();
    let response = serde_json::to_vec(&serde_json::json!({
        "count":1, "next_cursor":null, "conversations":[{
            "id":CONVERSATION, "conv_type":0, "name":null, "server_id":null,
            "created_at":"2026-10-04T00:00:00Z", "members":[
                {"user_id":ALICE,"username":"alice","identity_key":hex::encode(alice_key),"signing_key":hex::encode(alice_signing)},
                {"user_id":BOB,"username":"bob","identity_key":hex::encode(bob_key),"signing_key":hex::encode(bob_signing)}
            ]
        }]
    })).unwrap();
    install_directory(&mut alice, ALICE, &response);
    install_directory(&mut bob, BOB, &response);
    let alice_bundle = bundle(&mut alice);
    let bob_bundle = bundle(&mut bob);
    let alice_context = alice
        .direct_v2_initiator_context(CONVERSATION, BOB, bob_key, bob_signing, coordinate(&bob))
        .unwrap();
    let bob_context = bob
        .direct_v2_initiator_context(
            CONVERSATION,
            ALICE,
            alice_key,
            alice_signing,
            coordinate(&alice),
        )
        .unwrap();
    // Deterministic scheduling barrier: both initiators are durable before any
    // incoming packet. No sleeps, threads, or lucky network ordering required.
    alice
        .establish_session_classified_v2(&bob_key, &bob_bundle, alice_context)
        .unwrap();
    bob.establish_session_classified_v2(&alice_key, &alice_bundle, bob_context)
        .unwrap();
    assert_ne!(
        alice.direct_v2_sessions[&bob_key].session_id(),
        bob.direct_v2_sessions[&alice_key].session_id()
    );

    // Accept real native outbox intents with unavailable wire queues. These
    // envelopes must survive any future convergence design byte for byte.
    alice.test_only_install_queued_connection().close();
    bob.test_only_install_queued_connection().close();
    let alice_queued = alice
        .enqueue_direct_text_v1(CONVERSATION, "alice crossed first")
        .await
        .unwrap();
    let bob_queued = bob
        .enqueue_direct_text_v1(CONVERSATION, "bob crossed first")
        .await
        .unwrap();
    assert!(!alice_queued.transport_enqueued && !bob_queued.transport_enqueued);
    let alice_bytes = durable_payload(&alice, &alice_queued.client_message_id);
    let bob_bytes = durable_payload(&bob, &bob_queued.client_message_id);
    let alice_send = proto::SendMessage::decode(alice_bytes.as_slice()).unwrap();
    let bob_send = proto::SendMessage::decode(bob_bytes.as_slice()).unwrap();
    assert_eq!(alice_send.header[0], HEADER_INITIAL_V2);
    assert_eq!(bob_send.header[0], HEADER_INITIAL_V2);
    let alice_security = security(&alice, &bob, &alice_send);
    let bob_security = security(&bob, &alice, &bob_send);
    let alice_before = fingerprint(&alice, &bob_key);
    let bob_before = fingerprint(&bob, &alice_key);
    assert_crossed_rejection(
        &mut bob,
        &alice_key,
        &alice_send,
        &alice_security,
        &bob_before,
    );
    assert_crossed_rejection(
        &mut alice,
        &bob_key,
        &bob_send,
        &bob_security,
        &alice_before,
    );
    assert_eq!(
        durable_payload(&alice, &alice_queued.client_message_id),
        alice_bytes
    );
    assert_eq!(
        durable_payload(&bob, &bob_queued.client_message_id),
        bob_bytes
    );
    drop(alice);
    drop(bob);

    let mut alice = open_client(ALICE_MNEMONIC, &alice_path.0, ALICE);
    let mut bob = open_client(BOB_MNEMONIC, &bob_path.0, BOB);
    install_directory(&mut alice, ALICE, &response);
    install_directory(&mut bob, BOB, &response);
    alice.test_only_install_queued_connection().close();
    bob.test_only_install_queued_connection().close();
    assert_eq!(fingerprint(&alice, &bob_key), alice_before);
    assert_eq!(fingerprint(&bob, &alice_key), bob_before);
    for (client, user, identity, signing) in [
        (&mut alice, BOB, bob_key, bob_signing),
        (&mut bob, ALICE, alice_key, alice_signing),
    ] {
        assert_eq!(
            crate::direct::install_authenticated_direct_prekey_bundle(
                client,
                user,
                identity,
                signing,
                b"not-json"
            )
            .unwrap(),
            crate::direct::DirectPreKeyInstallResult::AlreadyEstablished,
            "repeated prekey fetch cannot replace a committed session"
        );
    }
    assert_crossed_rejection(
        &mut bob,
        &alice_key,
        &alice_send,
        &alice_security,
        &bob_before,
    );
    assert_crossed_rejection(
        &mut alice,
        &bob_key,
        &bob_send,
        &bob_security,
        &alice_before,
    );
    assert_eq!(
        durable_payload(&alice, &alice_queued.client_message_id),
        alice_bytes
    );
    assert_eq!(
        durable_payload(&bob, &bob_queued.client_message_id),
        bob_bytes
    );
}
