//! Canonical Direct v2 session and message transcripts.
//!
//! Direct v1 authenticated the conversation and account X25519 keys but did
//! not commit to the Node origin, account UUIDs, devices, binding revisions,
//! or the exact X3DH attempt. V2 makes those values an immutable session
//! coordinate and derives a fresh secret from the X3DH result plus that
//! coordinate. Every Double Ratchet AEAD then commits to the resulting session
//! ID and direction, preventing cross-Node, cross-account, cross-device, and
//! cross-session replay even when opaque server identifiers collide.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const DIRECT_SESSION_DOMAIN_V2: &[u8] = b"veil.direct.session.v2\0";
const DIRECT_X3DH_KDF_INFO_V2: &[u8] = b"veil.direct.x3dh.v2\0";
const DIRECT_MESSAGE_AD_DOMAIN_V2: &[u8] = b"veil.direct.message.v2\0";
const MAX_CANONICAL_ORIGIN_BYTES_V2: usize = 512;
const MAX_WIRE_PREFIX_BYTES_V2: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectAccountCoordinateV2 {
    pub user_id: String,
    pub identity_key: [u8; 32],
    pub signing_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectDeviceCoordinateV2 {
    pub device_id: [u8; 16],
    pub binding_version: u64,
    pub capabilities: u64,
    pub status: u8,
    pub identity_key: [u8; 32],
    pub signing_key: [u8; 32],
    #[serde(with = "serde_array_64")]
    pub account_signature: [u8; 64],
}

mod serde_array_64 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_slice().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<u8>::deserialize(deserializer)?;
        value
            .try_into()
            .map_err(|value: Vec<u8>| D::Error::invalid_length(value.len(), &"64 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectParticipantCoordinateV2 {
    pub account: DirectAccountCoordinateV2,
    pub device: DirectDeviceCoordinateV2,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectSessionContextV2 {
    pub canonical_server_origin: String,
    pub conversation_id: String,
    pub initiator: DirectParticipantCoordinateV2,
    pub responder: DirectParticipantCoordinateV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectInitialKeyAgreementV2 {
    pub ephemeral_public: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectSessionTranscriptV2 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectSessionBindingRecordV2 {
    version: u8,
    context: DirectSessionContextV2,
    agreement: DirectInitialKeyAgreementV2,
    session_id: [u8; 32],
    local_is_initiator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectSessionStateV2 {
    record: DirectSessionBindingRecordV2,
    transcript: DirectSessionTranscriptV2,
}

impl DirectSessionContextV2 {
    pub(crate) fn initial_transcript(
        &self,
        agreement: DirectInitialKeyAgreementV2,
    ) -> Result<DirectSessionTranscriptV2, String> {
        validate_context(self)?;
        if agreement.ephemeral_public == [0u8; 32] {
            return Err("Direct v2 ephemeral key is all zero".to_string());
        }
        if agreement.signed_prekey_id == 0 || agreement.one_time_prekey_id == Some(0) {
            return Err("Direct v2 prekey id is zero".to_string());
        }

        let origin = self.canonical_server_origin.as_bytes();
        let origin_len =
            u16::try_from(origin.len()).map_err(|_| "Direct v2 origin is oversized".to_string())?;
        let conversation = canonical_uuid_bytes("Direct v2 conversation", &self.conversation_id)?;
        let initiator_user = canonical_uuid_bytes(
            "Direct v2 initiator account",
            &self.initiator.account.user_id,
        )?;
        let responder_user = canonical_uuid_bytes(
            "Direct v2 responder account",
            &self.responder.account.user_id,
        )?;

        let mut bytes = Vec::with_capacity(
            DIRECT_SESSION_DOMAIN_V2.len()
                + 2
                + origin.len()
                + 16
                + (16 + 32 + 32 + 16 + 8 + 8 + 1 + 32 + 32 + 64) * 2
                + 32
                + 4
                + 1
                + 4,
        );
        bytes.extend_from_slice(DIRECT_SESSION_DOMAIN_V2);
        bytes.extend_from_slice(&origin_len.to_be_bytes());
        bytes.extend_from_slice(origin);
        bytes.extend_from_slice(&conversation);
        append_participant(&mut bytes, &initiator_user, &self.initiator);
        append_participant(&mut bytes, &responder_user, &self.responder);
        bytes.extend_from_slice(&agreement.ephemeral_public);
        bytes.extend_from_slice(&agreement.signed_prekey_id.to_be_bytes());
        match agreement.one_time_prekey_id {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id.to_be_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        let session_id = Sha256::digest(&bytes).into();
        Ok(DirectSessionTranscriptV2 { bytes, session_id })
    }
}

impl DirectSessionTranscriptV2 {
    pub(crate) fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Domain-separate the v1 X3DH output into a v2 session secret. The v1
    /// `associated_data` is consumed here rather than discarded, and the
    /// transcript hash is the HKDF salt, so changing any session coordinate
    /// produces an unrelated Double Ratchet root.
    pub(crate) fn derive_session_secret(
        &self,
        raw_x3dh_shared_secret: &[u8; 32],
        x3dh_associated_data: &[u8; 64],
    ) -> Result<[u8; 32], String> {
        if *raw_x3dh_shared_secret == [0u8; 32] {
            return Err("Direct v2 X3DH secret is all zero".to_string());
        }
        let mut info = Zeroizing::new(Vec::with_capacity(
            DIRECT_X3DH_KDF_INFO_V2.len() + 4 + self.bytes.len() + x3dh_associated_data.len(),
        ));
        info.extend_from_slice(DIRECT_X3DH_KDF_INFO_V2);
        let transcript_len = u32::try_from(self.bytes.len())
            .map_err(|_| "Direct v2 transcript is oversized".to_string())?;
        info.extend_from_slice(&transcript_len.to_be_bytes());
        info.extend_from_slice(&self.bytes);
        info.extend_from_slice(x3dh_associated_data);
        let mut derived = Zeroizing::new(veil_crypto::kdf::hkdf_sha256(
            &self.session_id,
            raw_x3dh_shared_secret,
            &info,
            32,
        ));
        if derived.len() != 32 {
            return Err("Direct v2 HKDF returned an invalid length".to_string());
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&derived);
        derived.zeroize();
        Ok(secret)
    }

    pub(crate) fn message_associated_data(
        &self,
        sender_device_id: &[u8; 16],
        recipient_device_id: &[u8; 16],
        wire_prefix: &[u8],
    ) -> Result<Vec<u8>, String> {
        if *sender_device_id == [0u8; 16]
            || *recipient_device_id == [0u8; 16]
            || sender_device_id == recipient_device_id
        {
            return Err("Direct v2 message has invalid device direction".to_string());
        }
        if wire_prefix.is_empty() || wire_prefix.len() > MAX_WIRE_PREFIX_BYTES_V2 {
            return Err("Direct v2 wire prefix is empty or oversized".to_string());
        }
        let prefix_len = u32::try_from(wire_prefix.len())
            .map_err(|_| "Direct v2 wire prefix is oversized".to_string())?;
        let mut ad = Vec::with_capacity(
            DIRECT_MESSAGE_AD_DOMAIN_V2.len() + 32 + 16 + 16 + 4 + wire_prefix.len(),
        );
        ad.extend_from_slice(DIRECT_MESSAGE_AD_DOMAIN_V2);
        ad.extend_from_slice(&self.session_id);
        ad.extend_from_slice(sender_device_id);
        ad.extend_from_slice(recipient_device_id);
        ad.extend_from_slice(&prefix_len.to_be_bytes());
        ad.extend_from_slice(wire_prefix);
        Ok(ad)
    }
}

impl DirectSessionStateV2 {
    pub(crate) fn new(
        context: DirectSessionContextV2,
        agreement: DirectInitialKeyAgreementV2,
        local_is_initiator: bool,
    ) -> Result<Self, String> {
        let transcript = context.initial_transcript(agreement)?;
        let record = DirectSessionBindingRecordV2 {
            version: 2,
            context,
            agreement,
            session_id: transcript.session_id(),
            local_is_initiator,
        };
        let state = Self { record, transcript };
        state.validate_local_orientation()?;
        Ok(state)
    }

    pub(crate) fn from_store_blob(
        blob: &veil_store::db::DirectSessionBindingBlobV2,
    ) -> Result<Self, String> {
        if blob.binding_data.is_empty() || blob.binding_data.len() > 4096 {
            return Err("Direct v2 stored binding is empty or oversized".to_string());
        }
        let record: DirectSessionBindingRecordV2 = serde_json::from_slice(&blob.binding_data)
            .map_err(|_| "Direct v2 stored binding JSON is invalid".to_string())?;
        if record.version != 2 {
            return Err("Direct v2 stored binding has an unknown version".to_string());
        }
        let state = Self::new(
            record.context.clone(),
            record.agreement,
            record.local_is_initiator,
        )?;
        if state.record.session_id != record.session_id
            || record.session_id != blob.session_id
            || state.peer().account.identity_key != blob.peer_identity_key
            || state.local().device.device_id != blob.local_device_id
            || state.peer().device.device_id != blob.peer_device_id
        {
            return Err("Direct v2 stored binding commitments disagree".to_string());
        }
        Ok(state)
    }

    pub(crate) fn to_store_blob(
        &self,
    ) -> Result<veil_store::db::DirectSessionBindingBlobV2, String> {
        self.validate_local_orientation()?;
        let binding_data = serde_json::to_vec(&self.record)
            .map_err(|_| "serialize Direct v2 session binding".to_string())?;
        if binding_data.is_empty() || binding_data.len() > 4096 {
            return Err("Direct v2 serialized binding is empty or oversized".to_string());
        }
        Ok(veil_store::db::DirectSessionBindingBlobV2 {
            peer_identity_key: self.peer().account.identity_key,
            session_id: self.record.session_id,
            local_device_id: self.local().device.device_id,
            peer_device_id: self.peer().device.device_id,
            binding_data,
        })
    }

    pub(crate) fn transcript(&self) -> &DirectSessionTranscriptV2 {
        &self.transcript
    }

    pub(crate) fn context(&self) -> &DirectSessionContextV2 {
        &self.record.context
    }

    pub(crate) fn session_id(&self) -> [u8; 32] {
        self.record.session_id
    }

    pub(crate) fn local(&self) -> &DirectParticipantCoordinateV2 {
        if self.record.local_is_initiator {
            &self.record.context.initiator
        } else {
            &self.record.context.responder
        }
    }

    pub(crate) fn peer(&self) -> &DirectParticipantCoordinateV2 {
        if self.record.local_is_initiator {
            &self.record.context.responder
        } else {
            &self.record.context.initiator
        }
    }

    fn validate_local_orientation(&self) -> Result<(), String> {
        if self.local().account.user_id == self.peer().account.user_id
            || self.local().device.device_id == self.peer().device.device_id
        {
            return Err("Direct v2 local/peer orientation is ambiguous".to_string());
        }
        Ok(())
    }
}

fn append_participant(
    bytes: &mut Vec<u8>,
    user_id: &[u8; 16],
    participant: &DirectParticipantCoordinateV2,
) {
    bytes.extend_from_slice(user_id);
    bytes.extend_from_slice(&participant.account.identity_key);
    bytes.extend_from_slice(&participant.account.signing_key);
    bytes.extend_from_slice(&participant.device.device_id);
    bytes.extend_from_slice(&participant.device.binding_version.to_be_bytes());
    bytes.extend_from_slice(&participant.device.capabilities.to_be_bytes());
    bytes.push(participant.device.status);
    bytes.extend_from_slice(&participant.device.identity_key);
    bytes.extend_from_slice(&participant.device.signing_key);
    bytes.extend_from_slice(&participant.device.account_signature);
}

fn validate_context(context: &DirectSessionContextV2) -> Result<(), String> {
    validate_canonical_origin(&context.canonical_server_origin)?;
    let conversation = canonical_uuid_bytes("Direct v2 conversation", &context.conversation_id)?;
    let initiator = canonical_uuid_bytes(
        "Direct v2 initiator account",
        &context.initiator.account.user_id,
    )?;
    let responder = canonical_uuid_bytes(
        "Direct v2 responder account",
        &context.responder.account.user_id,
    )?;
    if initiator == responder || conversation == initiator || conversation == responder {
        return Err("Direct v2 account/conversation coordinates collide".to_string());
    }
    validate_participant("initiator", &context.initiator)?;
    validate_participant("responder", &context.responder)?;
    if context.initiator.device.device_id == context.responder.device.device_id {
        return Err("Direct v2 device IDs collide".to_string());
    }
    Ok(())
}

fn validate_participant(
    label: &str,
    participant: &DirectParticipantCoordinateV2,
) -> Result<(), String> {
    if participant.account.identity_key == [0u8; 32]
        || participant.account.signing_key == [0u8; 32]
        || participant.account.identity_key == participant.account.signing_key
        || participant.device.device_id == [0u8; 16]
        || participant.device.binding_version == 0
        || participant.device.capabilities == 0
        || participant.device.status != crate::device_identity::DEVICE_BINDING_STATUS_ACTIVE
        || participant.device.identity_key == [0u8; 32]
        || participant.device.signing_key == [0u8; 32]
        || participant.device.identity_key == participant.device.signing_key
        || participant.device.account_signature == [0u8; 64]
    {
        return Err(format!("Direct v2 {label} coordinate is invalid"));
    }
    let binding = crate::device_identity::device_binding_signing_bytes(
        &participant.account.identity_key,
        &participant.account.signing_key,
        &participant.device.device_id,
        participant.device.binding_version,
        &participant.device.identity_key,
        &participant.device.signing_key,
        participant.device.capabilities,
        participant.device.status,
    );
    if !veil_crypto::signature::verify(
        &participant.account.signing_key,
        &binding,
        &participant.device.account_signature,
    ) {
        return Err(format!(
            "Direct v2 {label} device binding signature is invalid"
        ));
    }
    Ok(())
}

fn canonical_uuid_bytes(label: &str, value: &str) -> Result<[u8; 16], String> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| format!("{label} UUID is invalid"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(format!("{label} UUID is not canonical"));
    }
    Ok(*parsed.as_bytes())
}

fn validate_canonical_origin(origin: &str) -> Result<(), String> {
    if origin.is_empty() || origin.len() > MAX_CANONICAL_ORIGIN_BYTES_V2 {
        return Err("Direct v2 origin is empty, oversized, or non-ASCII".to_string());
    }
    crate::auth_contract::CanonicalNodeOriginV1::parse(origin)
        .map_err(|_| "Direct v2 origin is not canonical".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::IdentityKeyPair;

    type ContextMutation = Box<dyn Fn(&mut DirectSessionContextV2)>;

    fn participant(
        seed: u8,
        user_id: &str,
        account: &IdentityKeyPair,
    ) -> DirectParticipantCoordinateV2 {
        let account_identity = account.x25519_public_bytes();
        let account_signing = account.ed25519_public_bytes();
        let device_id = [seed + 2; 16];
        let device_identity = [seed + 3; 32];
        let device_signing = [seed + 4; 32];
        let binding_version = u64::from(seed);
        let capabilities = crate::device_identity::REQUIRED_DEVICE_CAPABILITIES;
        let status = crate::device_identity::DEVICE_BINDING_STATUS_ACTIVE;
        let binding = crate::device_identity::device_binding_signing_bytes(
            &account_identity,
            &account_signing,
            &device_id,
            binding_version,
            &device_identity,
            &device_signing,
            capabilities,
            status,
        );
        DirectParticipantCoordinateV2 {
            account: DirectAccountCoordinateV2 {
                user_id: user_id.to_string(),
                identity_key: account_identity,
                signing_key: account_signing,
            },
            device: DirectDeviceCoordinateV2 {
                device_id,
                binding_version,
                capabilities,
                status,
                identity_key: device_identity,
                signing_key: device_signing,
                account_signature: veil_crypto::signature::sign(account, &binding),
            },
        }
    }

    fn context() -> DirectSessionContextV2 {
        let initiator = IdentityKeyPair::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let responder = IdentityKeyPair::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        DirectSessionContextV2 {
            canonical_server_origin: "https://node.example.test:443".to_string(),
            conversation_id: "550e8400-e29b-41d4-a716-446655440010".to_string(),
            initiator: participant(1, "550e8400-e29b-41d4-a716-446655440001", &initiator),
            responder: participant(11, "550e8400-e29b-41d4-a716-446655440002", &responder),
        }
    }

    fn agreement() -> DirectInitialKeyAgreementV2 {
        DirectInitialKeyAgreementV2 {
            ephemeral_public: [0x51; 32],
            signed_prekey_id: 7,
            one_time_prekey_id: Some(9),
        }
    }

    #[test]
    fn session_id_and_secret_commit_every_security_coordinate() {
        let base = context();
        let base_transcript = base.initial_transcript(agreement()).unwrap();
        let base_id = base_transcript.session_id();
        let base_secret = base_transcript
            .derive_session_secret(&[0x71; 32], &[0x72; 64])
            .unwrap();

        let mutations: Vec<ContextMutation> = vec![
            Box::new(|c| c.canonical_server_origin = "https://other.example.test:443".into()),
            Box::new(|c| c.conversation_id = "550e8400-e29b-41d4-a716-446655440011".into()),
            Box::new(|c| {
                c.initiator.account.user_id = "550e8400-e29b-41d4-a716-446655440003".into()
            }),
            Box::new(|c| c.initiator.account.identity_key[0] ^= 1),
            Box::new(|c| c.initiator.account.signing_key[0] ^= 1),
            Box::new(|c| c.initiator.device.device_id[0] ^= 1),
            Box::new(|c| c.initiator.device.binding_version += 1),
            Box::new(|c| c.initiator.device.capabilities ^= 1 << 8),
            Box::new(|c| c.initiator.device.identity_key[0] ^= 1),
            Box::new(|c| c.initiator.device.signing_key[0] ^= 1),
            Box::new(|c| c.initiator.device.account_signature[0] ^= 1),
            Box::new(|c| {
                c.responder.account.user_id = "550e8400-e29b-41d4-a716-446655440004".into()
            }),
            Box::new(|c| c.responder.account.identity_key[0] ^= 1),
            Box::new(|c| c.responder.account.signing_key[0] ^= 1),
            Box::new(|c| c.responder.device.device_id[0] ^= 1),
            Box::new(|c| c.responder.device.binding_version += 1),
            Box::new(|c| c.responder.device.capabilities ^= 1 << 8),
            Box::new(|c| c.responder.device.identity_key[0] ^= 1),
            Box::new(|c| c.responder.device.signing_key[0] ^= 1),
            Box::new(|c| c.responder.device.account_signature[0] ^= 1),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            let Ok(transcript) = changed.initial_transcript(agreement()) else {
                // A changed account/device binding without a matching account
                // signature is rejected even earlier than key derivation.
                continue;
            };
            assert_ne!(transcript.session_id(), base_id);
            assert_ne!(
                transcript
                    .derive_session_secret(&[0x71; 32], &[0x72; 64])
                    .unwrap(),
                base_secret
            );
        }

        let mut changed_agreement = agreement();
        changed_agreement.ephemeral_public[0] ^= 1;
        assert_ne!(
            base.initial_transcript(changed_agreement)
                .unwrap()
                .session_id(),
            base_id
        );
        changed_agreement = agreement();
        changed_agreement.signed_prekey_id += 1;
        assert_ne!(
            base.initial_transcript(changed_agreement)
                .unwrap()
                .session_id(),
            base_id
        );
        changed_agreement = agreement();
        changed_agreement.one_time_prekey_id = None;
        assert_ne!(
            base.initial_transcript(changed_agreement)
                .unwrap()
                .session_id(),
            base_id
        );
    }

    #[test]
    fn message_ad_commits_session_direction_and_wire_prefix() {
        let transcript = context().initial_transcript(agreement()).unwrap();
        let sender = context().initiator.device.device_id;
        let recipient = context().responder.device.device_id;
        let prefix = [0x11, 0x22, 0x33];
        let ad = transcript
            .message_associated_data(&sender, &recipient, &prefix)
            .unwrap();
        assert_ne!(
            ad,
            transcript
                .message_associated_data(&recipient, &sender, &prefix)
                .unwrap()
        );
        let mut changed_prefix = prefix;
        changed_prefix[2] ^= 1;
        assert_ne!(
            ad,
            transcript
                .message_associated_data(&sender, &recipient, &changed_prefix)
                .unwrap()
        );
    }

    #[test]
    fn noncanonical_or_ambiguous_coordinates_fail_closed() {
        for origin in [
            "https://node.example.test",
            "https://NODE.example.test:443",
            "https://node.example.test:443/alias",
            "http://node.example.test:80",
        ] {
            let mut invalid = context();
            invalid.canonical_server_origin = origin.to_string();
            assert!(invalid.initial_transcript(agreement()).is_err());
        }
        let mut invalid = context();
        invalid.responder.account.user_id = invalid.initiator.account.user_id.clone();
        assert!(invalid.initial_transcript(agreement()).is_err());
        let mut invalid = context();
        invalid.responder.device.device_id = invalid.initiator.device.device_id;
        assert!(invalid.initial_transcript(agreement()).is_err());
        let mut invalid_agreement = agreement();
        invalid_agreement.signed_prekey_id = 0;
        assert!(context().initial_transcript(invalid_agreement).is_err());
    }
}
