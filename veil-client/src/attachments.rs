use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use veil_store::models::MessageAttachment;
use zeroize::{Zeroize, Zeroizing};

const PAYLOAD_PREFIX: &[u8] = b"veil-attachment-message/v1\n";
const WRAP_AAD_DOMAIN: &[u8] = b"veil-attachment-key-wrap/v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"veil-attachment-descriptor/v1\0";
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireAttachmentV1 {
    pub media_id: String,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone)]
pub struct OutgoingAttachmentV1 {
    pub media_id: String,
    pub file_name: String,
    pub detected_mime: String,
    pub format_version: u8,
    pub nonce_prefix: [u8; 16],
    pub chunk_count: u64,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
    pub content_key: [u8; 32],
}

impl Drop for OutgoingAttachmentV1 {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

#[derive(Debug)]
pub struct OpenedAttachmentMessageV1 {
    pub text: String,
    pub attachments: Vec<MessageAttachment>,
}

pub type BuiltAttachmentMessageV1 = (
    Zeroizing<Vec<u8>>,
    Vec<WireAttachmentV1>,
    Vec<MessageAttachment>,
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateEnvelopeV1 {
    schema: String,
    text: String,
    attachments: Vec<PrivateAttachmentV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateAttachmentV1 {
    media_id: String,
    file_name: String,
    detected_mime: String,
    format_version: u8,
    nonce_prefix: String,
    chunk_count: u64,
    plaintext_size: u64,
    ciphertext_size: u64,
    wrapping_key: String,
    descriptor_sha256: String,
}

pub fn build_outgoing_attachment_message_v1(
    conversation_id: &str,
    text: &str,
    attachments: Vec<OutgoingAttachmentV1>,
) -> Result<BuiltAttachmentMessageV1, String> {
    if conversation_id.is_empty()
        || attachments.is_empty()
        || attachments.len() > MAX_ATTACHMENTS_PER_MESSAGE
    {
        return Err("invalid attachment message scope or count".to_string());
    }
    validate_text(text)?;
    let mut private = Vec::with_capacity(attachments.len());
    let mut wire = Vec::with_capacity(attachments.len());
    let mut stored = Vec::with_capacity(attachments.len());
    let mut media_ids = std::collections::HashSet::new();

    for (ordinal, attachment) in attachments.into_iter().enumerate() {
        validate_attachment_fields(
            &attachment.media_id,
            &attachment.file_name,
            &attachment.detected_mime,
            attachment.format_version,
            attachment.chunk_count,
            attachment.plaintext_size,
            attachment.ciphertext_size,
        )?;
        if !media_ids.insert(attachment.media_id.clone()) {
            return Err("duplicate attachment media id".to_string());
        }
        let ordinal = u8::try_from(ordinal).map_err(|_| "attachment ordinal overflow")?;
        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(wrapping_key.as_mut());
        let aad = wrap_aad(conversation_id, ordinal, &attachment)?;
        let (encrypted_key, nonce) =
            veil_crypto::aead::encrypt_with_aad(&wrapping_key, &attachment.content_key, &aad)?;
        let descriptor = WireAttachmentV1 {
            media_id: attachment.media_id.clone(),
            encrypted_key,
            nonce: nonce.to_vec(),
            size: attachment.ciphertext_size,
            content_type: "application/octet-stream".to_string(),
        };
        let descriptor_sha256 = descriptor_digest(ordinal, &descriptor)?;
        private.push(PrivateAttachmentV1 {
            media_id: attachment.media_id.clone(),
            file_name: attachment.file_name.clone(),
            detected_mime: attachment.detected_mime.clone(),
            format_version: attachment.format_version,
            nonce_prefix: B64.encode(attachment.nonce_prefix),
            chunk_count: attachment.chunk_count,
            plaintext_size: attachment.plaintext_size,
            ciphertext_size: attachment.ciphertext_size,
            wrapping_key: B64.encode(wrapping_key.as_slice()),
            descriptor_sha256: B64.encode(descriptor_sha256),
        });
        stored.push(MessageAttachment {
            ordinal,
            media_id: attachment.media_id.clone(),
            file_name: attachment.file_name.clone(),
            detected_mime: attachment.detected_mime.clone(),
            format_version: attachment.format_version,
            nonce_prefix: attachment.nonce_prefix,
            chunk_count: attachment.chunk_count,
            plaintext_size: attachment.plaintext_size,
            ciphertext_size: attachment.ciphertext_size,
            content_key: attachment.content_key,
        });
        wire.push(descriptor);
    }

    let envelope = PrivateEnvelopeV1 {
        schema: "veil-attachment-message/v1".to_string(),
        text: text.to_string(),
        attachments: private,
    };
    let encoded = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize attachment message: {error}"))?;
    let total = PAYLOAD_PREFIX
        .len()
        .checked_add(encoded.len())
        .ok_or("attachment payload length overflow")?;
    if total > 32 * 1024 {
        return Err("attachment message metadata exceeds 32 KiB".to_string());
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(total));
    payload.extend_from_slice(PAYLOAD_PREFIX);
    payload.extend_from_slice(&encoded);
    Ok((payload, wire, stored))
}

pub fn open_attachment_message_v1(
    conversation_id: &str,
    plaintext: &[u8],
    wire: &[WireAttachmentV1],
) -> Result<OpenedAttachmentMessageV1, String> {
    if conversation_id.is_empty() || wire.is_empty() || wire.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err("invalid inbound attachment scope or count".to_string());
    }
    let json = plaintext
        .strip_prefix(PAYLOAD_PREFIX)
        .ok_or("attachment descriptors require an authenticated v1 payload")?;
    let envelope: PrivateEnvelopeV1 = serde_json::from_slice(json)
        .map_err(|error| format!("invalid attachment payload: {error}"))?;
    if envelope.schema != "veil-attachment-message/v1" || envelope.attachments.len() != wire.len() {
        return Err("attachment payload version or count mismatch".to_string());
    }
    validate_text(&envelope.text)?;
    let mut opened = Vec::with_capacity(wire.len());
    let mut media_ids = std::collections::HashSet::new();
    for (ordinal, (private, descriptor)) in envelope.attachments.into_iter().zip(wire).enumerate() {
        let ordinal = u8::try_from(ordinal).map_err(|_| "attachment ordinal overflow")?;
        validate_attachment_fields(
            &private.media_id,
            &private.file_name,
            &private.detected_mime,
            private.format_version,
            private.chunk_count,
            private.plaintext_size,
            private.ciphertext_size,
        )?;
        validate_wire_attachment(descriptor)?;
        if private.media_id != descriptor.media_id
            || private.ciphertext_size != descriptor.size
            || !media_ids.insert(private.media_id.clone())
        {
            return Err("attachment public/private binding mismatch".to_string());
        }
        let expected_digest: [u8; 32] =
            decode_exact_b64("attachment descriptor digest", &private.descriptor_sha256)?;
        if descriptor_digest(ordinal, descriptor)? != expected_digest {
            return Err("attachment descriptor commitment mismatch".to_string());
        }
        let wrapping_key: Zeroizing<[u8; 32]> = Zeroizing::new(decode_exact_b64(
            "attachment wrapping key",
            &private.wrapping_key,
        )?);
        let nonce: [u8; 24] = descriptor
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| "attachment wrap nonce must be 24 bytes")?;
        let nonce_prefix: [u8; 16] =
            decode_exact_b64("attachment nonce prefix", &private.nonce_prefix)?;
        let material = OutgoingAttachmentV1 {
            media_id: private.media_id.clone(),
            file_name: private.file_name.clone(),
            detected_mime: private.detected_mime.clone(),
            format_version: private.format_version,
            nonce_prefix,
            chunk_count: private.chunk_count,
            plaintext_size: private.plaintext_size,
            ciphertext_size: private.ciphertext_size,
            content_key: [0u8; 32],
        };
        let aad = wrap_aad(conversation_id, ordinal, &material)?;
        let mut content_key = Zeroizing::new(veil_crypto::aead::decrypt_with_aad(
            &wrapping_key,
            &descriptor.encrypted_key,
            &nonce,
            &aad,
        )?);
        if content_key.len() != 32 {
            return Err("unwrapped attachment key has invalid length".to_string());
        }
        let mut exact_key = [0u8; 32];
        exact_key.copy_from_slice(&content_key);
        content_key.zeroize();
        opened.push(MessageAttachment {
            ordinal,
            media_id: private.media_id,
            file_name: private.file_name,
            detected_mime: private.detected_mime,
            format_version: private.format_version,
            nonce_prefix,
            chunk_count: private.chunk_count,
            plaintext_size: private.plaintext_size,
            ciphertext_size: private.ciphertext_size,
            content_key: exact_key,
        });
    }
    Ok(OpenedAttachmentMessageV1 {
        text: envelope.text,
        attachments: opened,
    })
}

pub fn is_attachment_payload_v1(plaintext: &[u8]) -> bool {
    plaintext.starts_with(PAYLOAD_PREFIX)
}

fn validate_text(text: &str) -> Result<(), String> {
    if text.len() > 32 * 1024 {
        return Err("message text exceeds 32 KiB".to_string());
    }
    Ok(())
}

fn validate_attachment_fields(
    media_id: &str,
    file_name: &str,
    detected_mime: &str,
    format_version: u8,
    chunk_count: u64,
    plaintext_size: u64,
    ciphertext_size: u64,
) -> Result<(), String> {
    if media_id.len() != 32
        || !media_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || file_name.is_empty()
        || file_name.len() > 1024
        || file_name.chars().any(char::is_control)
        || file_name.contains('/')
        || file_name.contains('\\')
        || detected_mime.is_empty()
        || detected_mime.len() > 255
        || !detected_mime.is_ascii()
        || detected_mime.chars().any(char::is_whitespace)
        || format_version == 0
        || chunk_count == 0
        || chunk_count > 32_769
        || plaintext_size > 2 * 1024 * 1024 * 1024
        || !(16..=2_148_007_952).contains(&ciphertext_size)
    {
        return Err("invalid attachment metadata".to_string());
    }
    Ok(())
}

fn validate_wire_attachment(descriptor: &WireAttachmentV1) -> Result<(), String> {
    if descriptor.media_id.len() != 32
        || descriptor.encrypted_key.is_empty()
        || descriptor.encrypted_key.len() > 4096
        || descriptor.nonce.len() != 24
        || descriptor.content_type != "application/octet-stream"
        || descriptor.size < 16
        || descriptor.size > 2_148_007_952
    {
        return Err("invalid public attachment descriptor".to_string());
    }
    Ok(())
}

fn wrap_aad(
    conversation_id: &str,
    ordinal: u8,
    attachment: &OutgoingAttachmentV1,
) -> Result<Vec<u8>, String> {
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    append_bytes(&mut aad, conversation_id.as_bytes())?;
    aad.push(ordinal);
    append_bytes(&mut aad, attachment.media_id.as_bytes())?;
    append_bytes(&mut aad, attachment.file_name.as_bytes())?;
    append_bytes(&mut aad, attachment.detected_mime.as_bytes())?;
    aad.push(attachment.format_version);
    aad.extend_from_slice(&attachment.nonce_prefix);
    aad.extend_from_slice(&attachment.chunk_count.to_be_bytes());
    aad.extend_from_slice(&attachment.plaintext_size.to_be_bytes());
    aad.extend_from_slice(&attachment.ciphertext_size.to_be_bytes());
    Ok(aad)
}

fn descriptor_digest(ordinal: u8, descriptor: &WireAttachmentV1) -> Result<[u8; 32], String> {
    validate_wire_attachment(descriptor)?;
    let mut canonical = Vec::with_capacity(512);
    canonical.extend_from_slice(DESCRIPTOR_DOMAIN);
    canonical.push(ordinal);
    append_bytes(&mut canonical, descriptor.media_id.as_bytes())?;
    append_bytes(&mut canonical, &descriptor.encrypted_key)?;
    append_bytes(&mut canonical, &descriptor.nonce)?;
    canonical.extend_from_slice(&descriptor.size.to_be_bytes());
    append_bytes(&mut canonical, descriptor.content_type.as_bytes())?;
    Ok(Sha256::digest(canonical).into())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "attachment field length overflow")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_exact_b64<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    let decoded = B64
        .decode(value)
        .map_err(|_| format!("{label} is not canonical base64"))?;
    if B64.encode(&decoded) != value {
        return Err(format!("{label} is not canonical base64"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing() -> OutgoingAttachmentV1 {
        OutgoingAttachmentV1 {
            media_id: "0123456789abcdef0123456789abcdef".to_string(),
            file_name: "notes.txt".to_string(),
            detected_mime: "text/plain".to_string(),
            format_version: 2,
            nonce_prefix: [7u8; 16],
            chunk_count: 1,
            plaintext_size: 5,
            ciphertext_size: 21,
            content_key: [9u8; 32],
        }
    }

    #[test]
    fn attachment_round_trip_binds_every_public_descriptor() {
        let (payload, wire, stored) =
            build_outgoing_attachment_message_v1("conversation", "hello", vec![outgoing()])
                .unwrap();
        let opened = open_attachment_message_v1("conversation", &payload, &wire).unwrap();
        assert_eq!(opened.text, "hello");
        assert_eq!(opened.attachments[0].content_key, [9u8; 32]);
        assert_eq!(opened.attachments[0].file_name, "notes.txt");
        assert_eq!(stored[0].content_key, [9u8; 32]);
    }

    #[test]
    fn descriptor_substitution_and_cross_conversation_replay_fail_closed() {
        let (payload, mut wire, _) =
            build_outgoing_attachment_message_v1("conversation", "", vec![outgoing()]).unwrap();
        wire[0].size += 1;
        assert!(open_attachment_message_v1("conversation", &payload, &wire).is_err());
        let (_, wire, _) =
            build_outgoing_attachment_message_v1("conversation", "", vec![outgoing()]).unwrap();
        assert!(open_attachment_message_v1("other", &payload, &wire).is_err());
    }

    #[test]
    fn descriptors_never_downgrade_to_text() {
        let wire = vec![WireAttachmentV1 {
            media_id: "0123456789abcdef0123456789abcdef".to_string(),
            encrypted_key: vec![1],
            nonce: vec![2; 24],
            size: 16,
            content_type: "application/octet-stream".to_string(),
        }];
        assert!(open_attachment_message_v1("conversation", b"ordinary text", &wire).is_err());
    }
}
