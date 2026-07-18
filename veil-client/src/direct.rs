//! Shared authenticated Direct-message directory contracts.
//!
//! Desktop and mobile must install exactly the same origin-scoped account
//! directory before either surface is allowed to address or decrypt a DM.
//! Network transport deliberately stays outside this module: callers fetch a
//! bounded response from an authenticated, origin-bound REST request and hand
//! the exact response bytes to this fail-closed validator.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Deserialize;
use veil_store::models::{
    AccountSnapshot, AccountSnapshotSource, AuthenticatedDirectDirectoryEntry, ProfileLocator,
};

use crate::api::VeilClient;

pub const DIRECT_DIRECTORY_PAGE_LIMIT: usize = 100;
pub const DIRECT_DIRECTORY_RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
pub const DIRECT_DIRECTORY_MAX_PAGES: usize = 10_000;
pub const DIRECT_DIRECTORY_CURSOR_LIMIT: usize = 4_096;
pub const DIRECT_PREKEY_RESPONSE_LIMIT: usize = 64 * 1024;
const MAX_DIRECTORY_MEMBERS: usize = 1_024;
const MAX_DIRECTORY_USERNAME_BYTES: usize = 128;
const MAX_DIRECTORY_NAME_BYTES: usize = 256;
const MAX_CANONICAL_ORIGIN_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledDirectConversation {
    pub conversation_id: String,
    pub name: String,
    pub peer_user_id: String,
    pub peer_username: String,
    pub peer_identity_key: [u8; 32],
    pub peer_signing_key: [u8; 32],
    pub needs_prekey: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectDirectoryPageResult {
    pub conversations: Vec<InstalledDirectConversation>,
    pub next_cursor: Option<String>,
    pub skipped_non_direct: usize,
    pub validated_conversation_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct DirectDirectorySyncHistory {
    seen_conversation_ids: HashSet<String>,
    seen_cursors: HashSet<String>,
    pages: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPreKeyInstallResult {
    Established,
    AlreadyEstablished,
}

#[derive(Debug, Deserialize)]
struct ConversationPageWire {
    conversations: Vec<ConversationWire>,
    count: usize,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConversationWire {
    id: String,
    conv_type: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    server_id: Option<String>,
    created_at: String,
    members: Vec<DirectoryMemberWire>,
}

#[derive(Debug, Deserialize)]
struct DirectoryMemberWire {
    user_id: String,
    username: String,
    identity_key: String,
    signing_key: String,
}

#[derive(Debug, Deserialize)]
struct PreKeyBundleWire {
    identity_key: String,
    signing_key: String,
    signed_prekey: String,
    signed_prekey_signature: String,
    signed_prekey_id: u32,
    #[serde(default)]
    one_time_prekey: Option<String>,
    #[serde(default)]
    one_time_prekey_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedDirectoryMember {
    user_id: String,
    username: String,
    identity_key: [u8; 32],
    signing_key: [u8; 32],
}

#[derive(Debug)]
struct ValidatedDirectConversation {
    id: String,
    name: String,
    created_at: String,
    members: Vec<ValidatedDirectoryMember>,
    peer: ValidatedDirectoryMember,
}

#[derive(Debug)]
enum ValidatedConversation {
    Direct(Box<ValidatedDirectConversation>),
    Unsupported(Vec<ValidatedDirectoryMember>),
}

/// Validate and install one authenticated `/v1/conversations` page.
///
/// The complete page is validated before any durable write. Each accepted DM
/// is then committed to SQLCipher before process-local routing or trust pins
/// are published. A caller must keep chat gated until every page and every
/// conversation history has completed successfully.
///
/// The native transport owner must also revalidate the exact authenticated
/// origin/socket generation immediately before this function is called. Key
/// tuples alone cannot make a response from an earlier connection current.
pub fn install_authenticated_direct_directory_page(
    client: &mut VeilClient,
    canonical_server_origin: &str,
    authenticated_user_id: &str,
    current_cursor: Option<&str>,
    response: &[u8],
) -> Result<DirectDirectoryPageResult, String> {
    install_authenticated_direct_directory_page_inner(
        client,
        canonical_server_origin,
        authenticated_user_id,
        current_cursor,
        None,
        response,
    )
}

/// Tracked variant for a complete native sync epoch. It rejects cursor cycles,
/// conversation replay across page boundaries, and pagination beyond the
/// client cap before any page mutation is allowed.
pub fn install_authenticated_direct_directory_page_tracked(
    client: &mut VeilClient,
    canonical_server_origin: &str,
    authenticated_user_id: &str,
    current_cursor: Option<&str>,
    history: &mut DirectDirectorySyncHistory,
    response: &[u8],
) -> Result<DirectDirectoryPageResult, String> {
    if history.pages >= DIRECT_DIRECTORY_MAX_PAGES {
        return Err("conversation directory exceeds the page limit".to_string());
    }
    let result = install_authenticated_direct_directory_page_inner(
        client,
        canonical_server_origin,
        authenticated_user_id,
        current_cursor,
        Some(history),
        response,
    )?;
    history.pages = history
        .pages
        .checked_add(1)
        .ok_or("conversation directory page count overflow")?;
    for conversation_id in &result.validated_conversation_ids {
        history
            .seen_conversation_ids
            .insert(conversation_id.clone());
    }
    if let Some(next_cursor) = result.next_cursor.as_ref() {
        history.seen_cursors.insert(next_cursor.clone());
    }
    Ok(result)
}

fn install_authenticated_direct_directory_page_inner(
    client: &mut VeilClient,
    canonical_server_origin: &str,
    authenticated_user_id: &str,
    current_cursor: Option<&str>,
    history: Option<&DirectDirectorySyncHistory>,
    response: &[u8],
) -> Result<DirectDirectoryPageResult, String> {
    if response.len() > DIRECT_DIRECTORY_RESPONSE_LIMIT {
        return Err("conversation directory response exceeds the client limit".to_string());
    }
    validate_canonical_origin(canonical_server_origin)?;
    decode_canonical_uuid("authenticated directory user id", authenticated_user_id)?;
    validate_cursor("current directory cursor", current_cursor)?;

    let page: ConversationPageWire = serde_json::from_slice(response)
        .map_err(|error| format!("invalid conversation directory response: {error}"))?;
    if page.count != page.conversations.len() {
        return Err("conversation directory count mismatch".to_string());
    }
    if page.conversations.len() > DIRECT_DIRECTORY_PAGE_LIMIT {
        return Err("conversation directory page exceeds the client limit".to_string());
    }
    validate_next_cursor(
        current_cursor,
        page.next_cursor.as_deref(),
        page.conversations.len(),
    )?;
    if page
        .next_cursor
        .as_ref()
        .is_some_and(|cursor| history.is_some_and(|history| history.seen_cursors.contains(cursor)))
    {
        return Err("conversation directory cursor cycle detected".to_string());
    }

    let local_identity_key = client.identity_key()?;
    let local_signing_key = client.signing_key()?;
    let mut page_ids = HashSet::with_capacity(page.conversations.len());
    let mut validated = Vec::with_capacity(page.conversations.len());
    let mut validated_conversation_ids = Vec::with_capacity(page.conversations.len());
    for conversation in page.conversations {
        if !page_ids.insert(conversation.id.clone()) {
            return Err("conversation directory repeats a conversation in one page".to_string());
        }
        if history.is_some_and(|history| history.seen_conversation_ids.contains(&conversation.id)) {
            return Err("conversation directory repeats a conversation across pages".to_string());
        }
        validated_conversation_ids.push(conversation.id.clone());
        validated.push(validate_conversation(
            conversation,
            authenticated_user_id,
            local_identity_key,
            local_signing_key,
        )?);
    }
    validate_page_account_consistency(&validated)?;

    let mut direct_conversations = Vec::new();
    let mut skipped_non_direct = 0usize;
    for conversation in validated {
        match conversation {
            ValidatedConversation::Direct(conversation) => direct_conversations.push(conversation),
            ValidatedConversation::Unsupported(_) => {
                skipped_non_direct = skipped_non_direct
                    .checked_add(1)
                    .ok_or("non-direct conversation count overflow")?;
            }
        }
    }

    // Preflight every current runtime pin before SQLCipher accepts any member
    // from this page. No first item can win merely because it preceded a
    // conflicting item later in the authenticated response.
    for conversation in &direct_conversations {
        for member in &conversation.members {
            client.ensure_user_identity_binding_compatible(&member.user_id, member.identity_key)?;
            client.ensure_peer_signing_key_compatible(member.identity_key, member.signing_key)?;
        }
    }

    // Reassert the durable account/origin binding before accepting any server
    // directory data. This is idempotent for the authenticated account and
    // rejects a user/origin/key substitution atomically.
    client
        .db()
        .ok_or("database not initialized")?
        .bind_authenticated_self(
            canonical_server_origin,
            authenticated_user_id,
            &local_identity_key,
            &local_signing_key,
        )?;

    if !direct_conversations.is_empty() {
        let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let snapshots = direct_page_account_snapshots(
            &direct_conversations,
            canonical_server_origin,
            &observed_at,
        );
        let stored_conversations: Vec<AuthenticatedDirectDirectoryEntry> = direct_conversations
            .iter()
            .map(|conversation| AuthenticatedDirectDirectoryEntry {
                conversation_id: conversation.id.clone(),
                name: conversation.name.clone(),
                peer_user_id: conversation.peer.user_id.clone(),
                peer_identity_key: conversation.peer.identity_key,
                created_at: conversation.created_at.clone(),
            })
            .collect();
        let db = client.db().ok_or("database not initialized")?;
        db.upsert_identity_directory(&snapshots)?;
        db.upsert_directory_directs(canonical_server_origin, &stored_conversations)?;
    }

    // Durable page merge completed. Preflight every DM route before publishing
    // any runtime identity, sender authorization, or conversation binding.
    for conversation in &direct_conversations {
        client.ensure_dm_conversation_binding_compatible(
            &conversation.id,
            conversation.peer.identity_key,
        )?;
    }

    let mut installed = Vec::with_capacity(direct_conversations.len());
    for conversation in direct_conversations {
        installed.push(publish_direct_conversation(client, *conversation)?);
    }

    installed.sort_by(|left, right| left.conversation_id.cmp(&right.conversation_id));
    Ok(DirectDirectoryPageResult {
        conversations: installed,
        next_cursor: page.next_cursor,
        skipped_non_direct,
        validated_conversation_ids,
    })
}

/// Install one peer X3DH bundle obtained for an authenticated Direct member.
///
/// The peer account tuple must already be present in the process-local view
/// published by [`install_authenticated_direct_directory_page`]. Existing
/// sessions are never replaced: a fetched bundle may consume a server OPK,
/// but it cannot reset a durable Double Ratchet after an ACK was lost.
/// The native transport owner must reject a response whose authenticated
/// origin/socket generation is no longer current immediately before calling.
pub fn install_authenticated_direct_prekey_bundle(
    client: &mut VeilClient,
    peer_user_id: &str,
    expected_peer_identity_key: [u8; 32],
    expected_peer_signing_key: [u8; 32],
    response: &[u8],
) -> Result<DirectPreKeyInstallResult, String> {
    if response.len() > DIRECT_PREKEY_RESPONSE_LIMIT {
        return Err("Direct prekey response exceeds the client limit".to_string());
    }
    decode_canonical_uuid("Direct prekey peer user id", peer_user_id)?;
    if expected_peer_identity_key == [0u8; 32]
        || expected_peer_identity_key == client.identity_key()?
    {
        return Err("Direct prekey peer identity is invalid".to_string());
    }
    if client.known_user_identity(peer_user_id) != Some(expected_peer_identity_key) {
        return Err("Direct prekey peer is absent from the authenticated directory".to_string());
    }
    if !client.peer_signing_key_is_pinned(&expected_peer_identity_key, &expected_peer_signing_key) {
        return Err(
            "Direct prekey signing key is not pinned by the authenticated directory".to_string(),
        );
    }
    if client.has_session(&expected_peer_identity_key) {
        return Ok(DirectPreKeyInstallResult::AlreadyEstablished);
    }

    let wire: PreKeyBundleWire = serde_json::from_slice(response)
        .map_err(|error| format!("invalid Direct prekey response: {error}"))?;
    let identity_key =
        decode_canonical_b64_fixed::<32>("Direct prekey identity_key", &wire.identity_key)?;
    if identity_key != expected_peer_identity_key {
        return Err("Direct prekey identity does not match the authenticated peer".to_string());
    }
    let signing_key =
        decode_canonical_b64_fixed::<32>("Direct prekey signing_key", &wire.signing_key)?;
    if signing_key != expected_peer_signing_key {
        return Err("Direct prekey signing key does not match the authenticated peer".to_string());
    }
    if wire.signed_prekey_id == 0 {
        return Err("Direct signed prekey id must be non-zero".to_string());
    }
    let signed_prekey =
        decode_canonical_b64_fixed::<32>("Direct signed_prekey", &wire.signed_prekey)?;
    if signed_prekey == [0u8; 32] {
        return Err("Direct signed prekey must not be all zero".to_string());
    }
    let signed_prekey_signature = decode_canonical_b64_fixed::<64>(
        "Direct signed_prekey_signature",
        &wire.signed_prekey_signature,
    )?;
    let one_time_prekey = wire
        .one_time_prekey
        .as_deref()
        .map(|value| decode_canonical_b64_fixed::<32>("Direct one_time_prekey", value))
        .transpose()?;
    if one_time_prekey.is_some() != wire.one_time_prekey_id.is_some() {
        return Err("Direct prekey response contains an incomplete one-time prekey".to_string());
    }
    if one_time_prekey == Some([0u8; 32]) {
        return Err("Direct one-time prekey must not be all zero".to_string());
    }
    if wire.one_time_prekey_id == Some(0) {
        return Err("Direct one-time prekey id must be non-zero".to_string());
    }

    let bundle = veil_crypto::x3dh::PreKeyBundle {
        identity_key,
        signing_key,
        signed_prekey,
        signed_prekey_signature,
        signed_prekey_id: wire.signed_prekey_id,
        one_time_prekey,
        one_time_prekey_id: wire.one_time_prekey_id,
    };
    client.establish_session(&expected_peer_identity_key, &bundle)?;
    Ok(DirectPreKeyInstallResult::Established)
}

fn validate_conversation(
    conversation: ConversationWire,
    authenticated_user_id: &str,
    local_identity_key: [u8; 32],
    local_signing_key: [u8; 32],
) -> Result<ValidatedConversation, String> {
    decode_canonical_uuid("conversation directory id", &conversation.id)?;
    validate_utc_rfc3339_nano(
        "conversation directory created_at",
        &conversation.created_at,
    )?;
    if conversation.conv_type > 2 {
        return Err("conversation directory contains an unsupported type".to_string());
    }
    if conversation.server_id.as_deref().is_some_and(str::is_empty) {
        return Err("conversation directory contains an empty server id".to_string());
    }
    if let Some(server_id) = conversation.server_id.as_deref() {
        decode_canonical_uuid("conversation directory server id", server_id)?;
    }
    if (conversation.conv_type == 2) != conversation.server_id.is_some() {
        return Err("conversation directory type and server scope disagree".to_string());
    }
    if let Some(name) = conversation.name.as_deref() {
        validate_directory_text(
            "conversation directory name",
            name,
            MAX_DIRECTORY_NAME_BYTES,
            false,
        )?;
    }
    if conversation.members.is_empty() || conversation.members.len() > MAX_DIRECTORY_MEMBERS {
        return Err("conversation directory member count is invalid".to_string());
    }

    let mut user_ids = HashSet::with_capacity(conversation.members.len());
    let mut identity_owners = HashMap::with_capacity(conversation.members.len());
    let mut signing_owners = HashMap::with_capacity(conversation.members.len());
    let mut members = Vec::with_capacity(conversation.members.len());
    for member in conversation.members {
        decode_canonical_uuid("conversation directory member user id", &member.user_id)?;
        validate_directory_text(
            "conversation directory member username",
            &member.username,
            MAX_DIRECTORY_USERNAME_BYTES,
            false,
        )?;
        let identity_key = decode_lower_hex_fixed::<32>(
            "conversation directory member identity key",
            &member.identity_key,
        )?;
        let signing_key = decode_lower_hex_fixed::<32>(
            "conversation directory member signing key",
            &member.signing_key,
        )?;
        if identity_key == [0u8; 32] || signing_key == [0u8; 32] || identity_key == signing_key {
            return Err("conversation directory contains an invalid account key".to_string());
        }
        if !user_ids.insert(member.user_id.clone()) {
            return Err("conversation directory repeats a member".to_string());
        }
        if identity_owners
            .insert(identity_key, member.user_id.clone())
            .is_some()
        {
            return Err("conversation directory aliases an account identity".to_string());
        }
        if signing_owners
            .insert(signing_key, member.user_id.clone())
            .is_some()
        {
            return Err("conversation directory aliases an account signing key".to_string());
        }
        members.push(ValidatedDirectoryMember {
            user_id: member.user_id,
            username: member.username,
            identity_key,
            signing_key,
        });
    }

    let local = members
        .iter()
        .find(|member| member.user_id == authenticated_user_id)
        .ok_or("authenticated user is absent from the conversation directory")?;
    if local.identity_key != local_identity_key || local.signing_key != local_signing_key {
        return Err(
            "conversation directory substituted the authenticated account keys".to_string(),
        );
    }

    if conversation.conv_type != 0 {
        return Ok(ValidatedConversation::Unsupported(members));
    }
    if members.len() != 2 {
        return Err("Direct conversation must contain exactly two accounts".to_string());
    }
    let peer = members
        .iter()
        .find(|member| member.user_id != authenticated_user_id)
        .cloned()
        .ok_or("Direct conversation has no peer")?;
    let name = conversation
        .name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| peer.username.clone());

    Ok(ValidatedConversation::Direct(Box::new(
        ValidatedDirectConversation {
            id: conversation.id,
            name,
            created_at: conversation.created_at,
            members,
            peer,
        },
    )))
}

fn validate_page_account_consistency(
    conversations: &[ValidatedConversation],
) -> Result<(), String> {
    let mut accounts = HashMap::<String, ValidatedDirectoryMember>::new();
    let mut identity_owners = HashMap::<[u8; 32], String>::new();
    let mut signing_owners = HashMap::<[u8; 32], String>::new();
    let mut direct_peers = HashMap::<String, String>::new();

    for conversation in conversations {
        let members = match conversation {
            ValidatedConversation::Direct(conversation) => {
                if let Some(previous_conversation) =
                    direct_peers.insert(conversation.peer.user_id.clone(), conversation.id.clone())
                {
                    return Err(format!(
                        "conversation directory repeats one Direct peer in {previous_conversation} and {}",
                        conversation.id
                    ));
                }
                &conversation.members
            }
            ValidatedConversation::Unsupported(members) => members,
        };

        for member in members {
            if let Some(existing) = accounts.get(&member.user_id) {
                if existing != member {
                    return Err(
                        "conversation directory equivocates one account within a page".to_string(),
                    );
                }
            } else {
                accounts.insert(member.user_id.clone(), member.clone());
            }
            if identity_owners
                .get(&member.identity_key)
                .is_some_and(|owner| owner != &member.user_id)
            {
                return Err(
                    "conversation directory aliases one identity across page accounts".to_string(),
                );
            }
            identity_owners.insert(member.identity_key, member.user_id.clone());
            if signing_owners
                .get(&member.signing_key)
                .is_some_and(|owner| owner != &member.user_id)
            {
                return Err(
                    "conversation directory aliases one signing key across page accounts"
                        .to_string(),
                );
            }
            signing_owners.insert(member.signing_key, member.user_id.clone());
        }
    }
    Ok(())
}

fn direct_page_account_snapshots(
    conversations: &[Box<ValidatedDirectConversation>],
    canonical_server_origin: &str,
    observed_at: &str,
) -> Vec<AccountSnapshot> {
    let mut seen_user_ids = HashSet::new();
    conversations
        .iter()
        .flat_map(|conversation| conversation.members.iter())
        .filter(|member| seen_user_ids.insert(member.user_id.clone()))
        .map(|member| AccountSnapshot {
            locator: ProfileLocator {
                canonical_server_origin: canonical_server_origin.to_string(),
                user_id: member.user_id.clone(),
                identity_key: member.identity_key,
            },
            signing_key: member.signing_key,
            username: Some(member.username.clone()),
            display_name: None,
            profile_version: None,
            profile_origin: canonical_server_origin.to_string(),
            source: AccountSnapshotSource::AuthenticatedConversationDirectory,
            observed_at: observed_at.to_string(),
        })
        .collect()
}

fn publish_direct_conversation(
    client: &mut VeilClient,
    conversation: ValidatedDirectConversation,
) -> Result<InstalledDirectConversation, String> {
    for member in &conversation.members {
        client.remember_user_identity(&member.user_id, member.identity_key)?;
        client.pin_peer_signing_key(member.identity_key, member.signing_key)?;
    }
    client.replace_authorized_conversation_senders(
        &conversation.id,
        conversation
            .members
            .iter()
            .map(|member| member.identity_key),
    )?;
    client.bind_dm_conversation(&conversation.id, conversation.peer.identity_key)?;

    Ok(InstalledDirectConversation {
        conversation_id: conversation.id,
        name: conversation.name,
        peer_user_id: conversation.peer.user_id,
        peer_username: conversation.peer.username,
        peer_identity_key: conversation.peer.identity_key,
        peer_signing_key: conversation.peer.signing_key,
        needs_prekey: !client.has_session(&conversation.peer.identity_key),
    })
}

fn validate_next_cursor(
    current: Option<&str>,
    next: Option<&str>,
    item_count: usize,
) -> Result<(), String> {
    validate_cursor("next directory cursor", next)?;
    if let Some(next) = next {
        if current == Some(next) {
            return Err("server repeated the conversation directory cursor".to_string());
        }
        if item_count == 0 {
            return Err("server returned a cursor for an empty directory page".to_string());
        }
    }
    Ok(())
}

fn validate_cursor(field: &str, value: Option<&str>) -> Result<(), String> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > DIRECT_DIRECTORY_CURSOR_LIMIT
            || value.chars().any(char::is_control)
    }) {
        return Err(format!("{field} is empty, oversized, or contains controls"));
    }
    Ok(())
}

fn validate_canonical_origin(origin: &str) -> Result<(), String> {
    if origin.is_empty() || origin.len() > MAX_CANONICAL_ORIGIN_BYTES {
        return Err("invalid canonical server origin".to_string());
    }
    let parsed = url::Url::parse(origin).map_err(|_| "invalid canonical server origin")?;
    let host = parsed
        .host_str()
        .ok_or("invalid canonical server origin")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = parsed
        .port_or_known_default()
        .ok_or("invalid canonical server origin")?;
    if port == 0 {
        return Err("invalid canonical server origin".to_string());
    }
    let secure_transport = match parsed.scheme() {
        "https" => true,
        "http" => matches!(host, "localhost" | "127.0.0.1" | "::1"),
        _ => false,
    };
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let canonical = format!("{}://{}:{}", parsed.scheme(), authority, port);
    if parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
        || !secure_transport
        || canonical != origin
    {
        return Err("invalid canonical server origin".to_string());
    }
    Ok(())
}

fn decode_canonical_uuid(field: &str, value: &str) -> Result<[u8; 16], String> {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err(format!("{field} must be a canonical lowercase UUID"));
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    let decoded = decode_lower_hex_fixed(field, &compact)
        .map_err(|_| format!("{field} must be a canonical lowercase UUID"))?;
    if decoded == [0u8; 16] {
        return Err(format!("{field} must not be the nil UUID"));
    }
    Ok(decoded)
}

fn decode_lower_hex_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be exactly {N}-byte lowercase hex"));
    }
    hex::decode(value)
        .map_err(|error| format!("decode {field}: {error}"))?
        .try_into()
        .map_err(|_| format!("{field} must be exactly {N} bytes"))
}

fn decode_canonical_b64_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical standard base64"))?;
    if decoded.len() != N || BASE64_STANDARD.encode(&decoded) != value {
        return Err(format!(
            "{field} must be canonical standard base64 for exactly {N} bytes"
        ));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{field} must decode to exactly {N} bytes"))
}

fn validate_directory_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    if value.len() > max_bytes
        || (!allow_empty && value.is_empty())
        || value.chars().any(char::is_control)
    {
        return Err(format!("{field} is empty, oversized, or contains controls"));
    }
    Ok(())
}

fn validate_utc_rfc3339_nano(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let fixed_layout = bytes.len() >= 20
        && bytes.len() <= 30
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.last() == Some(&b'Z');
    if !fixed_layout {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16) || index == bytes.len() - 1 {
            continue;
        }
        if index == 19 && bytes.len() > 20 {
            if byte != b'.' {
                return Err(format!("{field} must be canonical UTC RFC3339Nano"));
            }
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(format!("{field} must be canonical UTC RFC3339Nano"));
        }
    }
    let parse_u8_component = |range: std::ops::Range<usize>| -> Result<u8, String> {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|part| part.parse::<u8>().ok())
            .ok_or_else(|| format!("{field} must be canonical UTC RFC3339Nano"))
    };
    let year = std::str::from_utf8(&bytes[0..4])
        .ok()
        .and_then(|part| part.parse::<u16>().ok())
        .ok_or_else(|| format!("{field} must be canonical UTC RFC3339Nano"))?;
    let month = parse_u8_component(5..7)?;
    let day = parse_u8_component(8..10)?;
    let hour = parse_u8_component(11..13)?;
    let minute = parse_u8_component(14..16)?;
    let second = parse_u8_component(17..19)?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    let fractional_is_canonical = bytes.len() == 20
        || (bytes.len() >= 22
            && bytes.len() <= 30
            && bytes[19] == b'.'
            && bytes[bytes.len() - 2] != b'0');
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month
        || hour > 23
        || minute > 59
        || second > 59
        || !fractional_is_canonical
    {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://veil.example.test:443";
    const SELF_USER: &str = "10000000-0000-4000-8000-000000000001";
    const PEER_USER: &str = "10000000-0000-4000-8000-000000000002";
    const PEER_TWO_USER: &str = "10000000-0000-4000-8000-000000000003";
    const CONVERSATION: &str = "20000000-0000-4000-8000-000000000001";
    const CONVERSATION_TWO: &str = "20000000-0000-4000-8000-000000000002";

    fn initialized_client() -> (VeilClient, std::path::PathBuf) {
        let mut client = VeilClient::new();
        let mnemonic = client.generate_mnemonic();
        let path =
            std::env::temp_dir().join(format!("veil-direct-directory-{}.db", uuid::Uuid::new_v4()));
        client.init_with_mnemonic(&mnemonic, &path).unwrap();
        (client, path)
    }

    fn member(
        user_id: &str,
        username: &str,
        identity: [u8; 32],
        signing: [u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "user_id": user_id,
            "username": username,
            "identity_key": hex::encode(identity),
            "signing_key": hex::encode(signing),
        })
    }

    fn page(conversations: Vec<serde_json::Value>, next_cursor: Option<&str>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "count": conversations.len(),
            "conversations": conversations,
            "next_cursor": next_cursor,
        }))
        .unwrap()
    }

    fn direct_conversation(
        local_identity: [u8; 32],
        local_signing: [u8; 32],
        peer_identity: [u8; 32],
        peer_signing: [u8; 32],
    ) -> serde_json::Value {
        direct_conversation_for(
            CONVERSATION,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            peer_identity,
            peer_signing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn direct_conversation_for(
        conversation_id: &str,
        peer_user_id: &str,
        peer_username: &str,
        local_identity: [u8; 32],
        local_signing: [u8; 32],
        peer_identity: [u8; 32],
        peer_signing: [u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "id": conversation_id,
            "conv_type": 0,
            "name": null,
            "server_id": null,
            "created_at": "2026-07-18T00:00:00Z",
            "members": [
                member(SELF_USER, "self", local_identity, local_signing),
                member(peer_user_id, peer_username, peer_identity, peer_signing),
            ],
        })
    }

    fn prekey_response(
        identity_key: [u8; 32],
        signing_key: [u8; 32],
        prekeys: &crate::api::PreKeySet,
    ) -> Vec<u8> {
        let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
        serde_json::to_vec(&serde_json::json!({
            "identity_key": BASE64_STANDARD.encode(identity_key),
            "signing_key": BASE64_STANDARD.encode(signing_key),
            "signed_prekey": BASE64_STANDARD.encode(prekeys.spk_public),
            "signed_prekey_signature": BASE64_STANDARD.encode(prekeys.spk_signature),
            "signed_prekey_id": prekeys.spk_id,
            "one_time_prekey": BASE64_STANDARD.encode(one_time_prekey),
            "one_time_prekey_id": one_time_prekey_id,
            "opk_low_warning": true,
            "opk_remaining": 9,
        }))
        .unwrap()
    }

    fn install_peer_directory(
        client: &mut VeilClient,
        peer_identity: [u8; 32],
        peer_signing: [u8; 32],
    ) {
        let response = page(
            vec![direct_conversation(
                client.identity_key().unwrap(),
                client.signing_key().unwrap(),
                peer_identity,
                peer_signing,
            )],
            None,
        );
        install_authenticated_direct_directory_page(client, ORIGIN, SELF_USER, None, &response)
            .unwrap();
    }

    #[test]
    fn installs_an_origin_scoped_direct_directory_before_publishing_routes() {
        let (mut client, path) = initialized_client();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let peer_identity = peer.x25519_public_bytes();
        let peer_signing = peer.ed25519_public_bytes();

        let result = install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(
                vec![direct_conversation(
                    local_identity,
                    local_signing,
                    peer_identity,
                    peer_signing,
                )],
                None,
            ),
        )
        .unwrap();

        assert_eq!(result.skipped_non_direct, 0);
        assert_eq!(result.next_cursor, None);
        assert_eq!(result.conversations.len(), 1);
        assert_eq!(result.conversations[0].peer_user_id, PEER_USER);
        assert_eq!(result.conversations[0].name, "peer");
        assert!(result.conversations[0].needs_prekey);
        assert_eq!(client.known_user_identity(PEER_USER), Some(peer_identity));
        assert!(client.peer_signing_key_is_pinned(&peer_identity, &peer_signing));

        let stored = client.db().unwrap().get_conversations().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, CONVERSATION);
        assert_eq!(stored[0].server_origin.as_deref(), Some(ORIGIN));
        assert_eq!(stored[0].peer_user_id.as_deref(), Some(PEER_USER));
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validates_the_complete_page_before_any_directory_write() {
        let (mut client, path) = initialized_client();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let valid = direct_conversation(
            local_identity,
            local_signing,
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        let mut invalid = valid.clone();
        invalid["id"] = serde_json::json!("NOT-A-UUID");

        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![valid, invalid], None),
        )
        .is_err());
        assert!(client.db().unwrap().get_conversations().unwrap().is_empty());
        assert_eq!(client.known_user_identity(PEER_USER), None);
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_same_page_peer_equivocation_before_durable_or_runtime_publication() {
        let (mut client, path) = initialized_client();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        let first_peer = veil_crypto::IdentityKeyPair::generate();
        let second_peer = veil_crypto::IdentityKeyPair::generate();
        let first = direct_conversation_for(
            CONVERSATION,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            first_peer.x25519_public_bytes(),
            first_peer.ed25519_public_bytes(),
        );
        let second = direct_conversation_for(
            CONVERSATION_TWO,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            second_peer.x25519_public_bytes(),
            second_peer.ed25519_public_bytes(),
        );

        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![first, second], None),
        )
        .unwrap_err()
        .contains("repeats one Direct peer"));
        assert!(client.db().unwrap().get_conversations().unwrap().is_empty());
        assert_eq!(client.known_user_identity(PEER_USER), None);
        assert!(!client.peer_signing_key_is_pinned(
            &first_peer.x25519_public_bytes(),
            &first_peer.ed25519_public_bytes(),
        ));
        assert!(client
            .db()
            .unwrap()
            .resolve_account_by_origin_user(ORIGIN, PEER_USER)
            .unwrap()
            .is_none());
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rolls_back_the_direct_conversation_batch_before_publishing_runtime_routes() {
        let (mut client, path) = initialized_client();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        let first_peer = veil_crypto::IdentityKeyPair::generate();
        let second_peer = veil_crypto::IdentityKeyPair::generate();
        client
            .db()
            .unwrap()
            .upsert_directory_conversation(
                CONVERSATION_TWO,
                0,
                ORIGIN,
                Some("existing peer"),
                Some(PEER_TWO_USER),
                Some(&[0x77; 32]),
                None,
                "2026-07-17T00:00:00Z",
            )
            .unwrap();
        let first = direct_conversation_for(
            CONVERSATION,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            first_peer.x25519_public_bytes(),
            first_peer.ed25519_public_bytes(),
        );
        let second = direct_conversation_for(
            CONVERSATION_TWO,
            PEER_TWO_USER,
            "second-peer",
            local_identity,
            local_signing,
            second_peer.x25519_public_bytes(),
            second_peer.ed25519_public_bytes(),
        );

        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![first, second], None),
        )
        .unwrap_err()
        .contains("changed the pinned DM peer"));
        let stored = client.db().unwrap().get_conversations().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, CONVERSATION_TWO);
        assert_eq!(client.known_user_identity(PEER_USER), None);
        assert_eq!(client.known_user_identity(PEER_TWO_USER), None);
        assert!(!client.peer_signing_key_is_pinned(
            &first_peer.x25519_public_bytes(),
            &first_peer.ed25519_public_bytes(),
        ));
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_duplicate_direct_peer_across_directory_pages() {
        let (mut client, path) = initialized_client();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let local_identity = client.identity_key().unwrap();
        let local_signing = client.signing_key().unwrap();
        let first = direct_conversation_for(
            CONVERSATION,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![first], Some("page-two")),
        )
        .unwrap();

        let second = direct_conversation_for(
            CONVERSATION_TWO,
            PEER_USER,
            "peer",
            local_identity,
            local_signing,
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            Some("page-two"),
            &page(vec![second], None),
        )
        .unwrap_err()
        .contains("already bound"));

        let stored = client.db().unwrap().get_conversations().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, CONVERSATION);
        assert_eq!(
            client.known_user_identity(PEER_USER),
            Some(peer.x25519_public_bytes())
        );
        assert!(
            client.peer_signing_key_is_pinned(
                &peer.x25519_public_bytes(),
                &peer.ed25519_public_bytes(),
            )
        );
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tracked_sync_rejects_cross_page_replay_cursor_cycles_and_page_exhaustion() {
        let (mut client, path) = initialized_client();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let response = page(
            vec![direct_conversation(
                client.identity_key().unwrap(),
                client.signing_key().unwrap(),
                peer.x25519_public_bytes(),
                peer.ed25519_public_bytes(),
            )],
            Some("next-page"),
        );

        let mut replay = DirectDirectorySyncHistory::default();
        replay
            .seen_conversation_ids
            .insert(CONVERSATION.to_string());
        assert!(install_authenticated_direct_directory_page_tracked(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &mut replay,
            &response,
        )
        .unwrap_err()
        .contains("across pages"));

        let mut cursor_cycle = DirectDirectorySyncHistory::default();
        cursor_cycle.seen_cursors.insert("next-page".to_string());
        assert!(install_authenticated_direct_directory_page_tracked(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &mut cursor_cycle,
            &response,
        )
        .unwrap_err()
        .contains("cursor cycle"));

        let mut exhausted = DirectDirectorySyncHistory {
            pages: DIRECT_DIRECTORY_MAX_PAGES,
            ..DirectDirectorySyncHistory::default()
        };
        assert!(install_authenticated_direct_directory_page_tracked(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &mut exhausted,
            &response,
        )
        .unwrap_err()
        .contains("page limit"));
        assert!(client.db().unwrap().get_conversations().unwrap().is_empty());
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_self_substitution_and_non_progressing_cursors() {
        let (mut client, path) = initialized_client();
        let local_signing = client.signing_key().unwrap();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let substituted = direct_conversation(
            [0x42; 32],
            local_signing,
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![substituted], None),
        )
        .unwrap_err()
        .contains("substituted"));

        let valid = direct_conversation(
            client.identity_key().unwrap(),
            local_signing,
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            Some("same"),
            &page(vec![valid], Some("same")),
        )
        .unwrap_err()
        .contains("repeated"));
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validates_but_does_not_publish_non_direct_conversations() {
        let (mut client, path) = initialized_client();
        let group = serde_json::json!({
            "id": CONVERSATION,
            "conv_type": 1,
            "name": "future group",
            "server_id": null,
            "created_at": "2026-07-18T00:00:00Z",
            "members": [member(
                SELF_USER,
                "self",
                client.identity_key().unwrap(),
                client.signing_key().unwrap(),
            )],
        });
        let result = install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![group], None),
        )
        .unwrap();
        assert_eq!(result.skipped_non_direct, 1);
        assert!(result.conversations.is_empty());
        assert!(client.db().unwrap().get_conversations().unwrap().is_empty());
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn follows_the_server_wire_name_and_rejects_insecure_remote_origins() {
        let (mut client, path) = initialized_client();
        let peer = veil_crypto::IdentityKeyPair::generate();
        let mut conversation = direct_conversation(
            client.identity_key().unwrap(),
            client.signing_key().unwrap(),
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        conversation["type"] = conversation["conv_type"].take();
        assert!(install_authenticated_direct_directory_page(
            &mut client,
            ORIGIN,
            SELF_USER,
            None,
            &page(vec![conversation], None),
        )
        .unwrap_err()
        .contains("invalid conversation directory response"));

        let valid = direct_conversation(
            client.identity_key().unwrap(),
            client.signing_key().unwrap(),
            peer.x25519_public_bytes(),
            peer.ed25519_public_bytes(),
        );
        assert!(install_authenticated_direct_directory_page(
            &mut client,
            "http://veil.example.test:80",
            SELF_USER,
            None,
            &page(vec![valid], None),
        )
        .unwrap_err()
        .contains("canonical server origin"));
        assert!(validate_canonical_origin("https://veil.example.test:443").is_ok());
        assert!(validate_canonical_origin("http://127.0.0.1:8080").is_ok());
        assert!(validate_canonical_origin("https://veil.example.test").is_err());
        assert!(validate_canonical_origin("https://veil.example.test:0").is_err());
        drop(client);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn establishes_x3dh_only_for_the_authenticated_directory_peer() {
        let (mut client, path) = initialized_client();
        let (mut peer, peer_path) = initialized_client();
        let peer_identity = peer.identity_key().unwrap();
        let peer_signing = peer.signing_key().unwrap();
        let prekeys = peer.generate_prekeys().unwrap();
        install_peer_directory(&mut client, peer_identity, peer_signing);

        let result = install_authenticated_direct_prekey_bundle(
            &mut client,
            PEER_USER,
            peer_identity,
            peer_signing,
            &prekey_response(peer_identity, peer_signing, &prekeys),
        )
        .unwrap();
        assert_eq!(result, DirectPreKeyInstallResult::Established);
        assert!(client.has_session(&peer_identity));

        // A redundant/stale fetch can never reset an existing ratchet, even
        // if its body is malformed after the server has consumed an OPK.
        let result = install_authenticated_direct_prekey_bundle(
            &mut client,
            PEER_USER,
            peer_identity,
            peer_signing,
            b"not-json",
        )
        .unwrap();
        assert_eq!(result, DirectPreKeyInstallResult::AlreadyEstablished);

        drop(client);
        drop(peer);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(peer_path);
    }

    #[test]
    fn direct_session_survives_sqlcipher_restart_and_repeated_bundle_is_noop() {
        let mut client = VeilClient::new();
        let mnemonic = client.generate_mnemonic();
        let path = std::env::temp_dir().join(format!(
            "veil-direct-session-restart-{}.db",
            uuid::Uuid::new_v4()
        ));
        client.init_with_mnemonic(&mnemonic, &path).unwrap();

        let (mut peer, peer_path) = initialized_client();
        let peer_identity = peer.identity_key().unwrap();
        let peer_signing = peer.signing_key().unwrap();
        let prekeys = peer.generate_prekeys().unwrap();
        let response = prekey_response(peer_identity, peer_signing, &prekeys);
        install_peer_directory(&mut client, peer_identity, peer_signing);

        assert_eq!(
            install_authenticated_direct_prekey_bundle(
                &mut client,
                PEER_USER,
                peer_identity,
                peer_signing,
                &response,
            )
            .unwrap(),
            DirectPreKeyInstallResult::Established
        );
        assert!(client.has_session(&peer_identity));
        let session_before_restart = client
            .db()
            .unwrap()
            .load_ratchet_session(&peer_identity)
            .unwrap()
            .expect("initiator ratchet must be durable before restart");
        let header_before_restart = client.db().unwrap().load_pending_initial_headers().unwrap();
        assert_eq!(header_before_restart.len(), 1);
        assert_eq!(header_before_restart[0].0, peer_identity);
        drop(client);

        let mut restored = VeilClient::new();
        restored.init_with_mnemonic(&mnemonic, &path).unwrap();
        assert!(
            restored.has_session(&peer_identity),
            "SQLCipher restart must restore the existing ratchet"
        );
        install_peer_directory(&mut restored, peer_identity, peer_signing);
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity)
                .unwrap()
                .as_deref(),
            Some(session_before_restart.as_slice())
        );
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_pending_initial_headers()
                .unwrap(),
            header_before_restart
        );

        assert_eq!(
            install_authenticated_direct_prekey_bundle(
                &mut restored,
                PEER_USER,
                peer_identity,
                peer_signing,
                &response,
            )
            .unwrap(),
            DirectPreKeyInstallResult::AlreadyEstablished
        );
        assert!(restored.has_session(&peer_identity));
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity)
                .unwrap()
                .as_deref(),
            Some(session_before_restart.as_slice()),
            "a repeated bundle must not replace durable ratchet state"
        );
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_pending_initial_headers()
                .unwrap(),
            header_before_restart,
            "a repeated bundle must not replace the pending X3DH header"
        );

        // Once the durable ratchet has been restored, even an obsolete fetch
        // body that is no longer parseable cannot reset or damage the session.
        assert_eq!(
            install_authenticated_direct_prekey_bundle(
                &mut restored,
                PEER_USER,
                peer_identity,
                peer_signing,
                b"not-json",
            )
            .unwrap(),
            DirectPreKeyInstallResult::AlreadyEstablished
        );
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_ratchet_session(&peer_identity)
                .unwrap()
                .as_deref(),
            Some(session_before_restart.as_slice())
        );
        assert_eq!(
            restored
                .db()
                .unwrap()
                .load_pending_initial_headers()
                .unwrap(),
            header_before_restart
        );

        drop(restored);
        drop(peer);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(peer_path);
    }

    #[test]
    fn non_contributory_bundle_keys_never_install_a_ratchet() {
        let alice = veil_crypto::IdentityKeyPair::generate();
        let mut client = VeilClient::from_identity(alice);
        let bob = veil_crypto::IdentityKeyPair::generate();
        let bob_identity = bob.x25519_public_bytes();
        let bob_signing = bob.ed25519_public_bytes();
        let spk = veil_crypto::x3dh::SignedPreKey::generate(&bob, 1);
        let opk = veil_crypto::x3dh::OneTimePreKey::generate(1);
        let low_order = {
            let mut key = [0u8; 32];
            key[0] = 1;
            key
        };

        let low_identity_bundle = veil_crypto::x3dh::PreKeyBundle {
            identity_key: low_order,
            signing_key: bob_signing,
            signed_prekey: *spk.public.as_bytes(),
            signed_prekey_signature: spk.signature,
            signed_prekey_id: spk.id,
            one_time_prekey: Some(*opk.public.as_bytes()),
            one_time_prekey_id: Some(opk.id),
        };
        assert!(client
            .establish_session(&low_order, &low_identity_bundle)
            .unwrap_err()
            .contains("non-contributory X25519 identity key"));
        assert!(!client.has_session(&low_order));

        let low_spk_signature = veil_crypto::signature::sign(
            &bob,
            &veil_crypto::x3dh::signed_prekey_signature_message(&low_order),
        );
        let low_spk_bundle = veil_crypto::x3dh::PreKeyBundle {
            identity_key: bob_identity,
            signing_key: bob_signing,
            signed_prekey: low_order,
            signed_prekey_signature: low_spk_signature,
            signed_prekey_id: spk.id,
            one_time_prekey: Some(*opk.public.as_bytes()),
            one_time_prekey_id: Some(opk.id),
        };
        assert!(client
            .establish_session(&bob_identity, &low_spk_bundle)
            .unwrap_err()
            .contains("non-contributory X25519 signed prekey"));
        assert!(!client.has_session(&bob_identity));

        let low_opk_bundle = veil_crypto::x3dh::PreKeyBundle {
            identity_key: bob_identity,
            signing_key: bob_signing,
            signed_prekey: *spk.public.as_bytes(),
            signed_prekey_signature: spk.signature,
            signed_prekey_id: spk.id,
            one_time_prekey: Some(low_order),
            one_time_prekey_id: Some(opk.id),
        };
        assert!(client
            .establish_session(&bob_identity, &low_opk_bundle)
            .unwrap_err()
            .contains("non-contributory X25519 one-time prekey"));
        assert!(!client.has_session(&bob_identity));
    }

    #[test]
    fn rejects_prekey_substitution_incomplete_opks_and_invalid_signatures() {
        let (mut client, path) = initialized_client();
        let (mut peer, peer_path) = initialized_client();
        let peer_identity = peer.identity_key().unwrap();
        let peer_signing = peer.signing_key().unwrap();
        let prekeys = peer.generate_prekeys().unwrap();
        install_peer_directory(&mut client, peer_identity, peer_signing);

        let mut substituted: serde_json::Value =
            serde_json::from_slice(&prekey_response(peer_identity, peer_signing, &prekeys))
                .unwrap();
        substituted["identity_key"] = serde_json::json!(BASE64_STANDARD.encode([0x42; 32]));
        assert!(install_authenticated_direct_prekey_bundle(
            &mut client,
            PEER_USER,
            peer_identity,
            peer_signing,
            &serde_json::to_vec(&substituted).unwrap(),
        )
        .unwrap_err()
        .contains("does not match"));
        assert!(!client.has_session(&peer_identity));

        let mut incomplete: serde_json::Value =
            serde_json::from_slice(&prekey_response(peer_identity, peer_signing, &prekeys))
                .unwrap();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("one_time_prekey_id");
        assert!(install_authenticated_direct_prekey_bundle(
            &mut client,
            PEER_USER,
            peer_identity,
            peer_signing,
            &serde_json::to_vec(&incomplete).unwrap(),
        )
        .unwrap_err()
        .contains("incomplete"));
        assert!(!client.has_session(&peer_identity));

        let mut invalid_signature: serde_json::Value =
            serde_json::from_slice(&prekey_response(peer_identity, peer_signing, &prekeys))
                .unwrap();
        invalid_signature["signed_prekey_signature"] =
            serde_json::json!(BASE64_STANDARD.encode([0u8; 64]));
        assert!(install_authenticated_direct_prekey_bundle(
            &mut client,
            PEER_USER,
            peer_identity,
            peer_signing,
            &serde_json::to_vec(&invalid_signature).unwrap(),
        )
        .unwrap_err()
        .contains("signature"));
        assert!(!client.has_session(&peer_identity));

        drop(client);
        drop(peer);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(peer_path);
    }
}
