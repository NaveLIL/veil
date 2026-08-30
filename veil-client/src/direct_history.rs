//! Authenticated, origin-scoped Direct text-history contracts.
//!
//! Transport deliberately stays outside this module. Native callers prepare
//! the exact request target from [`DirectHistorySyncState`], fetch one bounded
//! response under their authenticated origin/lease, then hand the raw bytes to
//! [`install_authenticated_direct_history_page`]. The complete wire page is
//! structurally validated before any Double Ratchet or SQLCipher mutation.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use veil_store::models::{
    AuthenticatedDirectHistoryScopeV1, MessageAuthorContext, RemoteMessageStateKind, RemoteReaction,
};
use zeroize::Zeroize;

use crate::api::{
    DirectHistoryMutationError, DirectMessageSecurityContextV2, MessageSecurityContextV1,
    ReceiveMessageResult, RemoteMessageMetadata, RemoteReconcileAction, VeilClient,
};

pub const DIRECT_HISTORY_PAGE_LIMIT: usize = 25;
pub const DIRECT_HISTORY_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
pub const DIRECT_HISTORY_CURSOR_LIMIT: usize = 1_024;
pub const DIRECT_HISTORY_MAX_PAGES: usize = 10_000;
pub const DIRECT_HISTORY_MAX_MESSAGES: usize = DIRECT_HISTORY_PAGE_LIMIT * DIRECT_HISTORY_MAX_PAGES;

const MAX_HISTORY_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_HISTORY_HEADER_BYTES: usize = 512;
const MAX_HISTORY_REACTIONS: usize = 256;
const MAX_HISTORY_EMOJI_BYTES: usize = 64;
const MAX_HISTORY_USERNAME_BYTES: usize = 128;
const MAX_HISTORY_JSON_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectHistorySyncOutcome {
    InProgress,
    Complete,
    IncompleteSelfHistory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectHistorySyncState {
    canonical_server_origin: String,
    authenticated_user_id: String,
    conversation_id: String,
    current_cursor: Option<String>,
    seen_cursors: HashSet<String>,
    seen_message_ids: HashSet<String>,
    last_sort_key: Option<DirectHistorySortKey>,
    pages: usize,
    messages: usize,
    outcome: DirectHistorySyncOutcome,
}

impl DirectHistorySyncState {
    pub fn new(
        canonical_server_origin: &str,
        authenticated_user_id: &str,
        conversation_id: &str,
    ) -> Result<Self, String> {
        crate::direct::validate_canonical_origin(canonical_server_origin)?;
        decode_canonical_uuid(
            "Direct history authenticated user id",
            authenticated_user_id,
        )?;
        decode_canonical_uuid("Direct history conversation id", conversation_id)?;
        Ok(Self {
            canonical_server_origin: canonical_server_origin.to_string(),
            authenticated_user_id: authenticated_user_id.to_string(),
            conversation_id: conversation_id.to_string(),
            current_cursor: None,
            seen_cursors: HashSet::new(),
            seen_message_ids: HashSet::new(),
            last_sort_key: None,
            pages: 0,
            messages: 0,
            outcome: DirectHistorySyncOutcome::InProgress,
        })
    }

    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    pub fn canonical_server_origin(&self) -> &str {
        &self.canonical_server_origin
    }

    pub fn authenticated_user_id(&self) -> &str {
        &self.authenticated_user_id
    }

    pub fn current_cursor(&self) -> Option<&str> {
        self.current_cursor.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.outcome == DirectHistorySyncOutcome::Complete
    }

    pub fn is_terminal(&self) -> bool {
        self.outcome != DirectHistorySyncOutcome::InProgress
    }

    pub fn outcome(&self) -> DirectHistorySyncOutcome {
        self.outcome
    }

    pub fn pages(&self) -> usize {
        self.pages
    }

    pub fn messages(&self) -> usize {
        self.messages
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectHistoryPageResult {
    pub next_cursor: Option<String>,
    pub conversation_complete: bool,
    pub outcome: DirectHistorySyncOutcome,
    pub stored: usize,
    pub duplicates: usize,
    pub tombstones: usize,
    pub unavailable: usize,
    pub edits: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectHistoryRejectCode {
    InvalidPage,
    ScopeMismatch,
    IdentityMismatch,
    UnsupportedMessage,
    OrderingViolation,
    CryptographicFailure,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectHistoryInstallError {
    /// The complete page was rejected before any page-derived crypto or
    /// persistence mutation. This is safe for a caller to quarantine as a
    /// conversation/protocol failure.
    ConversationRejected { code: DirectHistoryRejectCode },
    /// A trusted local read or an atomic SQLCipher transition failed. Callers
    /// keep this retryable and must not quarantine a conversation from it.
    StorageUncertain,
}

impl std::fmt::Display for DirectHistoryInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConversationRejected { code } => {
                write!(formatter, "Direct history conversation rejected: {code:?}")
            }
            Self::StorageUncertain => {
                formatter.write_str("Direct history storage state is uncertain")
            }
        }
    }
}

impl std::error::Error for DirectHistoryInstallError {}

impl DirectHistoryInstallError {
    fn rejected(code: DirectHistoryRejectCode) -> Self {
        Self::ConversationRejected { code }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DirectHistorySortKey {
    created_at: DateTime<Utc>,
    message_id: [u8; 16],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectHistoryPageWire {
    messages: Vec<DirectHistoryMessageWire>,
    count: usize,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectHistoryMessageWire {
    id: String,
    conversation_id: String,
    sender_id: String,
    sender_identity_key: String,
    sender_signing_key: String,
    ciphertext: String,
    header: String,
    msg_type: i16,
    #[serde(default)]
    reply_to_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    edited_at: Option<String>,
    is_deleted: bool,
    is_expired: bool,
    #[serde(default)]
    reactions: Vec<DirectHistoryReactionWire>,
    #[serde(default)]
    attachments: Vec<DirectHistoryAttachmentWire>,
    created_at: String,
    server_timestamp: i64,
    revision_timestamp: i64,
    crypto_profile: String,
    #[serde(default)]
    crypto_era: Option<String>,
    #[serde(default)]
    roster_version: Option<String>,
    #[serde(default)]
    roster_commitment: Option<String>,
    #[serde(default)]
    sender_device_id: Option<String>,
    #[serde(default)]
    sender_binding_version: Option<String>,
    #[serde(default)]
    sender_device_identity_key: Option<String>,
    #[serde(default)]
    sender_device_signing_key: Option<String>,
    #[serde(default)]
    sender_device_capabilities: Option<String>,
    #[serde(default)]
    sender_device_binding_status: Option<u8>,
    #[serde(default)]
    sender_account_signature: Option<String>,
    #[serde(default)]
    target_device_id: Option<String>,
    #[serde(default)]
    target_binding_version: Option<String>,
    #[serde(default)]
    direct_session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectHistoryReactionWire {
    emoji: String,
    user_id: String,
    username: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct DirectHistoryAttachmentWire {
    media_id: String,
    encrypted_key: String,
    nonce: String,
    size: i64,
    content_type: String,
}

struct ValidatedDirectHistoryMessage {
    id: String,
    sender_id: String,
    sender_identity_key: [u8; 32],
    security_context: Option<MessageSecurityContextV1>,
    header: Vec<u8>,
    ciphertext: Vec<u8>,
    reply_to_id: Option<String>,
    server_timestamp: i64,
    revision_timestamp: i64,
    remote_state: RemoteMessageStateKind,
    reactions: Vec<RemoteReaction>,
    sort_key: DirectHistorySortKey,
}

/// Build the only request target accepted for this tracked conversation.
/// Cursors are opaque and live solely inside the current authenticated epoch.
pub fn direct_history_request_target(state: &DirectHistorySyncState) -> Result<String, String> {
    if state.is_terminal() {
        return Err("Direct history is already terminal".to_string());
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &DIRECT_HISTORY_PAGE_LIMIT.to_string());
    if let Some(cursor) = state.current_cursor.as_deref() {
        validate_cursor(cursor)?;
        query.append_pair("cursor", cursor);
    }
    Ok(format!(
        "/v1/messages/{}?{}",
        state.conversation_id,
        query.finish()
    ))
}

/// Validate, reconcile, decrypt and durably persist one Direct text page.
///
/// The whole page is parsed and preflighted before the first mutation. Each
/// individual message/ratchet transition uses VeilClient's existing atomic
/// receive savepoint. The page cursor advances only after every row succeeds;
/// an exact replay therefore sees already-committed prefix rows as duplicates
/// and never advances their ratchets twice.
pub fn install_authenticated_direct_history_page(
    client: &mut VeilClient,
    state: &mut DirectHistorySyncState,
    response: &[u8],
) -> Result<DirectHistoryPageResult, DirectHistoryInstallError> {
    let result = install_authenticated_direct_history_page_inner(client, state, response);
    if matches!(&result, Err(DirectHistoryInstallError::StorageUncertain)) {
        // A page can touch ratchets, message rows, author snapshots, and
        // metadata through several helpers. One top-level boundary ensures no
        // storage-uncertain branch merely becomes a retryable sync failure.
        client.revoke_storage_uncertain_epoch_v1();
    }
    result
}

fn install_authenticated_direct_history_page_inner(
    client: &mut VeilClient,
    state: &mut DirectHistorySyncState,
    response: &[u8],
) -> Result<DirectHistoryPageResult, DirectHistoryInstallError> {
    if state.is_terminal() || state.pages >= DIRECT_HISTORY_MAX_PAGES {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    let runtime_user = client
        .authenticated_user_id()
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::ScopeMismatch))?;
    if runtime_user != state.authenticated_user_id {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::ScopeMismatch,
        ));
    }

    let scope = client
        .db()
        .ok_or(DirectHistoryInstallError::StorageUncertain)?
        .resolve_authenticated_direct_history_scope_v1(
            &state.canonical_server_origin,
            &state.authenticated_user_id,
            &state.conversation_id,
        )
        .map_err(|_| DirectHistoryInstallError::StorageUncertain)?;
    validate_runtime_scope(client, &scope)?;

    let page = decode_history_page(response)?;
    let validated = validate_history_page(state, &scope, page)?;

    let mut result = DirectHistoryPageResult {
        next_cursor: validated.next_cursor.clone(),
        conversation_complete: false,
        outcome: DirectHistorySyncOutcome::InProgress,
        stored: 0,
        duplicates: 0,
        tombstones: 0,
        unavailable: 0,
        edits: 0,
    };
    for message in &validated.messages {
        process_message(client, &scope, message, &mut result)?;
    }

    state.pages = state
        .pages
        .checked_add(1)
        .ok_or(DirectHistoryInstallError::StorageUncertain)?;
    state.messages = state
        .messages
        .checked_add(validated.messages.len())
        .ok_or(DirectHistoryInstallError::StorageUncertain)?;
    for message in validated.messages {
        state.seen_message_ids.insert(message.id);
        state.last_sort_key = Some(message.sort_key);
    }
    if let Some(cursor) = validated.next_cursor.as_ref() {
        state.seen_cursors.insert(cursor.clone());
    }
    result.outcome = if result.unavailable > 0 {
        DirectHistorySyncOutcome::IncompleteSelfHistory
    } else if validated.next_cursor.is_none() {
        DirectHistorySyncOutcome::Complete
    } else {
        DirectHistorySyncOutcome::InProgress
    };
    result.conversation_complete = result.outcome == DirectHistorySyncOutcome::Complete;
    state.outcome = result.outcome;
    state.current_cursor = if state.outcome == DirectHistorySyncOutcome::InProgress {
        validated.next_cursor
    } else {
        None
    };
    Ok(result)
}

struct ValidatedDirectHistoryPage {
    messages: Vec<ValidatedDirectHistoryMessage>,
    next_cursor: Option<String>,
}

fn decode_history_page(
    response: &[u8],
) -> Result<DirectHistoryPageWire, DirectHistoryInstallError> {
    if response.is_empty() || response.len() > DIRECT_HISTORY_RESPONSE_LIMIT {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    reject_duplicate_json_keys(response)
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    let mut deserializer = serde_json::Deserializer::from_slice(response);
    let page = DirectHistoryPageWire::deserialize(&mut deserializer)
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    deserializer
        .end()
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    Ok(page)
}

fn validate_runtime_scope(
    client: &VeilClient,
    scope: &AuthenticatedDirectHistoryScopeV1,
) -> Result<(), DirectHistoryInstallError> {
    if client.identity_key().ok() != Some(scope.self_account.locator.identity_key)
        || client.signing_key().ok() != Some(scope.self_account.signing_key)
        || client.known_user_identity(&scope.peer_account.locator.user_id)
            != Some(scope.peer_account.locator.identity_key)
        || !client.peer_signing_key_is_pinned(
            &scope.peer_account.locator.identity_key,
            &scope.peer_account.signing_key,
        )
    {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::IdentityMismatch,
        ));
    }
    // This existing API returns String for both a route mismatch and a local
    // database error. Treating either as a quarantine-worthy peer failure
    // would be unsafe, so keep the result conservatively retryable.
    client
        .ensure_dm_conversation_binding_compatible(
            &scope.conversation_id,
            scope.peer_account.locator.identity_key,
        )
        .map_err(|_| DirectHistoryInstallError::StorageUncertain)?;
    Ok(())
}

fn validate_history_page(
    state: &DirectHistorySyncState,
    scope: &AuthenticatedDirectHistoryScopeV1,
    page: DirectHistoryPageWire,
) -> Result<ValidatedDirectHistoryPage, DirectHistoryInstallError> {
    if page.count != page.messages.len()
        || page.messages.len() > DIRECT_HISTORY_PAGE_LIMIT
        || state.messages.saturating_add(page.messages.len()) > DIRECT_HISTORY_MAX_MESSAGES
    {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        validate_cursor(cursor).map_err(|_| {
            DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
        })?;
        if state.current_cursor.as_deref() == Some(cursor)
            || state.seen_cursors.contains(cursor)
            || page.messages.is_empty()
        {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::OrderingViolation,
            ));
        }
    }

    let mut page_ids = HashSet::with_capacity(page.messages.len());
    let mut previous = state.last_sort_key.clone();
    let mut messages = Vec::with_capacity(page.messages.len());
    for wire in page.messages {
        if !page_ids.insert(wire.id.clone()) || state.seen_message_ids.contains(&wire.id) {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::OrderingViolation,
            ));
        }
        let message = validate_message(scope, wire)?;
        if previous
            .as_ref()
            .is_some_and(|last| message.sort_key <= *last)
        {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::OrderingViolation,
            ));
        }
        previous = Some(message.sort_key.clone());
        messages.push(message);
    }
    Ok(ValidatedDirectHistoryPage {
        messages,
        next_cursor: page.next_cursor,
    })
}

fn validate_message(
    scope: &AuthenticatedDirectHistoryScopeV1,
    wire: DirectHistoryMessageWire,
) -> Result<ValidatedDirectHistoryMessage, DirectHistoryInstallError> {
    let message_id = decode_canonical_uuid("Direct history message id", &wire.id)
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    decode_canonical_uuid(
        "Direct history response conversation id",
        &wire.conversation_id,
    )
    .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::ScopeMismatch))?;
    if wire.conversation_id != scope.conversation_id {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::ScopeMismatch,
        ));
    }
    decode_canonical_uuid("Direct history sender id", &wire.sender_id)
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::ScopeMismatch))?;
    let expected = if wire.sender_id == scope.self_account.locator.user_id {
        &scope.self_account
    } else if wire.sender_id == scope.peer_account.locator.user_id {
        &scope.peer_account
    } else {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::ScopeMismatch,
        ));
    };
    let sender_identity_key = decode_lower_hex_fixed::<32>(
        "Direct history sender identity key",
        &wire.sender_identity_key,
    )
    .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::IdentityMismatch))?;
    let sender_signing_key = decode_lower_hex_fixed::<32>(
        "Direct history sender signing key",
        &wire.sender_signing_key,
    )
    .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::IdentityMismatch))?;
    if sender_identity_key == [0u8; 32]
        || sender_signing_key == [0u8; 32]
        || sender_identity_key == sender_signing_key
        || sender_identity_key != expected.locator.identity_key
        || sender_signing_key != expected.signing_key
    {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::IdentityMismatch,
        ));
    }

    if wire.msg_type != 0 || !wire.attachments.is_empty() {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::UnsupportedMessage,
        ));
    }
    // REST rows replace ciphertext in-place for edits and omit it entirely for
    // terminal/TTL state. Neither representation preserves every Double
    // Ratchet step, so replaying it by created_at can exceed MAX_SKIP or advance
    // the chain over an unauthenticated gap. Closed Preview accepts immutable,
    // non-expiring text only until a signed event-log/ratchet-advance contract
    // exists.
    if wire.edited_at.is_some() || wire.is_deleted || wire.is_expired || wire.expires_at.is_some() {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::UnsupportedMessage,
        ));
    }
    #[cfg(any(test, feature = "test-utils"))]
    let all_direct_fields_absent = wire.sender_device_identity_key.is_none()
        && wire.sender_device_signing_key.is_none()
        && wire.sender_device_capabilities.is_none()
        && wire.sender_device_binding_status.is_none()
        && wire.sender_account_signature.is_none()
        && wire.target_device_id.is_none()
        && wire.target_binding_version.is_none()
        && wire.direct_session_id.is_none();
    let security_context = match wire.crypto_profile.as_str() {
        // Kept only for legacy cryptographic fixtures. Product builds reject
        // history rows without an authenticated Direct v2 device/session
        // coordinate before any ratchet or SQLCipher mutation.
        #[cfg(any(test, feature = "test-utils"))]
        "legacy_unknown"
            if wire.crypto_era.is_none()
                && wire.roster_version.is_none()
                && wire.roster_commitment.is_none()
                && wire.sender_device_id.is_none()
                && wire.sender_binding_version.is_none()
                && all_direct_fields_absent =>
        {
            None
        }
        "direct_v2" if wire.roster_version.is_none() && wire.roster_commitment.is_none() => {
            let era = parse_canonical_u63(
                "Direct history crypto era",
                wire.crypto_era.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )?;
            if era != 1 {
                return Err(DirectHistoryInstallError::rejected(
                    DirectHistoryRejectCode::UnsupportedMessage,
                ));
            }
            let sender_device_id = decode_lower_hex_fixed::<16>(
                "Direct history sender device id",
                wire.sender_device_id.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            let sender_binding_version = parse_canonical_u63(
                "Direct history sender binding version",
                wire.sender_binding_version.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )?;
            let sender_device_identity_key = decode_lower_hex_fixed::<32>(
                "Direct history sender device identity key",
                wire.sender_device_identity_key.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            let sender_device_signing_key = decode_lower_hex_fixed::<32>(
                "Direct history sender device signing key",
                wire.sender_device_signing_key.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            let sender_device_capabilities = parse_canonical_u63(
                "Direct history sender device capabilities",
                wire.sender_device_capabilities.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )?;
            let sender_device_binding_status =
                wire.sender_device_binding_status.ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?;
            let sender_account_signature = decode_lower_hex_fixed::<64>(
                "Direct history sender account signature",
                wire.sender_account_signature.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            let target_device_id = decode_lower_hex_fixed::<16>(
                "Direct history target device id",
                wire.target_device_id.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            let target_binding_version = parse_canonical_u63(
                "Direct history target binding version",
                wire.target_binding_version.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )?;
            let direct_session_id = decode_lower_hex_fixed::<32>(
                "Direct history session id",
                wire.direct_session_id.as_deref().ok_or_else(|| {
                    DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
                })?,
            )
            .map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
            if sender_device_id == [0u8; 16]
                || sender_device_identity_key == [0u8; 32]
                || sender_device_signing_key == [0u8; 32]
                || sender_device_identity_key == sender_device_signing_key
                || sender_device_capabilities == 0
                || sender_device_binding_status
                    != crate::device_identity::DEVICE_BINDING_STATUS_ACTIVE
                || sender_account_signature == [0u8; 64]
                || target_device_id == [0u8; 16]
                || target_device_id == sender_device_id
                || direct_session_id == [0u8; 32]
            {
                return Err(DirectHistoryInstallError::rejected(
                    DirectHistoryRejectCode::InvalidPage,
                ));
            }
            let binding = crate::device_identity::device_binding_signing_bytes(
                &sender_identity_key,
                &sender_signing_key,
                &sender_device_id,
                sender_binding_version,
                &sender_device_identity_key,
                &sender_device_signing_key,
                sender_device_capabilities,
                sender_device_binding_status,
            );
            if !veil_crypto::signature::verify(
                &sender_signing_key,
                &binding,
                &sender_account_signature,
            ) {
                return Err(DirectHistoryInstallError::rejected(
                    DirectHistoryRejectCode::IdentityMismatch,
                ));
            }
            Some(MessageSecurityContextV1::DirectV2(
                DirectMessageSecurityContextV2 {
                    sender_user_id: wire.sender_id.clone(),
                    sender_device_id,
                    sender_binding_version,
                    sender_device_identity_key,
                    sender_device_signing_key,
                    sender_device_capabilities,
                    sender_device_binding_status,
                    sender_account_signature,
                    target_device_id,
                    target_binding_version,
                    direct_session_id,
                },
            ))
        }
        _ => {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::UnsupportedMessage,
            ));
        }
    };

    let created_at = parse_canonical_utc("Direct history created_at", &wire.created_at)
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    if wire.server_timestamp < 0 || created_at.timestamp_millis() != wire.server_timestamp {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    if let Some(expires_at) = wire.expires_at.as_deref() {
        parse_canonical_utc("Direct history expires_at", expires_at).map_err(|_| {
            DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
        })?;
    }
    let expected_revision = if let Some(edited_at) = wire.edited_at.as_deref() {
        parse_canonical_utc("Direct history edited_at", edited_at)
            .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?
            .timestamp_millis()
    } else {
        wire.server_timestamp
    };
    if wire.revision_timestamp < wire.server_timestamp
        || wire.revision_timestamp != expected_revision
    {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    if let Some(reply_to_id) = wire.reply_to_id.as_deref() {
        let reply =
            decode_canonical_uuid("Direct history reply id", reply_to_id).map_err(|_| {
                DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage)
            })?;
        if reply == message_id {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::InvalidPage,
            ));
        }
    }

    let remote_state = if wire.is_deleted {
        RemoteMessageStateKind::Deleted
    } else if wire.is_expired {
        RemoteMessageStateKind::Expired
    } else {
        RemoteMessageStateKind::Active
    };
    let terminal = remote_state != RemoteMessageStateKind::Active;
    let (header, ciphertext) = if terminal {
        if !wire.header.is_empty() || !wire.ciphertext.is_empty() {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::InvalidPage,
            ));
        }
        (Vec::new(), Vec::new())
    } else {
        let header = decode_lower_hex_bounded(
            "Direct history header",
            &wire.header,
            MAX_HISTORY_HEADER_BYTES,
        )
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
        let ciphertext = decode_lower_hex_bounded(
            "Direct history ciphertext",
            &wire.ciphertext,
            MAX_HISTORY_CIPHERTEXT_BYTES,
        )
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
        let valid_header = match security_context.as_ref() {
            #[cfg(any(test, feature = "test-utils"))]
            None => {
                matches!(header.as_slice(), [0x01, ..] | [0x02, ..])
                    && ((header[0] == 0x01 && header.len() == 82)
                        || (header[0] == 0x02 && header.len() == 42))
            }
            #[cfg(not(any(test, feature = "test-utils")))]
            None => false,
            Some(MessageSecurityContextV1::DirectV2(context)) => {
                matches!(header.as_slice(), [0x11, ..] | [0x12, ..])
                    && ((header[0] == 0x11 && header.len() == 114)
                        || (header[0] == 0x12 && header.len() == 74))
                    && header.get(1..33) == Some(context.direct_session_id.as_slice())
            }
            Some(
                MessageSecurityContextV1::SenderKeyV5(_) | MessageSecurityContextV1::SenderKeyV6(_),
            ) => false,
        };
        if !valid_header {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::UnsupportedMessage,
            ));
        }
        (header, ciphertext)
    };

    if wire.reactions.len() > MAX_HISTORY_REACTIONS {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    let mut seen_reactions = HashSet::with_capacity(wire.reactions.len());
    let mut reactions = Vec::with_capacity(wire.reactions.len());
    for reaction in wire.reactions {
        decode_canonical_uuid("Direct history reaction user id", &reaction.user_id).map_err(
            |_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage),
        )?;
        if reaction.user_id != scope.self_account.locator.user_id
            && reaction.user_id != scope.peer_account.locator.user_id
        {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::ScopeMismatch,
            ));
        }
        validate_bounded_text(
            "Direct history reaction emoji",
            &reaction.emoji,
            MAX_HISTORY_EMOJI_BYTES,
        )
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
        validate_bounded_text(
            "Direct history reaction username",
            &reaction.username,
            MAX_HISTORY_USERNAME_BYTES,
        )
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
        if !seen_reactions.insert((reaction.user_id.clone(), reaction.emoji.clone())) {
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::InvalidPage,
            ));
        }
        reactions.push(RemoteReaction {
            emoji: reaction.emoji,
            user_id: reaction.user_id,
            username: reaction.username,
        });
    }

    Ok(ValidatedDirectHistoryMessage {
        id: wire.id,
        sender_id: wire.sender_id,
        sender_identity_key,
        security_context,
        header,
        ciphertext,
        reply_to_id: wire.reply_to_id,
        server_timestamp: wire.server_timestamp,
        revision_timestamp: wire.revision_timestamp,
        remote_state,
        reactions,
        sort_key: DirectHistorySortKey {
            created_at,
            message_id,
        },
    })
}

fn process_message(
    client: &mut VeilClient,
    scope: &AuthenticatedDirectHistoryScopeV1,
    message: &ValidatedDirectHistoryMessage,
    result: &mut DirectHistoryPageResult,
) -> Result<(), DirectHistoryInstallError> {
    let metadata = RemoteMessageMetadata {
        revision_ms: message.revision_timestamp,
        reactions: Some(&message.reactions),
    };
    let author = if message.sender_id == scope.self_account.locator.user_id {
        &scope.self_account
    } else {
        &scope.peer_account
    };

    // Account-scoped REST history may contain one envelope for a different
    // local device. It is authenticated metadata but is not decryptable by
    // this device and must never select or advance its ratchet.
    if message.sender_id != scope.self_account.locator.user_id {
        if let Some(MessageSecurityContextV1::DirectV2(context)) = message.security_context.as_ref()
        {
            if context.target_device_id != client.device_id()
                || client.current_device_binding_version_v1()
                    != Some(context.target_binding_version)
            {
                client
                    .reconcile_remote_message_metadata_classified(
                        &message.id,
                        &scope.conversation_id,
                        &message.sender_identity_key,
                        &metadata,
                        RemoteMessageStateKind::Unavailable,
                    )
                    .map_err(classify_history_mutation_error)?;
                result.unavailable += 1;
                return Ok(());
            }
        }
    }

    // Another local device may have authored a server row that this device
    // never persisted. It cannot decrypt its own outbound ratchet ciphertext.
    // Record Unavailable directly: probing Active first would make an exact
    // full reconnect look like a same-revision resurrection on the next epoch.
    if message.remote_state == RemoteMessageStateKind::Active
        && message.sender_id == scope.self_account.locator.user_id
        && !client
            .db()
            .ok_or(DirectHistoryInstallError::StorageUncertain)?
            .message_exists(&message.id)
            .map_err(|_| DirectHistoryInstallError::StorageUncertain)?
    {
        client
            .reconcile_remote_message_metadata_classified(
                &message.id,
                &scope.conversation_id,
                &message.sender_identity_key,
                &metadata,
                RemoteMessageStateKind::Unavailable,
            )
            .map_err(classify_history_mutation_error)?;
        result.unavailable += 1;
        return Ok(());
    }

    let action = client
        .reconcile_remote_message_metadata_classified(
            &message.id,
            &scope.conversation_id,
            &message.sender_identity_key,
            &metadata,
            message.remote_state,
        )
        .map_err(classify_history_mutation_error)?;

    match action {
        RemoteReconcileAction::Deleted => {
            result.tombstones += 1;
        }
        RemoteReconcileAction::Unavailable => {
            result.unavailable += 1;
        }
        RemoteReconcileAction::Unchanged | RemoteReconcileAction::SelfStateOnly => {
            if client
                .db()
                .ok_or(DirectHistoryInstallError::StorageUncertain)?
                .message_exists(&message.id)
                .map_err(|_| DirectHistoryInstallError::StorageUncertain)?
            {
                client
                    .db()
                    .ok_or(DirectHistoryInstallError::StorageUncertain)?
                    .attach_message_author_with_context(
                        &message.id,
                        author,
                        MessageAuthorContext::DirectoryMemberAtObservation,
                    )
                    .map_err(|_| DirectHistoryInstallError::StorageUncertain)?;
            }
            result.duplicates += 1;
        }
        RemoteReconcileAction::NeedsInitialCiphertext => {
            match client
                .receive_and_persist_direct_history_message(
                    &message.id,
                    &scope.conversation_id,
                    &message.sender_identity_key,
                    author,
                    MessageAuthorContext::DirectoryMemberAtObservation,
                    message.security_context.as_ref(),
                    &message.header,
                    &message.ciphertext,
                    Some(message.server_timestamp),
                    message.reply_to_id.as_deref(),
                    Some(&metadata),
                )
                .map_err(classify_history_mutation_error)?
            {
                ReceiveMessageResult::Stored { mut plaintext } => {
                    plaintext.zeroize();
                    result.stored += 1;
                }
                ReceiveMessageResult::Duplicate => result.duplicates += 1,
            }
        }
        RemoteReconcileAction::NeedsEncryptedEdit => {
            // Edited ciphertext is rejected during page validation. Reaching
            // this action would mean local metadata cannot be reconciled with
            // the immutable-history preview contract, so fail closed without
            // attempting a later ratchet step.
            return Err(DirectHistoryInstallError::rejected(
                DirectHistoryRejectCode::UnsupportedMessage,
            ));
        }
    }
    Ok(())
}

fn classify_history_mutation_error(error: DirectHistoryMutationError) -> DirectHistoryInstallError {
    match error {
        DirectHistoryMutationError::ConversationRejected(_) => {
            DirectHistoryInstallError::rejected(DirectHistoryRejectCode::CryptographicFailure)
        }
        DirectHistoryMutationError::StorageUncertain(_) => {
            DirectHistoryInstallError::StorageUncertain
        }
    }
}

fn validate_cursor(cursor: &str) -> Result<(), String> {
    if cursor.is_empty()
        || cursor.len() > DIRECT_HISTORY_CURSOR_LIMIT
        || !cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Direct history cursor is invalid".to_string());
    }
    Ok(())
}

fn decode_canonical_uuid(field: &str, value: &str) -> Result<[u8; 16], String> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| format!("{field} must be a canonical lowercase UUID"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(format!(
            "{field} must be a canonical non-nil lowercase UUID"
        ));
    }
    Ok(*parsed.as_bytes())
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
        .map_err(|_| format!("{field} is invalid"))?
        .try_into()
        .map_err(|_| format!("{field} has the wrong length"))
}

fn parse_canonical_u63(_field: &str, value: &str) -> Result<u64, DirectHistoryInstallError> {
    if value.is_empty()
        || value.len() > 19
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| DirectHistoryInstallError::rejected(DirectHistoryRejectCode::InvalidPage))?;
    if parsed == 0 || parsed > i64::MAX as u64 {
        return Err(DirectHistoryInstallError::rejected(
            DirectHistoryRejectCode::InvalidPage,
        ));
    }
    Ok(parsed)
}

fn decode_lower_hex_bounded(field: &str, value: &str, limit: usize) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > limit.saturating_mul(2)
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} is empty, oversized, or non-canonical"));
    }
    hex::decode(value).map_err(|_| format!("{field} is invalid"))
}

fn parse_canonical_utc(field: &str, value: &str) -> Result<DateTime<Utc>, String> {
    if value.len() < 20 || value.len() > 30 || !value.ends_with('Z') {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| format!("{field} must be canonical UTC RFC3339Nano"))?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true) != value {
        return Err(format!("{field} must be canonical UTC RFC3339Nano"));
    }
    Ok(parsed)
}

fn validate_bounded_text(field: &str, value: &str, limit: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > limit
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(format!("{field} is invalid"));
    }
    Ok(())
}

fn reject_duplicate_json_keys(input: &[u8]) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| format!("invalid Direct history JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid Direct history JSON: {error}"))
}

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_HISTORY_JSON_DEPTH {
            return Err(serde::de::Error::custom(
                "Direct history JSON exceeds the nesting limit",
            ));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom(
                    "Direct history JSON contains a duplicate object key",
                ));
            }
            map.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonSeed {
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonSeed {
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_bytes<E>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_byte_buf<E>(self, _: Vec<u8>) -> Result<Self::Value, E> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    const ORIGIN: &str = "https://history.example.test:443";
    const SELF_USER: &str = "10000000-0000-4000-8000-000000000001";
    const PEER_USER: &str = "10000000-0000-4000-8000-000000000002";
    const OTHER_USER: &str = "10000000-0000-4000-8000-000000000003";
    const CONVERSATION: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER_CONVERSATION: &str = "20000000-0000-4000-8000-000000000002";

    struct HistoryFixture {
        receiver: VeilClient,
        sender: VeilClient,
        receiver_path: std::path::PathBuf,
        self_identity: [u8; 32],
        self_signing: [u8; 32],
        peer_identity: [u8; 32],
        peer_signing: [u8; 32],
    }

    impl HistoryFixture {
        fn new() -> Self {
            let mut receiver = VeilClient::new();
            let mnemonic = receiver.generate_mnemonic();
            let receiver_path = std::env::temp_dir()
                .join(format!("veil-direct-history-{}.db", uuid::Uuid::new_v4()));
            receiver
                .init_with_mnemonic(&mnemonic, &receiver_path)
                .unwrap();
            receiver
                .test_only_restore_authenticated_user_from_durable_binding(ORIGIN, SELF_USER)
                .unwrap();
            let self_identity = receiver.identity_key().unwrap();
            let self_signing = receiver.signing_key().unwrap();

            let sender_identity = veil_crypto::IdentityKeyPair::generate();
            let peer_identity = sender_identity.x25519_public_bytes();
            let peer_signing = sender_identity.ed25519_public_bytes();
            let sender = VeilClient::from_identity(sender_identity);

            let directory = serde_json::to_vec(&serde_json::json!({
                "count": 1,
                "conversations": [{
                    "id": CONVERSATION,
                    "conv_type": 0,
                    "name": null,
                    "server_id": null,
                    "created_at": "2026-07-18T00:00:00Z",
                    "members": [
                        {
                            "user_id": SELF_USER,
                            "username": "self",
                            "identity_key": hex::encode(self_identity),
                            "signing_key": hex::encode(self_signing),
                        },
                        {
                            "user_id": PEER_USER,
                            "username": "peer",
                            "identity_key": hex::encode(peer_identity),
                            "signing_key": hex::encode(peer_signing),
                        }
                    ]
                }]
            }))
            .unwrap();
            crate::direct::install_authenticated_direct_directory_page(
                &mut receiver,
                ORIGIN,
                SELF_USER,
                None,
                &directory,
            )
            .unwrap();

            Self {
                receiver,
                sender,
                receiver_path,
                self_identity,
                self_signing,
                peer_identity,
                peer_signing,
            }
        }

        fn establish_sender_session(&mut self) {
            let prekeys = self.receiver.generate_prekeys().unwrap();
            let (one_time_prekey, one_time_prekey_id) = prekeys.otk_publics[0];
            let bundle = veil_crypto::x3dh::PreKeyBundle {
                identity_key: self.self_identity,
                signing_key: self.self_signing,
                signed_prekey: prekeys.spk_public,
                signed_prekey_signature: prekeys.spk_signature,
                signed_prekey_id: prekeys.spk_id,
                one_time_prekey: Some(one_time_prekey),
                one_time_prekey_id: Some(one_time_prekey_id),
            };
            self.sender
                .establish_session(&self.self_identity, &bundle)
                .unwrap();
            self.sender
                .bind_dm_conversation(CONVERSATION, self.self_identity)
                .unwrap();
        }

        fn close(self) {
            let path = self.receiver_path.clone();
            drop(self.receiver);
            drop(self.sender);
            let _ = std::fs::remove_file(path);
        }
    }

    fn message_id(index: u64) -> String {
        format!("30000000-0000-4000-8000-{index:012x}")
    }

    fn timestamp(index: i64) -> (String, i64) {
        let instant = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap()
            + Duration::milliseconds(index);
        (
            instant.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            instant.timestamp_millis(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn message(
        index: u64,
        sender_id: &str,
        sender_identity: [u8; 32],
        sender_signing: [u8; 32],
        header: &[u8],
        ciphertext: &[u8],
        is_deleted: bool,
        is_expired: bool,
    ) -> serde_json::Value {
        let (created_at, server_timestamp) = timestamp(index as i64);
        serde_json::json!({
            "id": message_id(index),
            "conversation_id": CONVERSATION,
            "sender_id": sender_id,
            "sender_identity_key": hex::encode(sender_identity),
            "sender_signing_key": hex::encode(sender_signing),
            "ciphertext": hex::encode(ciphertext),
            "header": hex::encode(header),
            "msg_type": 0,
            "reply_to_id": null,
            "edited_at": null,
            "is_deleted": is_deleted,
            "is_expired": is_expired,
            "reactions": [],
            "attachments": [],
            "created_at": created_at,
            "server_timestamp": server_timestamp,
            "revision_timestamp": server_timestamp,
            "crypto_profile": "legacy_unknown"
        })
    }

    fn fake_active_message(
        fixture: &HistoryFixture,
        index: u64,
        self_authored: bool,
    ) -> serde_json::Value {
        let mut header = vec![0u8; 82];
        header[0] = 0x01;
        if self_authored {
            message(
                index,
                SELF_USER,
                fixture.self_identity,
                fixture.self_signing,
                &header,
                &[0x42],
                false,
                false,
            )
        } else {
            message(
                index,
                PEER_USER,
                fixture.peer_identity,
                fixture.peer_signing,
                &header,
                &[0x42],
                false,
                false,
            )
        }
    }

    fn terminal_message(
        fixture: &HistoryFixture,
        index: u64,
        deleted: bool,
        expired: bool,
    ) -> serde_json::Value {
        let mut value = message(
            index,
            PEER_USER,
            fixture.peer_identity,
            fixture.peer_signing,
            &[],
            &[],
            deleted,
            expired,
        );
        if expired {
            value["expires_at"] = serde_json::json!("2025-12-31T23:59:59Z");
        }
        value
    }

    fn page(messages: Vec<serde_json::Value>, next_cursor: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "count": messages.len(),
            "messages": messages,
        });
        if let Some(cursor) = next_cursor {
            value["next_cursor"] = serde_json::json!(cursor);
        }
        serde_json::to_vec(&value).unwrap()
    }

    fn assert_rejected(
        result: Result<DirectHistoryPageResult, DirectHistoryInstallError>,
        code: DirectHistoryRejectCode,
    ) {
        assert_eq!(
            result.unwrap_err(),
            DirectHistoryInstallError::ConversationRejected { code }
        );
    }

    #[test]
    fn sync_state_seals_canonical_origin_user_and_conversation() {
        let state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_eq!(state.canonical_server_origin(), ORIGIN);
        assert_eq!(state.authenticated_user_id(), SELF_USER);
        assert_eq!(state.conversation_id(), CONVERSATION);
        assert!(DirectHistorySyncState::new(
            "https://history.example.test",
            SELF_USER,
            CONVERSATION
        )
        .is_err());
        assert!(DirectHistorySyncState::new(ORIGIN, "not-a-user", CONVERSATION).is_err());

        let mut fixture = HistoryFixture::new();
        let mut wrong_user = DirectHistorySyncState::new(ORIGIN, OTHER_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut wrong_user,
                &page(Vec::new(), None),
            ),
            DirectHistoryRejectCode::ScopeMismatch,
        );
        assert_eq!(wrong_user.pages(), 0);
        fixture.close();
    }

    #[test]
    fn installs_two_real_crypto_pages_initial_then_ratchet() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let mut first_page = Vec::new();
        for index in 1..=DIRECT_HISTORY_PAGE_LIMIT as u64 {
            let (ciphertext, header) = fixture
                .sender
                .test_only_encrypt_outgoing(CONVERSATION, &format!("history {index}"))
                .unwrap();
            assert_eq!(header[0], 0x01);
            first_page.push(message(
                index,
                PEER_USER,
                fixture.peer_identity,
                fixture.peer_signing,
                &header,
                &ciphertext,
                false,
                false,
            ));
        }

        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_eq!(
            direct_history_request_target(&state).unwrap(),
            format!("/v1/messages/{CONVERSATION}?limit=25")
        );
        let first = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(first_page, Some("page_two")),
        )
        .unwrap();
        assert_eq!(first.stored, DIRECT_HISTORY_PAGE_LIMIT);
        assert_eq!(first.next_cursor.as_deref(), Some("page_two"));
        assert!(!first.conversation_complete);
        assert_eq!(
            direct_history_request_target(&state).unwrap(),
            format!("/v1/messages/{CONVERSATION}?limit=25&cursor=page_two")
        );

        fixture
            .sender
            .test_only_confirm_peer_session_possession(&fixture.self_identity)
            .unwrap();
        let final_index = DIRECT_HISTORY_PAGE_LIMIT as u64 + 1;
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "history 26")
            .unwrap();
        assert_eq!(header[0], 0x02);
        let second = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(
                vec![message(
                    final_index,
                    PEER_USER,
                    fixture.peer_identity,
                    fixture.peer_signing,
                    &header,
                    &ciphertext,
                    false,
                    false,
                )],
                None,
            ),
        )
        .unwrap();
        assert_eq!(second.stored, 1);
        assert!(second.conversation_complete);
        assert!(state.is_complete());
        assert_eq!(state.pages(), 2);
        assert_eq!(state.messages(), 26);
        assert!(direct_history_request_target(&state).is_err());

        let stored = fixture
            .receiver
            .db()
            .unwrap()
            .get_messages(CONVERSATION, 100)
            .unwrap();
        assert_eq!(stored.len(), 26);
        assert_eq!(stored.first().unwrap().plaintext, "history 1");
        assert_eq!(stored.last().unwrap().plaintext, "history 26");
        assert!(stored.iter().all(|entry| {
            entry.author.as_ref().is_some_and(|author| {
                author.locator.user_id == PEER_USER
                    && author.locator.identity_key == fixture.peer_identity
            })
        }));
        fixture.close();
    }

    #[test]
    fn accepts_short_wire_budget_page_with_progressing_cursor() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "short first page")
            .unwrap();
        assert_eq!(header[0], 0x01);

        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        let first = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(
                vec![message(
                    1,
                    PEER_USER,
                    fixture.peer_identity,
                    fixture.peer_signing,
                    &header,
                    &ciphertext,
                    false,
                    false,
                )],
                Some("wire_budget_page_two"),
            ),
        )
        .unwrap();
        assert_eq!(first.stored, 1);
        assert_eq!(first.outcome, DirectHistorySyncOutcome::InProgress);
        assert_eq!(state.pages(), 1);
        assert_eq!(state.messages(), 1);
        assert_eq!(state.current_cursor(), Some("wire_budget_page_two"));

        fixture
            .sender
            .test_only_confirm_peer_session_possession(&fixture.self_identity)
            .unwrap();
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "final page")
            .unwrap();
        assert_eq!(header[0], 0x02);
        let final_page = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(
                vec![message(
                    2,
                    PEER_USER,
                    fixture.peer_identity,
                    fixture.peer_signing,
                    &header,
                    &ciphertext,
                    false,
                    false,
                )],
                None,
            ),
        )
        .unwrap();
        assert_eq!(final_page.stored, 1);
        assert_eq!(final_page.outcome, DirectHistorySyncOutcome::Complete);
        assert!(state.is_complete());
        assert_eq!(state.messages(), 2);
        fixture.close();
    }

    #[test]
    fn self_authored_missing_row_is_unavailable_and_full_epoch_replay_is_idempotent() {
        let mut fixture = HistoryFixture::new();
        let response = page(vec![fake_active_message(&fixture, 1, true)], None);

        for _ in 0..2 {
            let mut epoch = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
            let result = install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut epoch,
                &response,
            )
            .unwrap();
            assert_eq!(result.unavailable, 1);
            assert_eq!(result.stored, 0);
            assert_eq!(
                result.outcome,
                DirectHistorySyncOutcome::IncompleteSelfHistory
            );
            assert!(!result.conversation_complete);
            assert_eq!(
                epoch.outcome(),
                DirectHistorySyncOutcome::IncompleteSelfHistory
            );
            assert!(epoch.is_terminal());
            assert!(!epoch.is_complete());
            assert!(direct_history_request_target(&epoch).is_err());
        }

        assert!(!fixture
            .receiver
            .db()
            .unwrap()
            .message_exists(&message_id(1))
            .unwrap());
        assert_eq!(
            fixture
                .receiver
                .db()
                .unwrap()
                .get_remote_message_state(&message_id(1))
                .unwrap()
                .unwrap()
                .state,
            RemoteMessageStateKind::Unavailable
        );
        fixture.close();
    }

    #[test]
    fn tracks_cursor_order_and_cross_page_replay_without_mutating_rejected_pages() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let mut first_messages = Vec::new();
        for index in 1..=DIRECT_HISTORY_PAGE_LIMIT as u64 {
            let (ciphertext, header) = fixture
                .sender
                .test_only_encrypt_outgoing(CONVERSATION, &format!("ordered {index}"))
                .unwrap();
            first_messages.push(message(
                index,
                PEER_USER,
                fixture.peer_identity,
                fixture.peer_signing,
                &header,
                &ciphertext,
                false,
                false,
            ));
        }
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(first_messages, Some("page_two")),
        )
        .unwrap();

        let replayed = page(vec![terminal_message(&fixture, 25, true, false)], None);
        assert_rejected(
            install_authenticated_direct_history_page(&mut fixture.receiver, &mut state, &replayed),
            DirectHistoryRejectCode::OrderingViolation,
        );
        let cursor_cycle = page(
            vec![terminal_message(&fixture, 26, true, false)],
            Some("page_two"),
        );
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &cursor_cycle,
            ),
            DirectHistoryRejectCode::OrderingViolation,
        );
        let mut out_of_order = fake_active_message(&fixture, 26, false);
        let (old_timestamp, old_millis) = timestamp(1);
        out_of_order["created_at"] = serde_json::json!(old_timestamp);
        out_of_order["server_timestamp"] = serde_json::json!(old_millis);
        out_of_order["revision_timestamp"] = serde_json::json!(old_millis);
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![out_of_order], None),
            ),
            DirectHistoryRejectCode::OrderingViolation,
        );
        assert_eq!(state.pages(), 1);
        assert_eq!(state.messages(), DIRECT_HISTORY_PAGE_LIMIT);
        assert_eq!(state.current_cursor(), Some("page_two"));
        fixture.close();
    }

    #[test]
    fn rejects_scope_identity_timestamp_and_revision_substitution() {
        let mut fixture = HistoryFixture::new();
        let valid = fake_active_message(&fixture, 1, false);

        let mut identity_substitution = valid.clone();
        identity_substitution["sender_identity_key"] = hex::encode(fixture.self_identity).into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![identity_substitution], None),
            ),
            DirectHistoryRejectCode::IdentityMismatch,
        );

        let mut sender_substitution = valid.clone();
        sender_substitution["sender_id"] = OTHER_USER.into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![sender_substitution], None),
            ),
            DirectHistoryRejectCode::ScopeMismatch,
        );

        let mut conversation_substitution = valid.clone();
        conversation_substitution["conversation_id"] = OTHER_CONVERSATION.into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![conversation_substitution], None),
            ),
            DirectHistoryRejectCode::ScopeMismatch,
        );

        let mut noncanonical_time = valid.clone();
        noncanonical_time["created_at"] = "2026-01-01T00:00:00.000Z".into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![noncanonical_time], None),
            ),
            DirectHistoryRejectCode::InvalidPage,
        );

        let mut timestamp_mismatch = valid.clone();
        timestamp_mismatch["server_timestamp"] =
            serde_json::json!(valid["server_timestamp"].as_i64().unwrap() + 1);
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![timestamp_mismatch], None),
            ),
            DirectHistoryRejectCode::InvalidPage,
        );

        let mut revision_mismatch = valid;
        let (edited_at, _) = timestamp(100);
        revision_mismatch["edited_at"] = edited_at.into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![revision_mismatch], None),
            ),
            DirectHistoryRejectCode::UnsupportedMessage,
        );
        fixture.close();
    }

    #[test]
    fn rejects_nontext_attachments_modern_context_and_unknown_header_kinds() {
        let mut fixture = HistoryFixture::new();
        let valid = fake_active_message(&fixture, 1, false);

        let mut nontext = valid.clone();
        nontext["msg_type"] = serde_json::json!(1);
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![nontext], None),
            ),
            DirectHistoryRejectCode::UnsupportedMessage,
        );

        let mut attachment = valid.clone();
        attachment["attachments"] = serde_json::json!([{
            "media_id": "file",
            "encrypted_key": "AA==",
            "nonce": "AA==",
            "size": 1,
            "content_type": "application/octet-stream"
        }]);
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![attachment], None),
            ),
            DirectHistoryRejectCode::UnsupportedMessage,
        );

        let mut modern = valid.clone();
        modern["crypto_profile"] = "sender_key_v5".into();
        modern["crypto_era"] = "5".into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![modern], None),
            ),
            DirectHistoryRejectCode::UnsupportedMessage,
        );

        let mut header = valid;
        header["header"] = hex::encode([0x03; 42]).into();
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![header], None),
            ),
            DirectHistoryRejectCode::UnsupportedMessage,
        );
        fixture.close();
    }

    #[test]
    fn rejects_mutation_terminal_and_ttl_rows_before_ratchet_or_db_mutation() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "immutable preview")
            .unwrap();
        let active = message(
            1,
            PEER_USER,
            fixture.peer_identity,
            fixture.peer_signing,
            &header,
            &ciphertext,
            false,
            false,
        );

        let mut edited = active.clone();
        let (edited_at, edited_ms) = timestamp(2);
        edited["edited_at"] = edited_at.into();
        edited["revision_timestamp"] = edited_ms.into();
        let deleted = terminal_message(&fixture, 1, true, false);
        let expired = terminal_message(&fixture, 1, false, true);
        let mut ttl = active.clone();
        ttl["expires_at"] = "2026-01-02T00:00:00Z".into();

        for unsupported in [edited, deleted, expired, ttl] {
            let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
            assert_rejected(
                install_authenticated_direct_history_page(
                    &mut fixture.receiver,
                    &mut state,
                    &page(vec![unsupported], None),
                ),
                DirectHistoryRejectCode::UnsupportedMessage,
            );
            assert_eq!(state.pages(), 0);
            assert!(!fixture
                .receiver
                .db()
                .unwrap()
                .message_exists(&message_id(1))
                .unwrap());
            assert!(fixture
                .receiver
                .db()
                .unwrap()
                .load_ratchet_session(&fixture.peer_identity)
                .unwrap()
                .is_none());
        }

        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        let installed = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(vec![active], None),
        )
        .unwrap();
        assert_eq!(installed.stored, 1);
        assert_eq!(installed.outcome, DirectHistorySyncOutcome::Complete);
        fixture.close();
    }

    #[test]
    fn rejects_oversize_unknown_duplicate_and_noncanonical_cursor_input() {
        let expected = DirectHistoryInstallError::ConversationRejected {
            code: DirectHistoryRejectCode::InvalidPage,
        };
        let oversize = vec![b' '; DIRECT_HISTORY_RESPONSE_LIMIT + 1];
        assert_eq!(decode_history_page(&oversize).unwrap_err(), expected);
        assert_eq!(
            decode_history_page(br#"{"messages":[],"count":0,"unknown":true}"#).unwrap_err(),
            expected
        );
        assert_eq!(
            decode_history_page(br#"{"messages":[],"messages":[],"count":0}"#).unwrap_err(),
            expected
        );

        let mut fixture = HistoryFixture::new();
        let mut empty_cursor_state =
            DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_rejected(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut empty_cursor_state,
                &page(Vec::new(), Some("no_progress")),
            ),
            DirectHistoryRejectCode::OrderingViolation,
        );
        assert_eq!(empty_cursor_state.pages(), 0);
        fixture.close();

        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        state.current_cursor = Some("not+base64".to_string());
        assert!(direct_history_request_target(&state).is_err());
    }

    #[test]
    fn poison_ciphertext_is_conversation_rejected_without_ratchet_or_db_mutation() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "authenticated history")
            .unwrap();
        let mut poison = ciphertext.clone();
        poison[0] ^= 1;
        let poisoned = message(
            1,
            PEER_USER,
            fixture.peer_identity,
            fixture.peer_signing,
            &header,
            &poison,
            false,
            false,
        );
        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_eq!(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![poisoned], None),
            )
            .unwrap_err(),
            DirectHistoryInstallError::ConversationRejected {
                code: DirectHistoryRejectCode::CryptographicFailure
            }
        );
        assert_eq!(state.pages(), 0);
        assert_eq!(state.messages(), 0);
        assert_eq!(state.current_cursor(), None);
        assert!(!fixture
            .receiver
            .db()
            .unwrap()
            .message_exists(&message_id(1))
            .unwrap());
        assert!(fixture
            .receiver
            .db()
            .unwrap()
            .load_ratchet_session(&fixture.peer_identity)
            .unwrap()
            .is_none());

        let valid = message(
            1,
            PEER_USER,
            fixture.peer_identity,
            fixture.peer_signing,
            &header,
            &ciphertext,
            false,
            false,
        );
        let installed = install_authenticated_direct_history_page(
            &mut fixture.receiver,
            &mut state,
            &page(vec![valid], None),
        )
        .unwrap();
        assert_eq!(installed.stored, 1);
        assert!(state.is_complete());
        fixture.close();
    }

    #[test]
    fn sqlcipher_write_failure_revokes_the_complete_native_epoch() {
        let mut fixture = HistoryFixture::new();
        fixture.establish_sender_session();
        let (ciphertext, header) = fixture
            .sender
            .test_only_encrypt_outgoing(CONVERSATION, "retry after storage failure")
            .unwrap();
        let valid = message(
            1,
            PEER_USER,
            fixture.peer_identity,
            fixture.peer_signing,
            &header,
            &ciphertext,
            false,
            false,
        );
        fixture
            .receiver
            .db()
            .unwrap()
            .conn()
            .execute_batch(
                "CREATE TRIGGER reject_direct_history_message
                 BEFORE INSERT ON messages
                 BEGIN SELECT RAISE(ABORT, 'simulated Direct history write failure'); END;",
            )
            .unwrap();

        let mut state = DirectHistorySyncState::new(ORIGIN, SELF_USER, CONVERSATION).unwrap();
        assert_eq!(
            install_authenticated_direct_history_page(
                &mut fixture.receiver,
                &mut state,
                &page(vec![valid.clone()], None),
            )
            .unwrap_err(),
            DirectHistoryInstallError::StorageUncertain
        );
        assert_eq!(state.pages(), 0);
        assert_eq!(
            fixture
                .receiver
                .direct_conversation_availability_v1(CONVERSATION),
            crate::api::DirectConversationAvailabilityV1::RuntimeRevoked
        );
        assert!(fixture.receiver.db().is_none());
        assert!(fixture.receiver.identity_key().is_err());
        assert!(fixture.receiver.authenticated_user_id().is_err());
        assert!(!fixture.receiver.has_session(&fixture.peer_identity));
        assert!(fixture.receiver.generate_prekeys().is_err());
        fixture.close();
    }
}
