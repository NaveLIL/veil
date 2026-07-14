//! Local-only full-text search index for decrypted Veil messages.
//!
//! Backed by [Tantivy]. For sensitive message content, callers should use the
//! process-memory-only index and rebuild it from their encrypted database after
//! unlock. The index is never transmitted to the server.
//!
//! # Schema
//! - `id`           — STRING, STORED (primary key, used for delete/update)
//! - `conversation` — STRING, STORED, INDEXED (filter by conversation)
//! - `sender`       — STRING, STORED, INDEXED (sender hex key)
//! - `body`         — TEXT,   STORED          (full-text searchable)
//! - `ts`           — i64,    STORED, FAST    (sort by recency)

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tantivy::collector::TopDocs;
use tantivy::directory::RamDirectory;
use tantivy::query::{BooleanQuery, FuzzyTermQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, SchemaBuilder, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::tokenizer::TextAnalyzer;
use tantivy::{doc, Index, IndexWriter, ReloadPolicy, Term};
use thiserror::Error;

/// Heap budget for the index writer. 50 MB is plenty for a personal IM index
/// and well under the per-process WebView memory ceiling on weak laptops.
const WRITER_HEAP: usize = 50 * 1024 * 1024;

/// Maximum number of decrypted messages retained by the process-local index.
pub const MAX_INDEXED_MESSAGES: usize = 250_000;

/// Maximum estimated source payload retained by the process-local index.
pub const MAX_INDEX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

/// The encrypted database stores a 32-byte raw sender identity key. The
/// Tantivy document contains its encoded representation, but coverage uses the
/// source-size estimate so callers and rebuilds share one stable budget.
const RAW_SENDER_KEY_BYTES: usize = 32;
const SEARCH_DOCUMENT_OVERHEAD_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("tantivy: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
    #[error("query: {0}")]
    Query(#[from] tantivy::query::QueryParserError),
    #[error("poisoned writer mutex")]
    Poisoned,
    #[error("search rebuild cancelled")]
    Cancelled,
    #[error("search index changed while a replacement was being prepared")]
    MutationConflict,
    #[error("search index metadata is inconsistent")]
    MetadataInvariant,
    #[error("search index is unavailable after a fail-closed clear")]
    Unavailable,
}

pub type Result<T> = std::result::Result<T, SearchError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub body: String,
    pub ts: i64,
    pub score: f32,
}

/// One owned document accepted by an atomic in-memory rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDocument {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub body: String,
    pub ts: i64,
}

#[derive(Clone, Copy)]
struct SearchDocumentRef<'a> {
    id: &'a str,
    conversation_id: &'a str,
    sender: &'a str,
    body: &'a str,
    ts: i64,
}

/// Coverage of the complete Tantivy snapshot currently visible to searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchCoverageSnapshot {
    pub indexed_messages: usize,
    pub source_bytes: usize,
    pub truncated: bool,
    pub mutation_generation: u64,
}

#[derive(Clone, Copy)]
struct Fields {
    id: Field,
    conversation: Field,
    sender: Field,
    body: Field,
    ts: Field,
}

/// Synchronous, thread-safe index handle. Cheap to clone via `Arc`.
pub struct Indexer {
    state: Mutex<Option<IndexState>>,
    mutation_generation: AtomicU64,
}

/// Complete process-memory-only candidate built before an atomic publication.
///
/// Keeping preparation separate from publication lets the desktop serialize
/// the final index swap with its origin/session coverage snapshot without
/// blocking cancellation while Tantivy builds the candidate.
pub struct PreparedMemoryIndex {
    state: IndexState,
}

struct IndexState {
    index: Index,
    writer: IndexWriter,
    fields: Fields,
    documents: HashMap<String, IndexedDocumentMetadata>,
    document_order: BTreeSet<(i64, String)>,
    source_bytes: usize,
    truncated: bool,
}

#[derive(Clone)]
struct IndexedDocumentMetadata {
    ts: i64,
    source_bytes: usize,
    conversation_id: String,
    sender: String,
}

#[derive(Clone, Copy)]
struct IndexLimits {
    max_documents: usize,
    max_source_bytes: usize,
}

const INDEX_LIMITS: IndexLimits = IndexLimits {
    max_documents: MAX_INDEXED_MESSAGES,
    max_source_bytes: MAX_INDEX_SOURCE_BYTES,
};

fn build_schema() -> (Schema, Fields) {
    let mut sb: SchemaBuilder = Schema::builder();
    let id = sb.add_text_field("id", STRING | STORED);
    let conversation = sb.add_text_field("conversation", STRING | STORED);
    let sender = sb.add_text_field("sender", STRING | STORED);
    let body = sb.add_text_field("body", TEXT | STORED);
    let ts = sb.add_i64_field("ts", STORED | INDEXED | FAST);
    let schema = sb.build();
    (
        schema,
        Fields {
            id,
            conversation,
            sender,
            body,
            ts,
        },
    )
}

impl Indexer {
    /// Create a process-memory-only index.
    ///
    /// Decrypted message bodies must not be duplicated into an unencrypted
    /// on-disk Tantivy index. The desktop rebuilds this index from SQLCipher
    /// after unlock and clears it again when locking.
    pub fn in_memory() -> Result<Self> {
        let state = new_memory_state()?;
        Ok(Self {
            state: Mutex::new(Some(state)),
            mutation_generation: AtomicU64::new(0),
        })
    }

    /// Index (or replace) a message.
    pub fn index_message(
        &self,
        id: &str,
        conversation_id: &str,
        sender: &str,
        body: &str,
        ts: i64,
    ) -> Result<()> {
        // SQLCipher rebuild deliberately excludes empty text rows (for
        // example attachment-only messages). Keep the live projection exactly
        // equivalent instead of counting a document that can never match.
        if body.is_empty() {
            return self.delete(id);
        }
        self.index_message_with_limits(id, conversation_id, sender, body, ts, INDEX_LIMITS)
    }

    fn index_message_with_limits(
        &self,
        id: &str,
        conversation_id: &str,
        sender: &str,
        body: &str,
        ts: i64,
        limits: IndexLimits,
    ) -> Result<()> {
        let mut state_guard = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let state = state_guard.as_mut().ok_or(SearchError::Unavailable)?;
        self.index_message_in_state_with_limits(
            state,
            SearchDocumentRef {
                id,
                conversation_id,
                sender,
                body,
                ts,
            },
            limits,
        )
    }

    fn index_message_in_state_with_limits(
        &self,
        state: &mut IndexState,
        document: SearchDocumentRef<'_>,
        limits: IndexLimits,
    ) -> Result<()> {
        let SearchDocumentRef {
            id,
            conversation_id,
            sender,
            body,
            ts,
        } = document;
        let fields = state.fields;
        let source_bytes = estimated_source_bytes(id, conversation_id, body);
        let old = state.documents.get(id).cloned();
        let mut retained_messages = state.documents.len() - usize::from(old.is_some()) + 1;
        let mut retained_source_bytes = state
            .source_bytes
            .saturating_sub(old.as_ref().map_or(0, |metadata| metadata.source_bytes))
            .saturating_add(source_bytes);
        let new_order = (ts, id.to_owned());
        let mut retain_new = true;
        let mut evicted = Vec::new();
        let mut existing = state
            .document_order
            .iter()
            .filter(|(_, existing_id)| existing_id != id)
            .peekable();

        while retained_messages > limits.max_documents
            || retained_source_bytes > limits.max_source_bytes
        {
            let new_is_oldest = retain_new
                && existing
                    .peek()
                    .is_none_or(|oldest_existing| new_order <= **oldest_existing);
            if new_is_oldest {
                retain_new = false;
                retained_messages -= 1;
                retained_source_bytes = retained_source_bytes.saturating_sub(source_bytes);
            } else if let Some((_, oldest_id)) = existing.next() {
                let Some(metadata) = state.documents.get(oldest_id) else {
                    state.truncated = true;
                    self.advance_mutation_generation();
                    return Err(SearchError::MetadataInvariant);
                };
                retained_messages -= 1;
                retained_source_bytes = retained_source_bytes.saturating_sub(metadata.source_bytes);
                evicted.push(oldest_id.clone());
            } else {
                break;
            }
        }

        if old.is_some() {
            state
                .writer
                .delete_term(Term::from_field_text(fields.id, id));
        }
        for evicted_id in &evicted {
            state
                .writer
                .delete_term(Term::from_field_text(fields.id, evicted_id));
        }
        if retain_new {
            if let Err(error) = state.writer.add_document(doc!(
                fields.id => id,
                fields.conversation => conversation_id,
                fields.sender => sender,
                fields.body => body,
                fields.ts => ts,
            )) {
                let _ = state.writer.rollback();
                state.truncated = true;
                self.advance_mutation_generation();
                return Err(error.into());
            }
        }
        if old.is_some() || !evicted.is_empty() || retain_new {
            if let Err(error) = state.writer.commit() {
                let _ = state.writer.rollback();
                state.truncated = true;
                self.advance_mutation_generation();
                return Err(error.into());
            }
        }

        remove_document_metadata(state, id);
        for evicted_id in &evicted {
            remove_document_metadata(state, evicted_id);
        }
        if retain_new {
            insert_document_metadata(
                state,
                id.to_owned(),
                conversation_id.to_owned(),
                sender.to_owned(),
                ts,
                source_bytes,
            );
        }
        state.truncated |= !evicted.is_empty() || !retain_new;
        debug_assert_eq!(state.documents.len(), retained_messages);
        debug_assert_eq!(state.source_bytes, retained_source_bytes);
        self.advance_mutation_generation();
        Ok(())
    }

    /// Replace only the searchable body of an already-retained message while
    /// preserving its original conversation, sender, timestamp and therefore
    /// its position in the newest continuous slice.
    ///
    /// An edit for a message outside the retained slice must not reinsert that
    /// old message as if it were newly sent. In that case coverage becomes
    /// explicitly partial and the caller may schedule a full rebuild.
    pub fn update_message_body(&self, id: &str, body: &str) -> Result<bool> {
        let mut state_guard = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let state = state_guard.as_mut().ok_or(SearchError::Unavailable)?;
        let Some(metadata) = state.documents.get(id).cloned() else {
            state.truncated = true;
            self.advance_mutation_generation();
            return Ok(false);
        };
        if body.is_empty() {
            let id_field = state.fields.id;
            state
                .writer
                .delete_term(Term::from_field_text(id_field, id));
            if let Err(error) = state.writer.commit() {
                let _ = state.writer.rollback();
                state.truncated = true;
                self.advance_mutation_generation();
                return Err(error.into());
            }
            remove_document_metadata(state, id);
            self.advance_mutation_generation();
            return Ok(true);
        }
        self.index_message_in_state_with_limits(
            state,
            SearchDocumentRef {
                id,
                conversation_id: &metadata.conversation_id,
                sender: &metadata.sender,
                body,
                ts: metadata.ts,
            },
            INDEX_LIMITS,
        )?;
        Ok(true)
    }

    /// Build a fresh RAM index and publish it in one atomic swap.
    ///
    /// Searches continue to use the previous complete snapshot while the new
    /// candidate is assembled. Cancellation drops the candidate and preserves
    /// that previous snapshot, so the UI never observes a half-built index.
    pub fn replace_all_in_memory_cancellable<F>(
        &self,
        documents: &[SearchDocument],
        should_continue: F,
    ) -> Result<()>
    where
        F: Fn() -> bool,
    {
        let expected_mutation_generation = self.mutation_generation();
        let candidate = Self::prepare_replacement_cancellable(documents, &should_continue)?;
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }
        self.publish_prepared(candidate, expected_mutation_generation, false)
            .map(|_| ())
    }

    /// Build a complete RAM candidate without changing the currently
    /// published index. Cancellation or any Tantivy failure drops only the
    /// candidate, preserving the prior searchable snapshot.
    pub fn prepare_replacement_cancellable<F>(
        documents: &[SearchDocument],
        should_continue: F,
    ) -> Result<PreparedMemoryIndex>
    where
        F: Fn() -> bool,
    {
        Self::prepare_replacement_with_limits(documents, should_continue, INDEX_LIMITS)
    }

    fn prepare_replacement_with_limits<F>(
        documents: &[SearchDocument],
        should_continue: F,
        limits: IndexLimits,
    ) -> Result<PreparedMemoryIndex>
    where
        F: Fn() -> bool,
    {
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }

        let mut candidate = new_memory_state()?;
        let fields = candidate.fields;
        let mut chosen_by_id = HashMap::with_capacity(documents.len().min(limits.max_documents));
        for (index, document) in documents.iter().enumerate() {
            if index.is_multiple_of(64) && !should_continue() {
                return Err(SearchError::Cancelled);
            }
            chosen_by_id
                .entry(document.id.as_str())
                .and_modify(|chosen: &mut usize| {
                    if document.ts >= documents[*chosen].ts {
                        *chosen = index;
                    }
                })
                .or_insert(index);
        }
        let duplicate_documents = chosen_by_id.len() != documents.len();
        let mut newest_first = chosen_by_id.into_values().collect::<Vec<_>>();
        newest_first.sort_unstable_by(|left, right| {
            let left = &documents[*left];
            let right = &documents[*right];
            (right.ts, right.id.as_str()).cmp(&(left.ts, left.id.as_str()))
        });

        let mut retained = Vec::with_capacity(newest_first.len().min(limits.max_documents));
        let mut source_bytes = 0usize;
        let mut truncated = duplicate_documents;
        for (position, document_index) in newest_first.into_iter().enumerate() {
            if position.is_multiple_of(64) && !should_continue() {
                return Err(SearchError::Cancelled);
            }
            let document = &documents[document_index];
            let document_source_bytes =
                estimated_source_bytes(&document.id, &document.conversation_id, &document.body);
            if retained.len() == limits.max_documents
                || source_bytes.saturating_add(document_source_bytes) > limits.max_source_bytes
            {
                truncated = true;
                break;
            }
            source_bytes += document_source_bytes;
            retained.push((document_index, document_source_bytes));
        }

        for (position, (document_index, document_source_bytes)) in retained.into_iter().enumerate()
        {
            if position.is_multiple_of(64) && !should_continue() {
                return Err(SearchError::Cancelled);
            }
            let document = &documents[document_index];
            candidate.writer.add_document(doc!(
                fields.id => document.id.as_str(),
                fields.conversation => document.conversation_id.as_str(),
                fields.sender => document.sender.as_str(),
                fields.body => document.body.as_str(),
                fields.ts => document.ts,
            ))?;
            insert_document_metadata(
                &mut candidate,
                document.id.clone(),
                document.conversation_id.clone(),
                document.sender.clone(),
                document.ts,
                document_source_bytes,
            );
        }
        candidate.writer.commit()?;
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }
        candidate.truncated = truncated;

        Ok(PreparedMemoryIndex { state: candidate })
    }

    /// Atomically publish one already-complete RAM candidate if no live
    /// mutation happened since the caller captured `expected_generation`.
    ///
    /// `source_truncated` carries forward the encrypted-database extraction
    /// report. Defensive trimming performed while preparing the candidate is
    /// combined with it and can never be hidden by the caller.
    pub fn publish_prepared(
        &self,
        mut candidate: PreparedMemoryIndex,
        expected_generation: u64,
        source_truncated: bool,
    ) -> Result<SearchCoverageSnapshot> {
        let mut current = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        if self.mutation_generation.load(Ordering::SeqCst) != expected_generation {
            return Err(SearchError::MutationConflict);
        }
        candidate.state.truncated |= source_truncated;
        let indexed_messages = candidate.state.documents.len();
        let source_bytes = candidate.state.source_bytes;
        let truncated = candidate.state.truncated;
        *current = Some(candidate.state);
        let mutation_generation = self.advance_mutation_generation();
        Ok(SearchCoverageSnapshot {
            indexed_messages,
            source_bytes,
            truncated,
            mutation_generation,
        })
    }

    /// Remove a message from the index.
    pub fn delete(&self, id: &str) -> Result<()> {
        let mut state_guard = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let state = state_guard.as_mut().ok_or(SearchError::Unavailable)?;
        if state.documents.contains_key(id) {
            let id_field = state.fields.id;
            state
                .writer
                .delete_term(Term::from_field_text(id_field, id));
            if let Err(error) = state.writer.commit() {
                let _ = state.writer.rollback();
                state.truncated = true;
                self.advance_mutation_generation();
                return Err(error.into());
            }
            remove_document_metadata(state, id);
        }
        self.advance_mutation_generation();
        Ok(())
    }

    /// Monotonic epoch used to prevent a prepared rebuild from overwriting
    /// live message mutations that happened during extraction or indexing.
    pub fn mutation_generation(&self) -> u64 {
        self.mutation_generation.load(Ordering::SeqCst)
    }

    /// Return metadata for the exact committed Tantivy view visible to search.
    pub fn coverage_snapshot(&self) -> Result<SearchCoverageSnapshot> {
        let state = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let mutation_generation = self.mutation_generation();
        let state = state.as_ref().ok_or(SearchError::Unavailable)?;
        Ok(snapshot_from_state(state, mutation_generation))
    }

    /// Search for `query`, optionally restricted to one conversation.
    ///
    /// Each whitespace-separated term is tokenised with the same analyser
    /// used at index time, then matched as a *prefix* (`FuzzyTermQuery::new_prefix`
    /// with edit-distance 0). Multi-token queries are combined with `AND`.
    /// This gives natural typeahead UX across both Latin and Cyrillic text
    /// ("сля" → "слякоть", "wond" → "wonderful").
    pub fn search(
        &self,
        query: &str,
        conversation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchHit>> {
        let state_guard = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let state = state_guard.as_ref().ok_or(SearchError::Unavailable)?;
        let fields = state.fields;
        let terms = tokenise(&state.index, fields.body, query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }

        let reader = state
            .index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;
        let searcher = reader.searcher();

        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::with_capacity(terms.len() + 1);
        for t in terms {
            let term = Term::from_field_text(fields.body, &t);
            // (term, distance, transposition_cost_one) — distance 0 = pure prefix.
            let q: Box<dyn Query> = Box::new(FuzzyTermQuery::new_prefix(term, 0, true));
            clauses.push((Occur::Must, q));
        }
        if let Some(conv) = conversation_id {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(fields.conversation, conv),
                    IndexRecordOption::Basic,
                )),
            ));
        }
        let final_query = BooleanQuery::new(clauses);

        let top = searcher.search(&final_query, &TopDocs::with_limit(limit).order_by_score())?;
        let mut hits = Vec::with_capacity(top.len());
        for (score, addr) in top {
            let doc: tantivy::TantivyDocument = searcher.doc(addr)?;
            hits.push(SearchHit {
                id: read_str(&doc, fields.id),
                conversation_id: read_str(&doc, fields.conversation),
                sender: read_str(&doc, fields.sender),
                body: read_str(&doc, fields.body),
                ts: read_i64(&doc, fields.ts),
                score,
            });
        }
        Ok(hits)
    }

    /// Drop every document. Used by "Rebuild index" / "Clear cache" actions.
    pub fn clear(&self) -> Result<()> {
        self.clear_with_factory(new_memory_state)
    }

    fn clear_with_factory<F>(&self, create_empty_state: F) -> Result<()>
    where
        F: FnOnce() -> Result<IndexState>,
    {
        // Clear is the fail-closed recovery boundary: even a previous panic
        // while holding the mutex must not keep the old plaintext state alive.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = state.take();
        drop(previous);
        self.advance_mutation_generation();
        self.state.clear_poison();

        let replacement = create_empty_state()?;
        *state = Some(replacement);
        Ok(())
    }

    fn advance_mutation_generation(&self) -> u64 {
        self.mutation_generation.fetch_add(1, Ordering::SeqCst) + 1
    }
}

fn new_memory_state() -> Result<IndexState> {
    let (schema, fields) = build_schema();
    let index = Index::open_or_create(RamDirectory::create(), schema)?;
    let writer = index.writer(WRITER_HEAP)?;
    Ok(IndexState {
        index,
        writer,
        fields,
        documents: HashMap::new(),
        document_order: BTreeSet::new(),
        source_bytes: 0,
        truncated: false,
    })
}

fn estimated_source_bytes(id: &str, conversation_id: &str, body: &str) -> usize {
    body.len()
        .saturating_add(id.len())
        .saturating_add(conversation_id.len())
        .saturating_add(RAW_SENDER_KEY_BYTES)
        .saturating_add(SEARCH_DOCUMENT_OVERHEAD_BYTES)
}

fn insert_document_metadata(
    state: &mut IndexState,
    id: String,
    conversation_id: String,
    sender: String,
    ts: i64,
    source_bytes: usize,
) {
    debug_assert!(!state.documents.contains_key(&id));
    state.document_order.insert((ts, id.clone()));
    state.documents.insert(
        id,
        IndexedDocumentMetadata {
            ts,
            source_bytes,
            conversation_id,
            sender,
        },
    );
    state.source_bytes += source_bytes;
}

fn remove_document_metadata(state: &mut IndexState, id: &str) {
    let Some(metadata) = state.documents.remove(id) else {
        return;
    };
    state.document_order.remove(&(metadata.ts, id.to_owned()));
    state.source_bytes = state.source_bytes.saturating_sub(metadata.source_bytes);
}

fn snapshot_from_state(state: &IndexState, mutation_generation: u64) -> SearchCoverageSnapshot {
    SearchCoverageSnapshot {
        indexed_messages: state.documents.len(),
        source_bytes: state.source_bytes,
        truncated: state.truncated,
        mutation_generation,
    }
}

fn read_str(doc: &tantivy::TantivyDocument, f: Field) -> String {
    use tantivy::schema::Value;
    doc.get_first(f)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn read_i64(doc: &tantivy::TantivyDocument, f: Field) -> i64 {
    use tantivy::schema::Value;
    doc.get_first(f)
        .and_then(|v| v.as_i64())
        .unwrap_or_default()
}

/// Run `query` through the index's tokenizer for `field` and return the
/// resulting term texts. This guarantees query terms go through the same
/// normalisation pipeline (lowercase + Unicode segmentation) that index
/// terms did, so Cyrillic / mixed-case input matches stored tokens.
fn tokenise(index: &Index, field: Field, query: &str) -> Vec<String> {
    let analyzer: TextAnalyzer = match index.tokenizer_for_field(field) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut analyzer = analyzer;
    let mut stream = analyzer.token_stream(query);
    let mut out = Vec::new();
    while let Some(tok) = stream.next() {
        if !tok.text.is_empty() {
            out.push(tok.text.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_search_delete_roundtrip() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("m1", "c1", "alice", "hello world", 1)
            .unwrap();
        idx.index_message("m2", "c1", "bob", "another message", 2)
            .unwrap();
        idx.index_message("m3", "c2", "alice", "world peace", 3)
            .unwrap();

        let hits = idx.search("world", None, 10).unwrap();
        assert_eq!(hits.len(), 2);

        let scoped = idx.search("world", Some("c2"), 10).unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, "m3");

        idx.delete("m3").unwrap();
        let after = idx.search("world", None, 10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, "m1");
    }

    #[test]
    fn live_empty_body_matches_rebuild_exclusion_and_removes_an_old_document() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("m1", "c1", "alice", "searchable", 1)
            .unwrap();
        idx.index_message("m1", "c1", "alice", "", 2).unwrap();

        assert!(idx.search("searchable", None, 10).unwrap().is_empty());
        let coverage = idx.coverage_snapshot().unwrap();
        assert_eq!(coverage.indexed_messages, 0);
        assert_eq!(coverage.source_bytes, 0);
        assert!(!coverage.truncated);
    }

    #[test]
    fn prefix_and_cyrillic_match() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("m1", "c1", "alice", "слякоть на улице", 1)
            .unwrap();
        idx.index_message("m2", "c1", "bob", "привет мир", 2)
            .unwrap();
        idx.index_message("m3", "c1", "alice", "Hello World wonderful", 3)
            .unwrap();

        // Cyrillic prefix
        let h1 = idx.search("сля", None, 10).unwrap();
        assert_eq!(h1.len(), 1);
        assert_eq!(h1[0].id, "m1");

        // ASCII prefix
        let h2 = idx.search("wond", None, 10).unwrap();
        assert_eq!(h2.len(), 1);
        assert_eq!(h2[0].id, "m3");

        // Multi-token AND
        let h3 = idx.search("слякоть улице", None, 10).unwrap();
        assert_eq!(h3.len(), 1);

        // Empty / metacharacter-only query yields nothing, not an error.
        assert!(idx.search("", None, 10).unwrap().is_empty());
        assert!(idx.search("***", None, 10).unwrap().is_empty());
    }

    #[test]
    fn atomic_rebuild_publishes_complete_snapshot_and_preserves_old_on_cancel() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("old", "c1", "alice", "previous snapshot", 1)
            .unwrap();

        let replacement = vec![
            SearchDocument {
                id: "new-1".into(),
                conversation_id: "c1".into(),
                sender: "bob".into(),
                body: "fresh searchable body".into(),
                ts: 2,
            },
            SearchDocument {
                id: "new-2".into(),
                conversation_id: "c2".into(),
                sender: "carol".into(),
                body: "another fresh result".into(),
                ts: 3,
            },
        ];
        idx.replace_all_in_memory_cancellable(&replacement, || true)
            .unwrap();
        assert!(idx.search("previous", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("fresh", None, 10).unwrap().len(), 2);

        let cancelled = idx.replace_all_in_memory_cancellable(
            &[SearchDocument {
                id: "never-published".into(),
                conversation_id: "c3".into(),
                sender: "mallory".into(),
                body: "discarded candidate".into(),
                ts: 4,
            }],
            || false,
        );
        assert!(matches!(cancelled, Err(SearchError::Cancelled)));
        assert!(idx.search("discarded", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("fresh", None, 10).unwrap().len(), 2);
    }

    #[test]
    fn live_replacement_keeps_count_and_source_bytes_exact() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("m1", "c1", "alice", "old payload", 1)
            .unwrap();
        assert_eq!(
            idx.coverage_snapshot().unwrap(),
            SearchCoverageSnapshot {
                indexed_messages: 1,
                source_bytes: estimated_source_bytes("m1", "c1", "old payload"),
                truncated: false,
                mutation_generation: 1,
            }
        );

        idx.index_message(
            "m1",
            "conversation-long",
            "alice",
            "new payload is longer",
            2,
        )
        .unwrap();
        assert_eq!(
            idx.coverage_snapshot().unwrap(),
            SearchCoverageSnapshot {
                indexed_messages: 1,
                source_bytes: estimated_source_bytes(
                    "m1",
                    "conversation-long",
                    "new payload is longer"
                ),
                truncated: false,
                mutation_generation: 2,
            }
        );
        assert!(idx.search("old", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("longer", None, 10).unwrap()[0].id, "m1");
    }

    #[test]
    fn live_edit_preserves_original_recency_and_missing_edits_stay_outside_the_slice() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("m1", "c1", "alice", "original body", 17)
            .unwrap();

        assert!(idx.update_message_body("m1", "edited body").unwrap());
        assert!(idx.search("original", None, 10).unwrap().is_empty());
        let edited = idx.search("edited", None, 10).unwrap();
        assert_eq!(edited.len(), 1);
        assert_eq!(edited[0].conversation_id, "c1");
        assert_eq!(edited[0].sender, "alice");
        assert_eq!(edited[0].ts, 17);
        assert!(!idx.coverage_snapshot().unwrap().truncated);

        assert!(!idx
            .update_message_body("outside", "must not reinsert")
            .unwrap());
        assert!(idx.search("reinsert", None, 10).unwrap().is_empty());
        assert!(idx.coverage_snapshot().unwrap().truncated);
    }

    #[test]
    fn live_count_budget_retains_the_newest_continuous_set() {
        let idx = Indexer::in_memory().unwrap();
        let limits = IndexLimits {
            max_documents: 3,
            max_source_bytes: usize::MAX,
        };
        for timestamp in 1..=4 {
            let id = format!("m{timestamp}");
            let body = format!("term{timestamp}");
            idx.index_message_with_limits(&id, "c1", "alice", &body, timestamp, limits)
                .unwrap();
        }

        let coverage = idx.coverage_snapshot().unwrap();
        assert_eq!(coverage.indexed_messages, 3);
        assert!(coverage.truncated);
        assert!(idx.search("term1", None, 10).unwrap().is_empty());
        for timestamp in 2..=4 {
            assert_eq!(
                idx.search(&format!("term{timestamp}"), None, 10)
                    .unwrap()
                    .len(),
                1
            );
        }

        idx.index_message_with_limits("m0", "c1", "alice", "term0", 0, limits)
            .unwrap();
        assert!(idx.search("term0", None, 10).unwrap().is_empty());
        for timestamp in 2..=4 {
            assert_eq!(
                idx.search(&format!("term{timestamp}"), None, 10)
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn live_byte_budget_evicts_oldest_documents() {
        let idx = Indexer::in_memory().unwrap();
        let newest_body = "newest-payload";
        let middle_body = "middle-payload";
        let limits = IndexLimits {
            max_documents: 10,
            max_source_bytes: estimated_source_bytes("m2", "c1", middle_body)
                + estimated_source_bytes("m3", "c1", newest_body),
        };

        idx.index_message_with_limits("m1", "c1", "alice", "oldest-payload", 1, limits)
            .unwrap();
        idx.index_message_with_limits("m2", "c1", "alice", middle_body, 2, limits)
            .unwrap();
        idx.index_message_with_limits("m3", "c1", "alice", newest_body, 3, limits)
            .unwrap();

        let coverage = idx.coverage_snapshot().unwrap();
        assert_eq!(coverage.indexed_messages, 2);
        assert_eq!(coverage.source_bytes, limits.max_source_bytes);
        assert!(coverage.truncated);
        assert!(idx.search("oldest", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("middle", None, 10).unwrap().len(), 1);
        assert_eq!(idx.search("newest", None, 10).unwrap().len(), 1);
    }

    #[test]
    fn truncation_is_sticky_across_delete_and_clear_resets_it() {
        let idx = Indexer::in_memory().unwrap();
        let limits = IndexLimits {
            max_documents: 1,
            max_source_bytes: usize::MAX,
        };
        idx.index_message_with_limits("m1", "c1", "alice", "first", 1, limits)
            .unwrap();
        idx.index_message_with_limits("m2", "c1", "alice", "second", 2, limits)
            .unwrap();
        assert!(idx.coverage_snapshot().unwrap().truncated);

        idx.delete("m2").unwrap();
        let after_delete = idx.coverage_snapshot().unwrap();
        assert_eq!(after_delete.indexed_messages, 0);
        assert_eq!(after_delete.source_bytes, 0);
        assert!(after_delete.truncated);

        idx.clear().unwrap();
        assert_eq!(
            idx.coverage_snapshot().unwrap(),
            SearchCoverageSnapshot {
                indexed_messages: 0,
                source_bytes: 0,
                truncated: false,
                mutation_generation: 4,
            }
        );
    }

    #[test]
    fn failed_clear_drops_the_old_plaintext_snapshot_before_returning_error() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("secret", "c1", "alice", "sensitive plaintext", 1)
            .unwrap();
        let generation_before_clear = idx.mutation_generation();

        let result = idx.clear_with_factory(|| Err(SearchError::Cancelled));
        assert!(matches!(result, Err(SearchError::Cancelled)));
        assert_eq!(idx.mutation_generation(), generation_before_clear + 1);
        assert!(matches!(
            idx.search("sensitive", None, 10),
            Err(SearchError::Unavailable)
        ));
        assert!(matches!(
            idx.coverage_snapshot(),
            Err(SearchError::Unavailable)
        ));

        idx.clear().unwrap();
        assert!(idx.search("sensitive", None, 10).unwrap().is_empty());
    }

    #[test]
    fn clear_recovers_a_poisoned_mutex_without_retaining_old_plaintext() {
        let idx = Indexer::in_memory().unwrap();
        idx.index_message("secret", "c1", "alice", "poisoned plaintext", 1)
            .unwrap();

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = idx.state.lock().unwrap();
            panic!("deterministic mutex poison");
        }));
        assert!(panic_result.is_err());
        assert!(matches!(
            idx.search("poisoned", None, 10),
            Err(SearchError::Poisoned)
        ));

        let clear_result = idx.clear_with_factory(|| Err(SearchError::Cancelled));
        assert!(matches!(clear_result, Err(SearchError::Cancelled)));
        assert!(!idx.state.is_poisoned());
        assert!(idx.state.lock().unwrap().is_none());
        assert!(matches!(
            idx.search("poisoned", None, 10),
            Err(SearchError::Unavailable)
        ));

        idx.clear().unwrap();
        assert!(idx.search("poisoned", None, 10).unwrap().is_empty());
    }

    #[test]
    fn mutation_epoch_advances_and_rejects_stale_candidate_publication() {
        let idx = Indexer::in_memory().unwrap();
        let expected_generation = idx.mutation_generation();
        let candidate = Indexer::prepare_replacement_cancellable(
            &[SearchDocument {
                id: "candidate".into(),
                conversation_id: "c1".into(),
                sender: "alice".into(),
                body: "candidate body".into(),
                ts: 1,
            }],
            || true,
        )
        .unwrap();

        idx.index_message("live", "c1", "alice", "live body", 2)
            .unwrap();
        assert_eq!(idx.mutation_generation(), 1);
        assert!(matches!(
            idx.publish_prepared(candidate, expected_generation, false),
            Err(SearchError::MutationConflict)
        ));
        assert_eq!(idx.search("live", None, 10).unwrap().len(), 1);
        assert!(idx.search("candidate", None, 10).unwrap().is_empty());

        idx.delete("missing").unwrap();
        assert_eq!(idx.mutation_generation(), 2);
        idx.clear().unwrap();
        assert_eq!(idx.mutation_generation(), 3);
    }

    #[test]
    fn concurrent_live_mutation_cannot_be_overwritten_by_a_prepared_rebuild() {
        use std::sync::{Arc, Barrier};

        let idx = Arc::new(Indexer::in_memory().unwrap());
        let expected_generation = idx.mutation_generation();
        let candidate = Indexer::prepare_replacement_cancellable(
            &[SearchDocument {
                id: "candidate".into(),
                conversation_id: "c1".into(),
                sender: "alice".into(),
                body: "stale candidate body".into(),
                ts: 1,
            }],
            || true,
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mutation_index = Arc::clone(&idx);
        let mutation_barrier = Arc::clone(&barrier);
        let mutation = std::thread::spawn(move || {
            mutation_barrier.wait();
            mutation_index
                .index_message("live", "c1", "bob", "concurrent live body", 2)
                .unwrap();
        });

        barrier.wait();
        mutation.join().unwrap();
        assert!(matches!(
            idx.publish_prepared(candidate, expected_generation, false),
            Err(SearchError::MutationConflict)
        ));
        assert_eq!(idx.search("concurrent", None, 10).unwrap()[0].id, "live");
        assert!(idx.search("candidate", None, 10).unwrap().is_empty());
    }

    #[test]
    fn candidate_publication_enforces_limits_and_combines_truncation() {
        let idx = Indexer::in_memory().unwrap();
        let documents = (1..=3)
            .map(|timestamp| SearchDocument {
                id: format!("m{timestamp}"),
                conversation_id: "c1".into(),
                sender: "alice".into(),
                body: format!("candidate{timestamp}"),
                ts: timestamp,
            })
            .collect::<Vec<_>>();
        let candidate = Indexer::prepare_replacement_with_limits(
            &documents,
            || true,
            IndexLimits {
                max_documents: 2,
                max_source_bytes: usize::MAX,
            },
        )
        .unwrap();
        let published = idx
            .publish_prepared(candidate, idx.mutation_generation(), false)
            .unwrap();

        assert_eq!(published.indexed_messages, 2);
        assert!(published.truncated);
        assert_eq!(published.mutation_generation, 1);
        assert!(idx.search("candidate1", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("candidate2", None, 10).unwrap().len(), 1);
        assert_eq!(idx.search("candidate3", None, 10).unwrap().len(), 1);
        assert_eq!(idx.coverage_snapshot().unwrap(), published);

        let source_truncated_idx = Indexer::in_memory().unwrap();
        let candidate = Indexer::prepare_replacement_cancellable(&documents[..1], || true).unwrap();
        let source_truncated = source_truncated_idx
            .publish_prepared(candidate, source_truncated_idx.mutation_generation(), true)
            .unwrap();
        assert_eq!(source_truncated.indexed_messages, 1);
        assert!(source_truncated.truncated);
    }

    #[test]
    fn candidate_byte_budget_retains_only_the_newest_continuous_prefix() {
        let idx = Indexer::in_memory().unwrap();
        let documents = vec![
            SearchDocument {
                id: "older".into(),
                conversation_id: "c1".into(),
                sender: "alice".into(),
                body: "older payload".into(),
                ts: 1,
            },
            SearchDocument {
                id: "newer".into(),
                conversation_id: "c1".into(),
                sender: "alice".into(),
                body: "newer payload".into(),
                ts: 2,
            },
        ];
        let expected_source_bytes = estimated_source_bytes("newer", "c1", "newer payload");
        let candidate = Indexer::prepare_replacement_with_limits(
            &documents,
            || true,
            IndexLimits {
                max_documents: 10,
                max_source_bytes: expected_source_bytes,
            },
        )
        .unwrap();
        let published = idx
            .publish_prepared(candidate, idx.mutation_generation(), false)
            .unwrap();

        assert_eq!(published.indexed_messages, 1);
        assert_eq!(published.source_bytes, expected_source_bytes);
        assert!(published.truncated);
        assert!(idx.search("older", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("newer", None, 10).unwrap().len(), 1);
    }

    #[test]
    fn equal_timestamp_eviction_uses_the_message_id_tie_break() {
        let idx = Indexer::in_memory().unwrap();
        let limits = IndexLimits {
            max_documents: 1,
            max_source_bytes: usize::MAX,
        };
        idx.index_message_with_limits("b", "c1", "alice", "keep-b", 7, limits)
            .unwrap();
        idx.index_message_with_limits("a", "c1", "alice", "omit-a", 7, limits)
            .unwrap();

        assert!(idx.search("omit", None, 10).unwrap().is_empty());
        assert_eq!(idx.search("keep", None, 10).unwrap()[0].id, "b");
    }

    #[test]
    #[ignore = "manual release-profile performance evidence"]
    fn measures_large_profile_atomic_rebuild() {
        let documents = (0..100_000)
            .map(|index| SearchDocument {
                id: format!("message-{index}"),
                conversation_id: format!("conversation-{}", index % 64),
                sender: format!("sender-{}", index % 128),
                body: format!(
                    "searchable synthetic history row {index} {}",
                    "bounded payload ".repeat(12)
                ),
                ts: index,
            })
            .collect::<Vec<_>>();
        let idx = Indexer::in_memory().unwrap();
        let started = std::time::Instant::now();
        idx.replace_all_in_memory_cancellable(&documents, || true)
            .unwrap();
        let elapsed = started.elapsed();
        assert!(!idx
            .search("synthetic history", None, 10)
            .unwrap()
            .is_empty());
        eprintln!(
            "atomic RAM search rebuild: {} documents in {:.3}s",
            documents.len(),
            elapsed.as_secs_f64()
        );
    }
}
