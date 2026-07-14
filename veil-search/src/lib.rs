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

use std::path::Path;
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

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("tantivy: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
    #[error("query: {0}")]
    Query(#[from] tantivy::query::QueryParserError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("open directory: {0}")]
    OpenDir(#[from] tantivy::directory::error::OpenDirectoryError),
    #[error("poisoned writer mutex")]
    Poisoned,
    #[error("search rebuild cancelled")]
    Cancelled,
    #[error("atomic replacement is only available for an in-memory index")]
    PersistentReplaceUnsupported,
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
struct Fields {
    id: Field,
    conversation: Field,
    sender: Field,
    body: Field,
    ts: Field,
}

/// Synchronous, thread-safe index handle. Cheap to clone via `Arc`.
pub struct Indexer {
    state: Mutex<IndexState>,
    in_memory: bool,
}

struct IndexState {
    index: Index,
    writer: IndexWriter,
    fields: Fields,
}

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
            state: Mutex::new(state),
            in_memory: true,
        })
    }

    /// Open or create an index at `path`. Directory is created if missing.
    ///
    /// This constructor remains available for non-sensitive consumers. Veil
    /// Desktop intentionally uses [`Indexer::in_memory`] instead.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let (schema, fields) = build_schema();
        let index = Index::open_or_create(tantivy::directory::MmapDirectory::open(path)?, schema)?;
        let writer = index.writer(WRITER_HEAP)?;
        Ok(Self {
            state: Mutex::new(IndexState {
                index,
                writer,
                fields,
            }),
            in_memory: false,
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
        let mut state = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let fields = state.fields;
        // Delete any prior doc with this id so re-indexing replaces in place.
        state
            .writer
            .delete_term(Term::from_field_text(fields.id, id));
        state.writer.add_document(doc!(
            fields.id => id,
            fields.conversation => conversation_id,
            fields.sender => sender,
            fields.body => body,
            fields.ts => ts,
        ))?;
        state.writer.commit()?;
        Ok(())
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
        if !self.in_memory {
            return Err(SearchError::PersistentReplaceUnsupported);
        }
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }

        let mut candidate = new_memory_state()?;
        let fields = candidate.fields;
        for (index, document) in documents.iter().enumerate() {
            if index.is_multiple_of(64) && !should_continue() {
                return Err(SearchError::Cancelled);
            }
            candidate.writer.add_document(doc!(
                fields.id => document.id.as_str(),
                fields.conversation => document.conversation_id.as_str(),
                fields.sender => document.sender.as_str(),
                fields.body => document.body.as_str(),
                fields.ts => document.ts,
            ))?;
        }
        candidate.writer.commit()?;
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }

        let mut current = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        if !should_continue() {
            return Err(SearchError::Cancelled);
        }
        *current = candidate;
        Ok(())
    }

    /// Remove a message from the index.
    pub fn delete(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        let id_field = state.fields.id;
        state
            .writer
            .delete_term(Term::from_field_text(id_field, id));
        state.writer.commit()?;
        Ok(())
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
        let state = self.state.lock().map_err(|_| SearchError::Poisoned)?;
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
        if self.in_memory {
            let replacement = new_memory_state()?;
            *self.state.lock().map_err(|_| SearchError::Poisoned)? = replacement;
            return Ok(());
        }
        let mut state = self.state.lock().map_err(|_| SearchError::Poisoned)?;
        state.writer.delete_all_documents()?;
        state.writer.commit()?;
        Ok(())
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
    })
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
