//! Local-only full-text search index for decrypted Veil messages.
//!
//! Backed by [Tantivy]. The index lives entirely on-device under
//! `<app_data>/search/v1/` and is never transmitted to the server.
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

struct Fields {
    id: Field,
    conversation: Field,
    sender: Field,
    body: Field,
    ts: Field,
}

/// Synchronous, thread-safe index handle. Cheap to clone via `Arc`.
pub struct Indexer {
    index: Index,
    writer: Mutex<IndexWriter>,
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
    /// Open or create an index at `path`. Directory is created if missing.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let (schema, fields) = build_schema();
        let index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(path)?,
            schema,
        )?;
        let writer = index.writer(WRITER_HEAP)?;
        Ok(Self {
            index,
            writer: Mutex::new(writer),
            fields,
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
        let mut writer = self.writer.lock().map_err(|_| SearchError::Poisoned)?;
        // Delete any prior doc with this id so re-indexing replaces in place.
        writer.delete_term(Term::from_field_text(self.fields.id, id));
        writer.add_document(doc!(
            self.fields.id => id,
            self.fields.conversation => conversation_id,
            self.fields.sender => sender,
            self.fields.body => body,
            self.fields.ts => ts,
        ))?;
        writer.commit()?;
        Ok(())
    }

    /// Remove a message from the index.
    pub fn delete(&self, id: &str) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| SearchError::Poisoned)?;
        writer.delete_term(Term::from_field_text(self.fields.id, id));
        writer.commit()?;
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
        let terms = tokenise(&self.index, self.fields.body, query);
        if terms.is_empty() {
            return Ok(Vec::new());
        }

        let reader = self
            .index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;
        let searcher = reader.searcher();

        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::with_capacity(terms.len() + 1);
        for t in terms {
            let term = Term::from_field_text(self.fields.body, &t);
            // (term, distance, transposition_cost_one) — distance 0 = pure prefix.
            let q: Box<dyn Query> = Box::new(FuzzyTermQuery::new_prefix(term, 0, true));
            clauses.push((Occur::Must, q));
        }
        if let Some(conv) = conversation_id {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(self.fields.conversation, conv),
                    IndexRecordOption::Basic,
                )),
            ));
        }
        let final_query = BooleanQuery::new(clauses);

        let top = searcher.search(&final_query, &TopDocs::with_limit(limit))?;
        let mut hits = Vec::with_capacity(top.len());
        for (score, addr) in top {
            let doc: tantivy::TantivyDocument = searcher.doc(addr)?;
            hits.push(SearchHit {
                id: read_str(&doc, self.fields.id),
                conversation_id: read_str(&doc, self.fields.conversation),
                sender: read_str(&doc, self.fields.sender),
                body: read_str(&doc, self.fields.body),
                ts: read_i64(&doc, self.fields.ts),
                score,
            });
        }
        Ok(hits)
    }

    /// Drop every document. Used by "Rebuild index" / "Clear cache" actions.
    pub fn clear(&self) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| SearchError::Poisoned)?;
        writer.delete_all_documents()?;
        writer.commit()?;
        Ok(())
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
    doc.get_first(f).and_then(|v| v.as_i64()).unwrap_or_default()
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
        let dir = tempfile::tempdir().unwrap();
        let idx = Indexer::open(dir.path()).unwrap();
        idx.index_message("m1", "c1", "alice", "hello world", 1).unwrap();
        idx.index_message("m2", "c1", "bob", "another message", 2).unwrap();
        idx.index_message("m3", "c2", "alice", "world peace", 3).unwrap();

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
        let dir = tempfile::tempdir().unwrap();
        let idx = Indexer::open(dir.path()).unwrap();
        idx.index_message("m1", "c1", "alice", "слякоть на улице", 1).unwrap();
        idx.index_message("m2", "c1", "bob", "привет мир", 2).unwrap();
        idx.index_message("m3", "c1", "alice", "Hello World wonderful", 3).unwrap();

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
}
