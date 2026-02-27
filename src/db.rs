#![allow(dead_code)]

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Get the database path for the current project
pub fn get_db_path(project_root: &Path) -> Result<PathBuf> {
    // Check env: new name first, fallback to old
    if let Ok(path) =
        std::env::var("AST_INDEX_DB_PATH").or_else(|_| std::env::var("KOTLIN_INDEX_DB_PATH"))
    {
        return Ok(PathBuf::from(path));
    }

    let cache_dir = dirs::cache_dir()
        .context("Could not find cache directory")?
        .join("ast-index");

    // Create hash from project root for unique DB per project
    let project_hash = simple_hash(project_root.to_string_lossy().as_ref());
    let db_dir = cache_dir.join(&project_hash);

    // Auto-migrate: if new hash dir doesn't have a DB, look for old one
    if !db_dir.join("index.db").exists() {
        if let Ok(entries) = std::fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                let old_dir = entry.path();
                if old_dir.is_dir()
                    && old_dir.file_name().map(|n| n.to_string_lossy().to_string())
                        != Some(project_hash.clone())
                {
                    let old_db = old_dir.join("index.db");
                    if old_db.exists() {
                        // Check if this DB belongs to our project by reading metadata
                        if let Ok(conn) = rusqlite::Connection::open(&old_db) {
                            let root_str: Result<String, _> = conn.query_row(
                                "SELECT value FROM metadata WHERE key = 'project_root'",
                                [],
                                |row| row.get(0),
                            );
                            if let Ok(root_val) = root_str {
                                if root_val == project_root.to_string_lossy().as_ref() {
                                    // Found old DB for this project — migrate
                                    let _ = std::fs::create_dir_all(&db_dir);
                                    for suffix in ["index.db", "index.db-wal", "index.db-shm"] {
                                        let src = old_dir.join(suffix);
                                        if src.exists() {
                                            let _ = std::fs::rename(&src, db_dir.join(suffix));
                                        }
                                    }
                                    let _ = std::fs::remove_dir(&old_dir);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    std::fs::create_dir_all(&db_dir)?;
    Ok(db_dir.join("index.db"))
}

/// Deterministic hash (djb2 algorithm) — stable across Rust versions unlike DefaultHasher
fn simple_hash(s: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{:x}", hash)
}

/// Remove old kotlin-index cache dir entirely
pub fn cleanup_legacy_cache() {
    if let Some(cache_dir) = dirs::cache_dir() {
        let old_dir = cache_dir.join("kotlin-index");
        if old_dir.exists() {
            let _ = std::fs::remove_dir_all(&old_dir);
        }
    }
}

/// Migrate project DB from old kotlin-index dir to new ast-index dir
pub fn migrate_legacy_project(project_root: &Path) {
    let cache_dir = match dirs::cache_dir() {
        Some(d) => d,
        None => return,
    };
    let project_hash = simple_hash(project_root.to_string_lossy().as_ref());
    let old_db_dir = cache_dir.join("kotlin-index").join(&project_hash);
    let new_db_dir = cache_dir.join("ast-index").join(&project_hash);

    if !old_db_dir.exists() || new_db_dir.join("index.db").exists() {
        return;
    }

    let _ = std::fs::create_dir_all(&new_db_dir);
    for suffix in ["index.db", "index.db-wal", "index.db-shm"] {
        let src = old_db_dir.join(suffix);
        if src.exists() {
            let _ = std::fs::rename(&src, new_db_dir.join(suffix));
        }
    }
    // Remove old project dir if empty
    let _ = std::fs::remove_dir(&old_db_dir);
}

/// Acquire an exclusive lock file for rebuild operations.
/// Returns the lock file handle — lock is held until the handle is dropped.
/// If another process holds the lock, returns an error immediately.
pub fn acquire_rebuild_lock(project_root: &Path) -> Result<File> {
    use fs2::FileExt;

    let db_path = get_db_path(project_root)?;
    let lock_path = db_path.with_extension("lock");

    // Ensure parent dir exists
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let lock_file = File::create(&lock_path)?;
    lock_file.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("Another rebuild is already running for this project. Wait for it to finish or remove {}", lock_path.display()))?;
    Ok(lock_file)
}

/// Delete DB file and WAL/SHM files for the project
pub fn delete_db(project_root: &Path) -> Result<()> {
    let db_path = get_db_path(project_root)?;
    for suffix in ["", "-wal", "-shm"] {
        let p = db_path.with_extension(format!("db{}", suffix));
        if p.exists() {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(())
}

/// Initialize the database schema
pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        -- Files table
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL UNIQUE,
            mtime INTEGER NOT NULL,
            size INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);

        -- Symbols table (classes, interfaces, functions, etc.)
        CREATE TABLE IF NOT EXISTS symbols (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            line INTEGER NOT NULL,
            parent_id INTEGER,
            signature TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
        CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
        CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);

        -- FTS5 virtual table for full-text search
        CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
            name,
            signature,
            content=symbols,
            content_rowid=id
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS symbols_ai AFTER INSERT ON symbols BEGIN
            INSERT INTO symbols_fts(rowid, name, signature) VALUES (new.id, new.name, new.signature);
        END;
        CREATE TRIGGER IF NOT EXISTS symbols_ad AFTER DELETE ON symbols BEGIN
            INSERT INTO symbols_fts(symbols_fts, rowid, name, signature) VALUES('delete', old.id, old.name, old.signature);
        END;
        CREATE TRIGGER IF NOT EXISTS symbols_au AFTER UPDATE ON symbols BEGIN
            INSERT INTO symbols_fts(symbols_fts, rowid, name, signature) VALUES('delete', old.id, old.name, old.signature);
            INSERT INTO symbols_fts(rowid, name, signature) VALUES (new.id, new.name, new.signature);
        END;

        -- Modules table
        CREATE TABLE IF NOT EXISTS modules (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            path TEXT NOT NULL,
            kind TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_modules_name ON modules(name);

        -- Module dependencies
        CREATE TABLE IF NOT EXISTS module_deps (
            id INTEGER PRIMARY KEY,
            module_id INTEGER NOT NULL,
            dep_module_id INTEGER NOT NULL,
            dep_kind TEXT,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE,
            FOREIGN KEY (dep_module_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_module_deps_module ON module_deps(module_id);
        CREATE INDEX IF NOT EXISTS idx_module_deps_dep ON module_deps(dep_module_id);

        -- Inheritance/implementation relationships
        CREATE TABLE IF NOT EXISTS inheritance (
            id INTEGER PRIMARY KEY,
            child_id INTEGER NOT NULL,
            parent_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            FOREIGN KEY (child_id) REFERENCES symbols(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_inheritance_child ON inheritance(child_id);
        CREATE INDEX IF NOT EXISTS idx_inheritance_parent ON inheritance(parent_name);

        -- References table (symbol usages)
        CREATE TABLE IF NOT EXISTS refs (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            line INTEGER NOT NULL,
            context TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_refs_name ON refs(name);
        CREATE INDEX IF NOT EXISTS idx_refs_file ON refs(file_id);

        -- XML usages (classes used in XML layouts)
        CREATE TABLE IF NOT EXISTS xml_usages (
            id INTEGER PRIMARY KEY,
            module_id INTEGER,
            file_path TEXT NOT NULL,
            line INTEGER NOT NULL,
            class_name TEXT NOT NULL,
            usage_type TEXT,
            element_id TEXT,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_xml_usages_class ON xml_usages(class_name);
        CREATE INDEX IF NOT EXISTS idx_xml_usages_module ON xml_usages(module_id);

        -- Resources definitions
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY,
            module_id INTEGER,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line INTEGER,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_resources_name ON resources(name);
        CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);
        CREATE INDEX IF NOT EXISTS idx_resources_module ON resources(module_id);

        -- Resource usages
        CREATE TABLE IF NOT EXISTS resource_usages (
            id INTEGER PRIMARY KEY,
            resource_id INTEGER,
            usage_file TEXT NOT NULL,
            usage_line INTEGER NOT NULL,
            usage_type TEXT,
            FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_resource_usages_resource ON resource_usages(resource_id);

        -- Transitive dependencies cache
        CREATE TABLE IF NOT EXISTS transitive_deps (
            id INTEGER PRIMARY KEY,
            module_id INTEGER NOT NULL,
            dependency_id INTEGER NOT NULL,
            depth INTEGER NOT NULL,
            path TEXT,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE,
            FOREIGN KEY (dependency_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_transitive_deps_module ON transitive_deps(module_id);
        CREATE INDEX IF NOT EXISTS idx_transitive_deps_dep ON transitive_deps(dependency_id);

        -- iOS storyboard/xib usages
        CREATE TABLE IF NOT EXISTS storyboard_usages (
            id INTEGER PRIMARY KEY,
            module_id INTEGER,
            file_path TEXT NOT NULL,
            line INTEGER NOT NULL,
            class_name TEXT NOT NULL,
            usage_type TEXT,
            storyboard_id TEXT,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_storyboard_usages_class ON storyboard_usages(class_name);
        CREATE INDEX IF NOT EXISTS idx_storyboard_usages_module ON storyboard_usages(module_id);

        -- iOS assets (from .xcassets)
        CREATE TABLE IF NOT EXISTS ios_assets (
            id INTEGER PRIMARY KEY,
            module_id INTEGER,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ios_assets_name ON ios_assets(name);
        CREATE INDEX IF NOT EXISTS idx_ios_assets_type ON ios_assets(type);

        -- iOS asset usages
        CREATE TABLE IF NOT EXISTS ios_asset_usages (
            id INTEGER PRIMARY KEY,
            asset_id INTEGER,
            usage_file TEXT NOT NULL,
            usage_line INTEGER NOT NULL,
            usage_type TEXT,
            FOREIGN KEY (asset_id) REFERENCES ios_assets(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ios_asset_usages_asset ON ios_asset_usages(asset_id);

        -- Metadata for storing index settings
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Python endpoints (Django urlpatterns, DRF router)
        CREATE TABLE IF NOT EXISTS py_endpoints (
            id INTEGER PRIMARY KEY,
            method TEXT,
            path_pattern TEXT NOT NULL,
            file_id INTEGER NOT NULL,
            line INTEGER NOT NULL,
            handler_qname TEXT,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_py_endpoints_file ON py_endpoints(file_id);
        CREATE INDEX IF NOT EXISTS idx_py_endpoints_path ON py_endpoints(path_pattern);

        -- Python endpoint -> handler symbol links
        CREATE TABLE IF NOT EXISTS py_endpoint_handlers (
            id INTEGER PRIMARY KEY,
            endpoint_id INTEGER NOT NULL,
            symbol_id INTEGER NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'high',
            reason TEXT,
            FOREIGN KEY(endpoint_id) REFERENCES py_endpoints(id) ON DELETE CASCADE,
            FOREIGN KEY(symbol_id) REFERENCES symbols(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_py_endpoint_handlers_endpoint ON py_endpoint_handlers(endpoint_id);
        CREATE INDEX IF NOT EXISTS idx_py_endpoint_handlers_symbol ON py_endpoint_handlers(symbol_id);

        -- Python serializer -> model links
        CREATE TABLE IF NOT EXISTS py_serializer_models (
            id INTEGER PRIMARY KEY,
            serializer_symbol_id INTEGER NOT NULL,
            model_symbol_id INTEGER NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'high',
            reason TEXT,
            FOREIGN KEY(serializer_symbol_id) REFERENCES symbols(id) ON DELETE CASCADE,
            FOREIGN KEY(model_symbol_id) REFERENCES symbols(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_py_serializer_models_serializer ON py_serializer_models(serializer_symbol_id);
        CREATE INDEX IF NOT EXISTS idx_py_serializer_models_model ON py_serializer_models(model_symbol_id);

        -- Python symbol -> settings/env key links
        CREATE TABLE IF NOT EXISTS py_symbol_settings (
            id INTEGER PRIMARY KEY,
            symbol_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            key_kind TEXT NOT NULL DEFAULT 'settings',
            confidence TEXT NOT NULL DEFAULT 'medium',
            reason TEXT,
            FOREIGN KEY(symbol_id) REFERENCES symbols(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_py_symbol_settings_symbol ON py_symbol_settings(symbol_id);
        CREATE INDEX IF NOT EXISTS idx_py_symbol_settings_key ON py_symbol_settings(key);

        -- Python handler -> serializer direct links (serializer_class = X)
        CREATE TABLE IF NOT EXISTS py_handler_serializers (
            id INTEGER PRIMARY KEY,
            handler_symbol_id INTEGER NOT NULL,
            serializer_symbol_id INTEGER NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'high',
            reason TEXT,
            FOREIGN KEY(handler_symbol_id) REFERENCES symbols(id) ON DELETE CASCADE,
            FOREIGN KEY(serializer_symbol_id) REFERENCES symbols(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_py_handler_serializers_handler ON py_handler_serializers(handler_symbol_id);
        CREATE INDEX IF NOT EXISTS idx_py_handler_serializers_serializer ON py_handler_serializers(serializer_symbol_id);
        "#,
    )?;
    Ok(())
}

/// Open or create database connection
pub fn open_db(project_root: &Path) -> Result<Connection> {
    let db_path = get_db_path(project_root)?;
    let conn = Connection::open(&db_path)?;

    // Enable foreign keys and WAL mode for better performance
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // journal_mode returns result, use query_row
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "cache_size", "-8000")?; // 8 MB cache to limit memory
    let _: i64 = conn.query_row("PRAGMA busy_timeout = 5000", [], |row| row.get(0))?; // Wait up to 5s if DB is locked

    // Store project root for hash migration
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .ok();
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('project_root', ?1)",
        params![project_root.to_string_lossy().as_ref()],
    )
    .ok();

    Ok(conn)
}

/// Check if database exists and is initialized
pub fn db_exists(project_root: &Path) -> bool {
    if let Ok(db_path) = get_db_path(project_root) {
        if !db_path.exists() {
            return false;
        }
        // Also check if tables exist
        if let Ok(conn) = Connection::open(&db_path) {
            conn.query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='files'",
                [],
                |_| Ok(()),
            )
            .is_ok()
        } else {
            false
        }
    } else {
        false
    }
}

/// Symbol kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Class,
    Interface,
    Object,
    Enum,
    Function,
    Property,
    TypeAlias,
    // Perl-specific
    Package,
    Constant,
    // For imports/includes
    Import,
    // For annotations/decorators
    Annotation,
}

impl SymbolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymbolKind::Class => "class",
            SymbolKind::Interface => "interface",
            SymbolKind::Object => "object",
            SymbolKind::Enum => "enum",
            SymbolKind::Function => "function",
            SymbolKind::Property => "property",
            SymbolKind::TypeAlias => "typealias",
            SymbolKind::Package => "package",
            SymbolKind::Constant => "constant",
            SymbolKind::Import => "import",
            SymbolKind::Annotation => "annotation",
        }
    }
}

/// Insert or update a file record
pub fn upsert_file(conn: &Connection, path: &str, mtime: i64, size: i64) -> Result<i64> {
    conn.execute(
        "INSERT OR REPLACE INTO files (path, mtime, size) VALUES (?1, ?2, ?3)",
        params![path, mtime, size],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert a symbol
pub fn insert_symbol(
    conn: &Connection,
    file_id: i64,
    name: &str,
    kind: SymbolKind,
    line: usize,
    signature: Option<&str>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO symbols (file_id, name, kind, line, signature) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![file_id, name, kind.as_str(), line as i64, signature],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert inheritance relationship
pub fn insert_inheritance(
    conn: &Connection,
    child_id: i64,
    parent_name: &str,
    kind: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO inheritance (child_id, parent_name, kind) VALUES (?1, ?2, ?3)",
        params![child_id, parent_name, kind],
    )?;
    Ok(())
}

/// Escape FTS5 special characters
fn escape_fts5_query(query: &str) -> String {
    // Handle empty query
    if query.trim().is_empty() {
        return String::new();
    }
    // Check for prefix operator: * must stay OUTSIDE quotes for FTS5
    let (term, suffix) = if query.ends_with('*') {
        (&query[..query.len() - 1], "*")
    } else {
        (query, "")
    };
    // Wrap in double quotes to treat as literal phrase
    // Escape any existing double quotes
    let escaped = term.replace('"', "\"\"");
    format!("\"{}\"{}",  escaped, suffix)
}

/// Search symbols by name (FTS5)
pub fn search_symbols(conn: &Connection, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
    // Handle empty query
    if query.trim().is_empty() {
        return Ok(vec![]);
    }

    let escaped_query = escape_fts5_query(query);

    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols_fts fts
        JOIN symbols s ON fts.rowid = s.id
        JOIN files f ON s.file_id = f.id
        WHERE symbols_fts MATCH ?1
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![escaped_query, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Search result
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub kind: String,
    pub line: i64,
    pub signature: Option<String>,
    pub path: String,
}

/// Find files by name pattern
pub fn find_files(conn: &Connection, pattern: &str, limit: usize) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT path FROM files WHERE path LIKE ?1 LIMIT ?2")?;

    let pattern = format!("%{}%", pattern);
    let results = stmt
        .query_map(params![pattern, limit as i64], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find symbols by name (exact match first, then prefix/contains if no results)
pub fn find_symbols_by_name(
    conn: &Connection,
    name: &str,
    kind: Option<&str>,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    // Try exact match first
    let exact_query = if kind.is_some() {
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?1 AND s.kind = ?2
        LIMIT ?3
        "#
    } else {
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?1
        LIMIT ?2
        "#
    };

    let mut stmt = conn.prepare(exact_query)?;

    let results: Vec<SearchResult> = if let Some(k) = kind {
        stmt.query_map(params![name, k, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(params![name, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    };

    // If no exact match, try prefix match
    if results.is_empty() {
        let pattern = format!("{}%", name);
        let prefix_query = if kind.is_some() {
            r#"
            SELECT s.name, s.kind, s.line, s.signature, f.path
            FROM symbols s
            JOIN files f ON s.file_id = f.id
            WHERE s.name LIKE ?1 AND s.kind = ?2
            ORDER BY length(s.name)
            LIMIT ?3
            "#
        } else {
            r#"
            SELECT s.name, s.kind, s.line, s.signature, f.path
            FROM symbols s
            JOIN files f ON s.file_id = f.id
            WHERE s.name LIKE ?1
            ORDER BY length(s.name)
            LIMIT ?2
            "#
        };

        let mut stmt = conn.prepare(prefix_query)?;
        let results: Vec<SearchResult> = if let Some(k) = kind {
            stmt.query_map(params![pattern, k, limit as i64], |row| {
                Ok(SearchResult {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    line: row.get(2)?,
                    signature: row.get(3)?,
                    path: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![pattern, limit as i64], |row| {
                Ok(SearchResult {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    line: row.get(2)?,
                    signature: row.get(3)?,
                    path: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        return Ok(results);
    }

    Ok(results)
}

/// Find class-like symbols (class, interface, object, enum) by name - single query
pub fn find_class_like(conn: &Connection, name: &str, limit: usize) -> Result<Vec<SearchResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?1 AND s.kind IN ('class', 'interface', 'object', 'enum', 'protocol', 'struct', 'actor', 'package')
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![name, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find implementations (subclasses/implementors)
pub fn find_implementations(
    conn: &Connection,
    parent_name: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    // Match exact name, qualified suffix (%.Name), or contains (%Name%)
    let suffix_pattern = format!("%.{}", parent_name);
    let contains_pattern = format!("%{}%", parent_name);
    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM inheritance i
        JOIN symbols s ON i.child_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE i.parent_name = ?1 OR i.parent_name LIKE ?2 OR i.parent_name LIKE ?3
        ORDER BY
            CASE
                WHEN i.parent_name = ?1 THEN 0
                WHEN i.parent_name LIKE ?2 THEN 1
                ELSE 2
            END, s.name
        LIMIT ?4
        "#,
    )?;

    let results = stmt
        .query_map(params![parent_name, suffix_pattern, contains_pattern, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Get database statistics
pub fn get_stats(conn: &Connection) -> Result<DbStats> {
    let file_count: i64 = conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
    let symbol_count: i64 = conn.query_row("SELECT COUNT(*) FROM symbols", [], |row| row.get(0))?;
    let module_count: i64 = conn.query_row("SELECT COUNT(*) FROM modules", [], |row| row.get(0))?;
    let refs_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM refs", [], |row| row.get(0))
        .unwrap_or(0);
    let xml_usages_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM xml_usages", [], |row| row.get(0))
        .unwrap_or(0);
    let resources_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM resources", [], |row| row.get(0))
        .unwrap_or(0);
    let storyboard_usages_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM storyboard_usages", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    let ios_assets_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ios_assets", [], |row| row.get(0))
        .unwrap_or(0);

    Ok(DbStats {
        file_count,
        symbol_count,
        module_count,
        refs_count,
        xml_usages_count,
        resources_count,
        storyboard_usages_count,
        ios_assets_count,
    })
}

#[derive(Debug, Serialize)]
pub struct DbStats {
    pub file_count: i64,
    pub symbol_count: i64,
    pub module_count: i64,
    pub refs_count: i64,
    pub xml_usages_count: i64,
    pub resources_count: i64,
    pub storyboard_usages_count: i64,
    pub ios_assets_count: i64,
}

/// Clear all data from the database
pub fn clear_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        DELETE FROM py_symbol_settings;
        DELETE FROM py_handler_serializers;
        DELETE FROM py_serializer_models;
        DELETE FROM py_endpoint_handlers;
        DELETE FROM py_endpoints;
        DELETE FROM ios_asset_usages;
        DELETE FROM ios_assets;
        DELETE FROM storyboard_usages;
        DELETE FROM resource_usages;
        DELETE FROM resources;
        DELETE FROM xml_usages;
        DELETE FROM transitive_deps;
        DELETE FROM refs;
        DELETE FROM inheritance;
        DELETE FROM module_deps;
        DELETE FROM modules;
        DELETE FROM symbols;
        DELETE FROM files;
        "#,
    )?;
    Ok(())
}

/// Clear Python-specific tables by file_id (for incremental reindex)
pub fn clear_py_facts_for_files(conn: &Connection, file_ids: &[i64]) -> Result<()> {
    if file_ids.is_empty() {
        return Ok(());
    }
    let placeholders: Vec<String> = file_ids.iter().map(|_| "?".to_string()).collect();
    let ph = placeholders.join(",");

    // py_endpoints are linked directly to file_id
    let sql = format!("DELETE FROM py_endpoints WHERE file_id IN ({})", ph);
    let params: Vec<Box<dyn rusqlite::types::ToSql>> = file_ids
        .iter()
        .map(|id| Box::new(*id) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    conn.execute(&sql, param_refs.as_slice())?;

    // py_symbol_settings are linked via symbol_id -> symbols.file_id
    let sql = format!(
        "DELETE FROM py_symbol_settings WHERE symbol_id IN (SELECT id FROM symbols WHERE file_id IN ({}))",
        ph
    );
    conn.execute(&sql, param_refs.as_slice())?;

    // py_serializer_models are linked via serializer_symbol_id -> symbols.file_id
    let sql = format!(
        "DELETE FROM py_serializer_models WHERE serializer_symbol_id IN (SELECT id FROM symbols WHERE file_id IN ({}))",
        ph
    );
    conn.execute(&sql, param_refs.as_slice())?;

    // py_handler_serializers linked through handler_symbol_id -> symbols.file_id
    let sql = format!(
        "DELETE FROM py_handler_serializers WHERE handler_symbol_id IN (SELECT id FROM symbols WHERE file_id IN ({}))",
        ph
    );
    conn.execute(&sql, param_refs.as_slice())?;

    Ok(())
}

/// Reference result
#[derive(Debug, Serialize)]
pub struct RefResult {
    pub name: String,
    pub line: i64,
    pub context: Option<String>,
    pub path: String,
}

/// Find references (usages) of a symbol
pub fn find_references(conn: &Connection, name: &str, limit: usize) -> Result<Vec<RefResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT r.name, r.line, r.context, f.path
        FROM refs r
        JOIN files f ON r.file_id = f.id
        WHERE r.name = ?1
        ORDER BY f.path, r.line
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![name, limit as i64], |row| {
            Ok(RefResult {
                name: row.get(0)?,
                line: row.get(1)?,
                context: row.get(2)?,
                path: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Search references by name (prefix match, grouped by unique name)
pub fn search_refs(conn: &Connection, query: &str, limit: usize) -> Result<Vec<(String, i64)>> {
    let pattern = format!("{}%", query);
    let mut stmt = conn.prepare(
        r#"
        SELECT r.name, COUNT(*) as usage_count
        FROM refs r
        WHERE r.name LIKE ?1
        GROUP BY r.name
        ORDER BY
            CASE WHEN r.name = ?2 THEN 0
                 WHEN r.name LIKE ?1 THEN 1
                 ELSE 2
            END,
            usage_count DESC
        LIMIT ?3
        "#,
    )?;
    let results = stmt
        .query_map(params![pattern, query, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(results)
}

/// Count references in the database
pub fn count_refs(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM refs", [], |row| row.get(0))?)
}

/// Find import statements for a symbol name
pub fn find_imports(conn: &Connection, name: &str, limit: usize) -> Result<Vec<SearchResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.kind = 'import' AND s.name = ?1
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![name, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find all cross-references for a symbol: definitions, imports, and usages
pub fn find_cross_references(
    conn: &Connection,
    name: &str,
    limit: usize,
) -> Result<(Vec<SearchResult>, Vec<SearchResult>, Vec<RefResult>)> {
    // 1. Definitions (non-import symbols)
    let definitions = find_symbols_by_name(conn, name, None, limit)?
        .into_iter()
        .filter(|s| s.kind != "import")
        .collect();

    // 2. Imports
    let imports = find_imports(conn, name, limit)?;

    // 3. Usages (refs table)
    let usages = find_references(conn, name, limit)?;

    Ok((definitions, imports, usages))
}

/// Fuzzy search for symbols: exact → prefix → contains cascade
pub fn search_symbols_fuzzy(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    // Single query: contains match with ranking by relevance
    // exact match (name = query) first, then prefix, then contains — sorted by length
    let contains_pattern = format!("%{}%", query);
    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name LIKE ?1
        ORDER BY
            CASE WHEN s.name = ?2 THEN 0
                 WHEN s.name LIKE ?3 THEN 1
                 ELSE 2 END,
            length(s.name)
        LIMIT ?4
        "#,
    )?;
    let prefix_pattern = format!("{}%", query);
    let results: Vec<SearchResult> = stmt
        .query_map(
            params![contains_pattern, query, prefix_pattern, limit as i64],
            |row| {
                Ok(SearchResult {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    line: row.get(2)?,
                    signature: row.get(3)?,
                    path: row.get(4)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Scope filter for narrowing search results by file path or module
pub struct SearchScope<'a> {
    pub in_file: Option<&'a str>,
    pub module: Option<&'a str>,
    /// Directory prefix filter: only return results under this path (relative to project root)
    pub dir_prefix: Option<&'a str>,
}

impl<'a> SearchScope<'a> {
    pub fn none() -> Self {
        SearchScope { in_file: None, module: None, dir_prefix: None }
    }

    pub fn is_empty(&self) -> bool {
        self.in_file.is_none() && self.module.is_none() && self.dir_prefix.is_none()
    }

    /// Build WHERE clause fragment and collect params
    fn path_condition(&self) -> (String, Vec<String>) {
        let mut conditions = Vec::new();
        let mut params = Vec::new();
        if let Some(prefix) = self.dir_prefix {
            conditions.push("f.path LIKE ?".to_string());
            params.push(format!("{}%", prefix));
        }
        if let Some(file) = self.in_file {
            conditions.push("f.path LIKE ?".to_string());
            params.push(format!("%{}", file));
        }
        if let Some(module) = self.module {
            conditions.push("f.path LIKE ?".to_string());
            params.push(format!("{}%", module));
        }
        if conditions.is_empty() {
            (String::new(), params)
        } else {
            (format!(" AND {}", conditions.join(" AND ")), params)
        }
    }
}

/// Search symbols with scope filtering (file/module)
pub fn search_symbols_scoped(
    conn: &Connection,
    query: &str,
    limit: usize,
    scope: &SearchScope,
) -> Result<Vec<SearchResult>> {
    if scope.is_empty() {
        return search_symbols(conn, query, limit);
    }

    if query.trim().is_empty() {
        return Ok(vec![]);
    }

    let escaped_query = escape_fts5_query(query);
    let (scope_clause, scope_params) = scope.path_condition();

    let sql = format!(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols_fts fts
        JOIN symbols s ON fts.rowid = s.id
        JOIN files f ON s.file_id = f.id
        WHERE symbols_fts MATCH ?1{}
        LIMIT ?{}
        "#,
        scope_clause,
        2 + scope_params.len()
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    all_params.push(Box::new(escaped_query));
    for p in &scope_params {
        all_params.push(Box::new(p.clone()));
    }
    all_params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();
    let results = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find symbols by name with scope filtering
pub fn find_symbols_by_name_scoped(
    conn: &Connection,
    name: &str,
    kind: Option<&str>,
    limit: usize,
    scope: &SearchScope,
) -> Result<Vec<SearchResult>> {
    if scope.is_empty() {
        return find_symbols_by_name(conn, name, kind, limit);
    }

    let (scope_clause, scope_params) = scope.path_condition();

    let mut sql = format!(
        "SELECT s.name, s.kind, s.line, s.signature, f.path FROM symbols s JOIN files f ON s.file_id = f.id WHERE s.name = ?1{}",
        scope_clause
    );
    if kind.is_some() {
        sql.push_str(&format!(" AND s.kind = ?{}", 2 + scope_params.len()));
        sql.push_str(&format!(" LIMIT ?{}", 3 + scope_params.len()));
    } else {
        sql.push_str(&format!(" LIMIT ?{}", 2 + scope_params.len()));
    }

    let mut stmt = conn.prepare(&sql)?;
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    all_params.push(Box::new(name.to_string()));
    for p in &scope_params {
        all_params.push(Box::new(p.clone()));
    }
    if let Some(k) = kind {
        all_params.push(Box::new(k.to_string()));
    }
    all_params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();
    let results = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find class-like symbols with scope filtering
pub fn find_class_like_scoped(
    conn: &Connection,
    name: &str,
    limit: usize,
    scope: &SearchScope,
) -> Result<Vec<SearchResult>> {
    if scope.is_empty() {
        return find_class_like(conn, name, limit);
    }

    let (scope_clause, scope_params) = scope.path_condition();

    let sql = format!(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?1 AND s.kind IN ('class', 'interface', 'object', 'enum', 'protocol', 'struct', 'actor', 'package'){}
        LIMIT ?{}
        "#,
        scope_clause,
        2 + scope_params.len()
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    all_params.push(Box::new(name.to_string()));
    for p in &scope_params {
        all_params.push(Box::new(p.clone()));
    }
    all_params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();
    let results = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find references with scope filtering
pub fn find_references_scoped(
    conn: &Connection,
    name: &str,
    limit: usize,
    scope: &SearchScope,
) -> Result<Vec<RefResult>> {
    if scope.is_empty() {
        return find_references(conn, name, limit);
    }

    let (scope_clause, scope_params) = scope.path_condition();

    let sql = format!(
        r#"
        SELECT r.name, r.line, r.context, f.path
        FROM refs r
        JOIN files f ON r.file_id = f.id
        WHERE r.name = ?1{}
        ORDER BY f.path, r.line
        LIMIT ?{}
        "#,
        scope_clause,
        2 + scope_params.len()
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    all_params.push(Box::new(name.to_string()));
    for p in &scope_params {
        all_params.push(Box::new(p.clone()));
    }
    all_params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();
    let results = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(RefResult {
                name: row.get(0)?,
                line: row.get(1)?,
                context: row.get(2)?,
                path: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Get extra source roots stored in metadata
pub fn get_extra_roots(conn: &Connection) -> Result<Vec<String>> {
    let result: Result<String, _> = conn.query_row(
        "SELECT value FROM metadata WHERE key = 'extra_roots'",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(json) => {
            let roots: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
            Ok(roots)
        }
        Err(_) => Ok(vec![]),
    }
}

/// Add an extra source root
pub fn add_extra_root(conn: &Connection, path: &str) -> Result<()> {
    let mut roots = get_extra_roots(conn)?;
    if !roots.contains(&path.to_string()) {
        roots.push(path.to_string());
    }
    let json = serde_json::to_string(&roots)?;
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('extra_roots', ?1)",
        params![json],
    )?;
    Ok(())
}

/// Remove an extra source root
pub fn remove_extra_root(conn: &Connection, path: &str) -> Result<bool> {
    let mut roots = get_extra_roots(conn)?;
    let len_before = roots.len();
    roots.retain(|r| r != path);
    if roots.len() == len_before {
        return Ok(false);
    }
    let json = serde_json::to_string(&roots)?;
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('extra_roots', ?1)",
        params![json],
    )?;
    Ok(true)
}

// === Python graph query API ===

/// Result row for py.routes query
#[derive(Debug, Serialize)]
pub struct PyEndpointResult {
    pub id: i64,
    pub method: Option<String>,
    pub path_pattern: String,
    pub file_path: String,
    pub line: i64,
    pub handler_qname: Option<String>,
    pub confidence: Option<String>,
}

/// Result for py.endpoint-trace (endpoint -> handler -> serializer -> model)
#[derive(Debug, Serialize)]
pub struct PyEndpointTrace {
    pub endpoint: PyEndpointResult,
    pub handler: Option<SearchResult>,
    pub serializer: Option<SearchResult>,
    pub model: Option<SearchResult>,
    pub settings: Vec<PySettingUsage>,
}

/// Result row for py.setting-usage query
#[derive(Debug, Serialize)]
pub struct PySettingUsage {
    pub key: String,
    pub key_kind: String,
    pub symbol_name: String,
    pub file_path: String,
    pub line: i64,
    pub confidence: String,
    pub reason: Option<String>,
    /// Symbol ID for linking queries (not serialized to JSON)
    #[serde(skip)]
    pub symbol_id: i64,
}

/// Insert a Python endpoint
pub fn insert_py_endpoint(
    conn: &Connection,
    method: Option<&str>,
    path_pattern: &str,
    file_id: i64,
    line: usize,
    handler_qname: Option<&str>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO py_endpoints (method, path_pattern, file_id, line, handler_qname) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![method, path_pattern, file_id, line as i64, handler_qname],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert endpoint -> handler symbol link
pub fn insert_py_endpoint_handler(
    conn: &Connection,
    endpoint_id: i64,
    symbol_id: i64,
    confidence: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO py_endpoint_handlers (endpoint_id, symbol_id, confidence, reason) VALUES (?1, ?2, ?3, ?4)",
        params![endpoint_id, symbol_id, confidence, reason],
    )?;
    Ok(())
}

/// Insert serializer -> model link
pub fn insert_py_serializer_model(
    conn: &Connection,
    serializer_symbol_id: i64,
    model_symbol_id: i64,
    confidence: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO py_serializer_models (serializer_symbol_id, model_symbol_id, confidence, reason) VALUES (?1, ?2, ?3, ?4)",
        params![serializer_symbol_id, model_symbol_id, confidence, reason],
    )?;
    Ok(())
}

/// Insert symbol -> settings key link
pub fn insert_py_symbol_setting(
    conn: &Connection,
    symbol_id: i64,
    key: &str,
    key_kind: &str,
    confidence: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO py_symbol_settings (symbol_id, key, key_kind, confidence, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![symbol_id, key, key_kind, confidence, reason],
    )?;
    Ok(())
}

/// Insert handler -> serializer direct link
pub fn insert_py_handler_serializer(
    conn: &Connection,
    handler_symbol_id: i64,
    serializer_symbol_id: i64,
    confidence: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO py_handler_serializers (handler_symbol_id, serializer_symbol_id, confidence, reason) VALUES (?1, ?2, ?3, ?4)",
        params![handler_symbol_id, serializer_symbol_id, confidence, reason],
    )?;
    Ok(())
}

/// Get serializer linked to handler via py_handler_serializers
pub fn get_py_handler_serializer(
    conn: &Connection,
    handler_symbol_id: i64,
) -> Result<Option<(i64, SearchResult, String)>> {
    let result = conn.query_row(
        r#"
        SELECT s.id, s.name, s.kind, s.line, s.signature, f.path, hs.confidence
        FROM py_handler_serializers hs
        JOIN symbols s ON hs.serializer_symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE hs.handler_symbol_id = ?1
        ORDER BY CASE hs.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END
        LIMIT 1
        "#,
        params![handler_symbol_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                SearchResult {
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    line: row.get(3)?,
                    signature: row.get(4)?,
                    path: row.get(5)?,
                },
                row.get::<_, String>(6)?,
            ))
        },
    );

    match result {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Count Python endpoints with optional filter
pub fn count_py_endpoints(conn: &Connection, query: Option<&str>) -> Result<usize> {
    let count: i64 = if let Some(q) = query {
        let pattern = format!("%{}%", q.to_lowercase());
        conn.query_row(
            r#"
            SELECT COUNT(*) FROM py_endpoints e
            WHERE LOWER(e.path_pattern) LIKE ?1
               OR LOWER(COALESCE(e.handler_qname, '')) LIKE ?1
            "#,
            params![pattern],
            |row| row.get(0),
        )?
    } else {
        conn.query_row("SELECT COUNT(*) FROM py_endpoints", [], |row| row.get(0))?
    };
    Ok(count as usize)
}

/// Get Python endpoints with limit and optional filter (for py.routes)
pub fn get_py_endpoints(
    conn: &Connection,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<PyEndpointResult>> {
    let pattern = query.map(|q| format!("%{}%", q.to_lowercase()));

    let map_row = |row: &rusqlite::Row| -> rusqlite::Result<PyEndpointResult> {
        Ok(PyEndpointResult {
            id: row.get(0)?,
            method: row.get(1)?,
            path_pattern: row.get(2)?,
            file_path: row.get(3)?,
            line: row.get(4)?,
            handler_qname: row.get(5)?,
            confidence: row.get(6)?,
        })
    };

    let results = if let Some(ref pat) = pattern {
        let mut stmt = conn.prepare(
            r#"
            SELECT e.id, e.method, e.path_pattern, f.path, e.line, e.handler_qname,
                   h.confidence
            FROM py_endpoints e
            JOIN files f ON e.file_id = f.id
            LEFT JOIN py_endpoint_handlers h ON h.endpoint_id = e.id
            WHERE LOWER(e.path_pattern) LIKE ?1
               OR LOWER(COALESCE(e.handler_qname, '')) LIKE ?1
            ORDER BY e.path_pattern, e.method
            LIMIT ?2
            "#,
        )?;
        let rows = stmt
            .query_map(params![pat, limit as i64], map_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    } else {
        let mut stmt = conn.prepare(
            r#"
            SELECT e.id, e.method, e.path_pattern, f.path, e.line, e.handler_qname,
                   h.confidence
            FROM py_endpoints e
            JOIN files f ON e.file_id = f.id
            LEFT JOIN py_endpoint_handlers h ON h.endpoint_id = e.id
            ORDER BY e.path_pattern, e.method
            LIMIT ?1
            "#,
        )?;
        let rows = stmt
            .query_map(params![limit as i64], map_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    Ok(results)
}

/// Find endpoint by method + path pattern (for py.endpoint-trace)
pub fn find_py_endpoint(
    conn: &Connection,
    method: Option<&str>,
    path_pattern: &str,
) -> Result<Vec<PyEndpointResult>> {
    let (sql, use_method) = if method.is_some() {
        (
            r#"
            SELECT e.id, e.method, e.path_pattern, f.path, e.line, e.handler_qname,
                   h.confidence
            FROM py_endpoints e
            JOIN files f ON e.file_id = f.id
            LEFT JOIN py_endpoint_handlers h ON h.endpoint_id = e.id
            WHERE e.method = ?1 AND e.path_pattern LIKE ?2
            ORDER BY e.path_pattern
            "#,
            true,
        )
    } else {
        (
            r#"
            SELECT e.id, e.method, e.path_pattern, f.path, e.line, e.handler_qname,
                   h.confidence
            FROM py_endpoints e
            JOIN files f ON e.file_id = f.id
            LEFT JOIN py_endpoint_handlers h ON h.endpoint_id = e.id
            WHERE e.path_pattern LIKE ?1
            ORDER BY e.path_pattern
            "#,
            false,
        )
    };

    let mut stmt = conn.prepare(sql)?;
    let pattern = format!("%{}%", path_pattern);

    let results = if use_method {
        stmt.query_map(params![method.unwrap(), pattern], |row| {
            Ok(PyEndpointResult {
                id: row.get(0)?,
                method: row.get(1)?,
                path_pattern: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                handler_qname: row.get(5)?,
                confidence: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(params![pattern], |row| {
            Ok(PyEndpointResult {
                id: row.get(0)?,
                method: row.get(1)?,
                path_pattern: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                handler_qname: row.get(5)?,
                confidence: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    };

    Ok(results)
}

/// Get handler symbol for an endpoint
pub fn get_py_endpoint_handler(
    conn: &Connection,
    endpoint_id: i64,
) -> Result<Option<SearchResult>> {
    let result = conn.query_row(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM py_endpoint_handlers eh
        JOIN symbols s ON eh.symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE eh.endpoint_id = ?1
        LIMIT 1
        "#,
        params![endpoint_id],
        |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        },
    );

    match result {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Get linked serializer -> model for a symbol_id
pub fn get_py_serializer_model(conn: &Connection, symbol_id: i64) -> Result<Option<SearchResult>> {
    let result = conn.query_row(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM py_serializer_models sm
        JOIN symbols s ON sm.model_symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE sm.serializer_symbol_id = ?1
        LIMIT 1
        "#,
        params![symbol_id],
        |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        },
    );

    match result {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Find settings/env key usages (for py.setting-usage)
pub fn find_py_setting_usages(
    conn: &Connection,
    key: &str,
    limit: usize,
) -> Result<Vec<PySettingUsage>> {
    let pattern = format!("%{}%", key);
    let mut stmt = conn.prepare(
        r#"
        SELECT ps.key, ps.key_kind, s.name, f.path, s.line, ps.confidence, ps.reason, s.id
        FROM py_symbol_settings ps
        JOIN symbols s ON ps.symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE ps.key LIKE ?1
        ORDER BY ps.key, f.path, s.line
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![pattern, limit as i64], |row| {
            Ok(PySettingUsage {
                key: row.get(0)?,
                key_kind: row.get(1)?,
                symbol_name: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                confidence: row.get(5)?,
                reason: row.get(6)?,
                symbol_id: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Get settings for a symbol_id (for endpoint-trace)
pub fn get_py_symbol_settings(conn: &Connection, symbol_id: i64) -> Result<Vec<PySettingUsage>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT ps.key, ps.key_kind, s.name, f.path, s.line, ps.confidence, ps.reason, s.id
        FROM py_symbol_settings ps
        JOIN symbols s ON ps.symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE ps.symbol_id = ?1
        ORDER BY ps.key
        "#,
    )?;

    let results = stmt
        .query_map(params![symbol_id], |row| {
            Ok(PySettingUsage {
                key: row.get(0)?,
                key_kind: row.get(1)?,
                symbol_name: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                confidence: row.get(5)?,
                reason: row.get(6)?,
                symbol_id: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

// === py.model-impact query API ===

/// Result for py.model-impact: model -> serializers -> handlers -> endpoints
#[derive(Debug, Serialize)]
pub struct PyModelImpact {
    pub model: SearchResult,
    pub serializers: Vec<PyModelSerializerImpact>,
}

/// Serializer impact entry for model-impact
#[derive(Debug, Serialize)]
pub struct PyModelSerializerImpact {
    pub serializer: SearchResult,
    pub confidence: String,
    pub handlers: Vec<PyModelHandlerImpact>,
}

/// Handler + endpoints for model-impact
#[derive(Debug, Serialize)]
pub struct PyModelHandlerImpact {
    pub handler: SearchResult,
    pub endpoints: Vec<PyEndpointResult>,
}

/// Find model symbols by name (prefer models.py files)
pub fn find_py_model_symbols(
    conn: &Connection,
    name: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT s.name, s.kind, s.line, s.signature, f.path
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?1 AND s.kind = 'class'
        ORDER BY
            CASE WHEN f.path LIKE '%models.py' OR f.path LIKE '%models/%' THEN 0 ELSE 1 END,
            f.path
        LIMIT ?2
        "#,
    )?;

    let results = stmt
        .query_map(params![name, limit as i64], |row| {
            Ok(SearchResult {
                name: row.get(0)?,
                kind: row.get(1)?,
                line: row.get(2)?,
                signature: row.get(3)?,
                path: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find serializers linked to a model symbol (via py_serializer_models)
pub fn find_py_serializers_for_model(
    conn: &Connection,
    model_name: &str,
) -> Result<Vec<(i64, SearchResult, String)>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT s.id, s.name, s.kind, s.line, s.signature, f.path, sm.confidence
        FROM py_serializer_models sm
        JOIN symbols model_s ON sm.model_symbol_id = model_s.id
        JOIN symbols s ON sm.serializer_symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE model_s.name = ?1
        ORDER BY f.path, s.line
        "#,
    )?;

    let results = stmt
        .query_map(params![model_name], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                SearchResult {
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    line: row.get(3)?,
                    signature: row.get(4)?,
                    path: row.get(5)?,
                },
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find handlers linked to a serializer (via py_handler_serializers)
pub fn find_py_handlers_for_serializer(
    conn: &Connection,
    serializer_symbol_id: i64,
) -> Result<Vec<(i64, SearchResult)>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT s.id, s.name, s.kind, s.line, s.signature, f.path
        FROM py_handler_serializers hs
        JOIN symbols s ON hs.handler_symbol_id = s.id
        JOIN files f ON s.file_id = f.id
        WHERE hs.serializer_symbol_id = ?1
        ORDER BY f.path, s.line
        "#,
    )?;

    let results = stmt
        .query_map(params![serializer_symbol_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                SearchResult {
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    line: row.get(3)?,
                    signature: row.get(4)?,
                    path: row.get(5)?,
                },
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Find endpoints linked to a handler (via py_endpoint_handlers)
pub fn find_py_endpoints_for_handler(
    conn: &Connection,
    handler_symbol_id: i64,
) -> Result<Vec<PyEndpointResult>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT e.id, e.method, e.path_pattern, f.path, e.line, e.handler_qname, eh.confidence
        FROM py_endpoint_handlers eh
        JOIN py_endpoints e ON eh.endpoint_id = e.id
        JOIN files f ON e.file_id = f.id
        WHERE eh.symbol_id = ?1
        ORDER BY e.path_pattern, e.method
        "#,
    )?;

    let results = stmt
        .query_map(params![handler_symbol_id], |row| {
            Ok(PyEndpointResult {
                id: row.get(0)?,
                method: row.get(1)?,
                path_pattern: row.get(2)?,
                file_path: row.get(3)?,
                line: row.get(4)?,
                handler_qname: row.get(5)?,
                confidence: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash("/Users/test/project");
        let h2 = simple_hash("/Users/test/project");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_different() {
        let h1 = simple_hash("/Users/test/project1");
        let h2 = simple_hash("/Users/test/project2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_init_db() {
        let conn = create_test_db();
        // Check tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='files'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_escape_fts5_query_simple() {
        assert_eq!(escape_fts5_query("MyClass"), "\"MyClass\"");
    }

    #[test]
    fn test_escape_fts5_query_prefix() {
        assert_eq!(escape_fts5_query("Slow*"), "\"Slow\"*");
        assert_eq!(escape_fts5_query("SlowUpstream*"), "\"SlowUpstream\"*");
    }

    #[test]
    fn test_escape_fts5_query_empty() {
        assert_eq!(escape_fts5_query(""), "");
        assert_eq!(escape_fts5_query("   "), "");
    }

    #[test]
    fn test_escape_fts5_query_with_quotes() {
        assert_eq!(escape_fts5_query("say \"hello\""), "\"say \"\"hello\"\"\"");
    }

    #[test]
    fn test_upsert_and_search() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "src/main.kt", 1000, 100).unwrap();
        assert!(file_id > 0);

        insert_symbol(
            &conn,
            file_id,
            "MyService",
            SymbolKind::Class,
            10,
            Some("class MyService"),
        )
        .unwrap();
        insert_symbol(
            &conn,
            file_id,
            "processData",
            SymbolKind::Function,
            20,
            Some("fun processData()"),
        )
        .unwrap();

        let results = search_symbols(&conn, "MyService", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "MyService");
        assert_eq!(results[0].kind, "class");
        assert_eq!(results[0].path, "src/main.kt");
    }

    #[test]
    fn test_search_empty_query() {
        let conn = create_test_db();
        let results = search_symbols(&conn, "", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_files() {
        let conn = create_test_db();
        upsert_file(&conn, "src/main.kt", 1000, 100).unwrap();
        upsert_file(&conn, "src/utils/Helper.kt", 2000, 200).unwrap();

        let files = find_files(&conn, "Helper", 10).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].contains("Helper"));
    }

    #[test]
    fn test_find_symbols_by_name() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "src/model.kt", 1000, 100).unwrap();
        insert_symbol(
            &conn,
            file_id,
            "User",
            SymbolKind::Class,
            5,
            Some("data class User"),
        )
        .unwrap();
        insert_symbol(
            &conn,
            file_id,
            "UserRepository",
            SymbolKind::Interface,
            20,
            Some("interface UserRepository"),
        )
        .unwrap();

        let results = find_symbols_by_name(&conn, "User", None, 10).unwrap();
        assert!(results.len() >= 1);
        assert!(results.iter().any(|r| r.name == "User"));
    }

    #[test]
    fn test_upsert_file_updates_mtime() {
        let conn = create_test_db();
        let _id1 = upsert_file(&conn, "src/main.kt", 1000, 100).unwrap();
        let id2 = upsert_file(&conn, "src/main.kt", 2000, 200).unwrap();
        assert!(
            id2 > 0,
            "upsert should succeed for same path with different mtime"
        );
    }

    #[test]
    fn test_clear_db() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "src/main.kt", 1000, 100).unwrap();
        insert_symbol(
            &conn,
            file_id,
            "Test",
            SymbolKind::Class,
            1,
            Some("class Test"),
        )
        .unwrap();

        clear_db(&conn).unwrap();

        let results = search_symbols(&conn, "Test", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_stats() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "src/main.kt", 1000, 100).unwrap();
        insert_symbol(
            &conn,
            file_id,
            "Foo",
            SymbolKind::Class,
            1,
            Some("class Foo"),
        )
        .unwrap();
        insert_symbol(
            &conn,
            file_id,
            "bar",
            SymbolKind::Function,
            5,
            Some("fun bar()"),
        )
        .unwrap();

        let stats = get_stats(&conn).unwrap();
        assert_eq!(stats.file_count, 1);
        assert_eq!(stats.symbol_count, 2);
    }

    #[test]
    fn test_insert_and_find_inheritance() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "src/model.kt", 1000, 100).unwrap();
        insert_symbol(
            &conn,
            file_id,
            "Child",
            SymbolKind::Class,
            1,
            Some("class Child : Parent()"),
        )
        .unwrap();

        let child_id: i64 = conn
            .query_row("SELECT id FROM symbols WHERE name = 'Child'", [], |row| {
                row.get(0)
            })
            .unwrap();
        insert_inheritance(&conn, child_id, "Parent", "extends").unwrap();

        let impls = find_implementations(&conn, "Parent", 10).unwrap();
        assert_eq!(impls.len(), 1);
        assert_eq!(impls[0].name, "Child");
    }

    #[test]
    fn test_count_refs() {
        let conn = create_test_db();
        let count = count_refs(&conn).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_py_tables_exist() {
        let conn = create_test_db();
        for table in &[
            "py_endpoints",
            "py_endpoint_handlers",
            "py_serializer_models",
            "py_symbol_settings",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {} should exist", table);
        }
    }

    #[test]
    fn test_py_endpoints_crud() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "urls.py", 1000, 100).unwrap();

        let ep_id = insert_py_endpoint(
            &conn,
            Some("GET"),
            "/api/v1/users/",
            file_id,
            10,
            Some("apps.users.views.UserViewSet"),
        )
        .unwrap();
        assert!(ep_id > 0);

        let routes = get_py_endpoints(&conn, None, 100).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].method.as_deref(), Some("GET"));
        assert_eq!(routes[0].path_pattern, "/api/v1/users/");
        assert_eq!(
            routes[0].handler_qname.as_deref(),
            Some("apps.users.views.UserViewSet")
        );
    }

    #[test]
    fn test_py_endpoint_handler_link() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "views.py", 1000, 100).unwrap();
        let sym_id = insert_symbol(
            &conn,
            file_id,
            "UserViewSet",
            SymbolKind::Class,
            5,
            Some("class UserViewSet(ModelViewSet)"),
        )
        .unwrap();

        let ep_id = insert_py_endpoint(
            &conn,
            Some("GET"),
            "/api/v1/users/",
            file_id,
            10,
            Some("UserViewSet"),
        )
        .unwrap();

        insert_py_endpoint_handler(&conn, ep_id, sym_id, "high", Some("router.register")).unwrap();

        let handler = get_py_endpoint_handler(&conn, ep_id).unwrap();
        assert!(handler.is_some());
        assert_eq!(handler.unwrap().name, "UserViewSet");
    }

    #[test]
    fn test_py_serializer_model_link() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "serializers.py", 1000, 100).unwrap();
        let ser_id = insert_symbol(
            &conn,
            file_id,
            "UserSerializer",
            SymbolKind::Class,
            5,
            Some("class UserSerializer(ModelSerializer)"),
        )
        .unwrap();
        let model_id = insert_symbol(
            &conn,
            file_id,
            "User",
            SymbolKind::Class,
            20,
            Some("class User(Model)"),
        )
        .unwrap();

        insert_py_serializer_model(&conn, ser_id, model_id, "high", Some("Meta.model = User"))
            .unwrap();

        let model = get_py_serializer_model(&conn, ser_id).unwrap();
        assert!(model.is_some());
        assert_eq!(model.unwrap().name, "User");
    }

    #[test]
    fn test_py_symbol_settings_crud() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "views.py", 1000, 100).unwrap();
        let sym_id = insert_symbol(
            &conn,
            file_id,
            "get_host",
            SymbolKind::Function,
            5,
            Some("def get_host()"),
        )
        .unwrap();

        insert_py_symbol_setting(
            &conn,
            sym_id,
            "CLASSIFICATION_HOST",
            "settings",
            "medium",
            Some("settings.CLASSIFICATION_HOST"),
        )
        .unwrap();

        let usages = find_py_setting_usages(&conn, "CLASSIFICATION_HOST", 100).unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].key, "CLASSIFICATION_HOST");
        assert_eq!(usages[0].key_kind, "settings");
        assert_eq!(usages[0].symbol_name, "get_host");
    }

    #[test]
    fn test_find_py_endpoint_by_path() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "urls.py", 1000, 100).unwrap();

        insert_py_endpoint(&conn, Some("GET"), "/api/v1/users/", file_id, 10, None).unwrap();
        insert_py_endpoint(&conn, Some("POST"), "/api/v1/users/", file_id, 15, None).unwrap();
        insert_py_endpoint(&conn, Some("GET"), "/api/v1/orders/", file_id, 20, None).unwrap();

        // search by path pattern
        let results = find_py_endpoint(&conn, None, "users").unwrap();
        assert_eq!(results.len(), 2);

        // search by method + path
        let results = find_py_endpoint(&conn, Some("GET"), "users").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method.as_deref(), Some("GET"));
    }

    #[test]
    fn test_clear_py_facts_for_files() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "urls.py", 1000, 100).unwrap();
        let file_id2 = upsert_file(&conn, "views.py", 1000, 100).unwrap();

        insert_py_endpoint(&conn, Some("GET"), "/api/v1/users/", file_id, 10, None).unwrap();
        insert_py_endpoint(&conn, Some("GET"), "/api/v2/items/", file_id2, 10, None).unwrap();

        let sym_id = insert_symbol(
            &conn,
            file_id,
            "get_host",
            SymbolKind::Function,
            5,
            Some("def get_host()"),
        )
        .unwrap();
        insert_py_symbol_setting(&conn, sym_id, "HOST", "settings", "medium", None).unwrap();

        // clear only for file_id
        clear_py_facts_for_files(&conn, &[file_id]).unwrap();

        // endpoints from urls.py deleted, views.py untouched
        let routes = get_py_endpoints(&conn, None, 100).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path_pattern, "/api/v2/items/");

        // settings for symbols from urls.py deleted
        let usages = find_py_setting_usages(&conn, "HOST", 100).unwrap();
        assert_eq!(usages.len(), 0);
    }

    #[test]
    fn test_clear_db_with_py_tables() {
        let conn = create_test_db();
        let file_id = upsert_file(&conn, "urls.py", 1000, 100).unwrap();
        insert_py_endpoint(&conn, Some("GET"), "/api/", file_id, 1, None).unwrap();

        clear_db(&conn).unwrap();

        let routes = get_py_endpoints(&conn, None, 100).unwrap();
        assert!(routes.is_empty());
    }
}
