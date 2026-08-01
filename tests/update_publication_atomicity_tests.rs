//! CLI-level atomic update regressions using a real SQLite index in `TempDir`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use rusqlite::Connection;
use tempfile::TempDir;

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ast-index"))
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn run(root: &Path, db: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .current_dir(root)
        .args(args)
        .env("AST_INDEX_DB_PATH", db)
        .env("AST_INDEX_DISABLE_GC", "1")
        .env_remove("AST_INDEX_CACHE_DIR")
        .output()
        .unwrap()
}

fn file_count(db: &Path) -> i64 {
    Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
        .unwrap()
}

fn graph_count(db: &Path) -> i64 {
    Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM django_endpoints", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn legacy_cache_key(path: &Path) -> String {
    let mut hash = 5381u64;
    for byte in path.to_string_lossy().bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{hash:x}")
}

fn cached_db(cache_home: &Path, namespace: &str) -> std::path::PathBuf {
    fs::read_dir(cache_home.join(namespace))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("index.db"))
        .find(|path| path.is_file())
        .unwrap()
}

fn run_with_cache(cwd: &Path, cache_home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .current_dir(cwd)
        .args(args)
        .env("XDG_CACHE_HOME", cache_home)
        .env("AST_INDEX_DISABLE_GC", "1")
        .env_remove("AST_INDEX_DB_PATH")
        .env_remove("AST_INDEX_CACHE_DIR")
        .env_remove("KOTLIN_INDEX_DB_PATH")
        .output()
        .unwrap()
}

#[test]
fn noop_update_skips_snapshot_and_failed_staged_update_keeps_live_generation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Before:\n    pass\n");
    write(
        &root.join("app/urls.py"),
        "urlpatterns = [path('before/', Before.as_view())]\n",
    );

    let rebuilt = run(&root, &db, &["rebuild"]);
    assert!(
        rebuilt.status.success(),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let old_files = file_count(&db);
    let old_graph = graph_count(&db);

    let noop = run(&root, &db, &["update"]);
    assert!(
        noop.status.success(),
        "{}",
        String::from_utf8_lossy(&noop.stderr)
    );
    assert!(String::from_utf8_lossy(&noop.stdout).contains("up to date"));
    let cache = db.parent().unwrap();
    assert!(
        !fs::read_dir(cache)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(".update-")),
        "no-op update allocated a staging generation"
    );

    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('index_update_dirty_at', 'preserved')",
        [],
    )
    .unwrap();
    // A partial graph schema forces the update path to migrate. That DDL must
    // run only after the live generation has been backed up into staging.
    conn.execute("DROP TABLE django_file_settings", []).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_staged_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT, 'forced staged failure'); END;").unwrap();
    let live_schema_before: Vec<(String, String, String, Option<String>)> = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(conn);
    write(
        &root.join("app/views.py"),
        "class AfterWithLongerName:\n    pass\n",
    );

    let failed = run(&root, &db, &["update"]);
    assert!(
        !failed.status.success(),
        "staged update unexpectedly succeeded"
    );
    assert!(String::from_utf8_lossy(&failed.stderr).contains("forced staged failure"));
    assert_eq!(
        file_count(&db),
        old_files,
        "live core rows changed after staged failure"
    );
    assert_eq!(
        graph_count(&db),
        old_graph,
        "live graph rows changed after staged failure"
    );
    let dirty: String = Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT value FROM metadata WHERE key = 'index_update_dirty_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        dirty, "preserved",
        "failed staged update altered live dirty marker"
    );
    let live_schema_after: Vec<(String, String, String, Option<String>)> = Connection::open(&db)
        .unwrap()
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        live_schema_after, live_schema_before,
        "failed staged update altered the published SQLite schema"
    );
}

#[test]
fn update_migrates_legacy_subtrees_only_in_staging_after_read_only_preflight() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Before:\n    pass\n");
    assert!(run(&root, &db, &["rebuild"]).status.success());

    let conn = Connection::open(&db).unwrap();
    conn.execute("DROP TABLE subtrees", []).unwrap();
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('extra_roots', '[]')",
        [],
    )
    .unwrap();
    drop(conn);
    write(
        &root.join("app/views.py"),
        "class AfterChanged:\n    pass\n",
    );

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let conn = Connection::open(&db).unwrap();
    let subtrees: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'subtrees'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(subtrees, 1, "staged update must publish legacy migration");
    let legacy_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE key = 'extra_roots'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        legacy_rows, 0,
        "published migration must clear legacy metadata"
    );
}

#[test]
fn clean_update_publishes_legacy_and_partial_schema_migrations() {
    for (name, missing_table) in [
        ("legacy-subtrees", "subtrees"),
        ("partial-django-graph", "django_file_settings"),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join(name);
        let db = temp.path().join("cache/index.db");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0\"\n",
        );
        write(&root.join("app/views.py"), "class Stable:\n    pass\n");
        assert!(run(&root, &db, &["rebuild"]).status.success());

        Connection::open(&db)
            .unwrap()
            .execute(&format!("DROP TABLE {missing_table}"), [])
            .unwrap();

        let output = run(&root, &db, &["update"]);
        assert!(
            output.status.success(),
            "{name} stdout: {}\n{name} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("up to date"),
            "{name} schema migration was incorrectly treated as a no-op"
        );
        let migrated: i64 = Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [missing_table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migrated, 1, "{name} migration was not published");
    }
}

#[test]
fn update_recovers_interrupted_publication_before_opening_live_db() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Stable:\n    pass\n");
    assert!(run(&root, &db, &["rebuild"]).status.success());
    fs::write(
        db.with_extension("db.publish-state-v1"),
        r#"{"version":1,"token":"1-1-1","operation":"install","artifacts":[true,false,false,false]}"#,
    )
    .unwrap();

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !db.with_extension("db.publish-state-v1").exists(),
        "update must remove a recovered publication marker"
    );
}

#[test]
fn noop_update_recovers_published_dirty_marker() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Stable:\n    pass\n");
    assert!(run(&root, &db, &["rebuild"]).status.success());

    Connection::open(&db)
        .unwrap()
        .execute(
            "INSERT INTO metadata (key, value) VALUES ('index_update_dirty_at', '123')",
            [],
        )
        .unwrap();

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let remaining: i64 = Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE key = 'index_update_dirty_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0, "successful no-op must publish dirty recovery");
}

#[test]
fn update_from_nested_directory_recovers_publication_and_uses_ancestor_cache() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let cache_home = temp.path().join("cache-home");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Before:\n    pass\n");
    assert!(run_with_cache(&root, &cache_home, &["rebuild"])
        .status
        .success());

    let db = cached_db(&cache_home, "ast-index");
    fs::write(
        db.with_extension("db.publish-state-v1"),
        r#"{"version":1,"token":"1-1-1","operation":"install","artifacts":[true,false,false,false]}"#,
    )
    .unwrap();
    write(&root.join("app/views.py"), "class After:\n    pass\n");
    let nested = root.join("app/nested");
    fs::create_dir_all(&nested).unwrap();
    write(
        &nested.join("Cargo.toml"),
        "[package]\nname = \"nested-marker\"\nversion = \"0\"\n",
    );

    let update = run_with_cache(&nested, &cache_home, &["update"]);
    assert!(
        update.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    assert!(
        !db.with_extension("db.publish-state-v1").exists(),
        "marker remains; stdout: {} stderr: {}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    assert_eq!(file_count(&db), 1, "ancestor generation was not updated");
}

#[test]
fn symbols_rebuild_and_unchanged_update_materialize_missing_django_graph() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class StableView:\n    pass\n");
    write(
        &root.join("app/urls.py"),
        "from .views import StableView\nurlpatterns = [path('stable/', StableView.as_view())]\n",
    );

    assert!(run(&root, &db, &["rebuild", "--type", "symbols"])
        .status
        .success());
    assert_eq!(
        graph_count(&db),
        1,
        "symbols rebuild did not materialize graph"
    );

    let conn = Connection::open(&db).unwrap();
    conn.execute("DELETE FROM django_endpoints", []).unwrap();
    conn.execute(
        "DELETE FROM metadata WHERE key = 'django_graph_materialized_v1'",
        [],
    )
    .unwrap();
    drop(conn);

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        graph_count(&db),
        1,
        "unchanged update did not recover graph"
    );
}

#[test]
fn schema_only_update_rebuilds_django_graph_before_publication() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class StableView:\n    pass\n");
    write(
        &root.join("app/urls.py"),
        "from .views import StableView\nurlpatterns = [path('stable/', StableView.as_view())]\n",
    );
    assert!(run(&root, &db, &["rebuild"]).status.success());
    assert_eq!(graph_count(&db), 1, "fixture did not create a graph row");

    Connection::open(&db)
        .unwrap()
        .execute("DROP TABLE django_file_settings", [])
        .unwrap();

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        graph_count(&db),
        1,
        "schema-only publication must rebuild the materialized graph"
    );
}

#[test]
fn non_python_rebuild_marks_empty_django_graph_and_noop_update_keeps_generation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db = temp.path().join("cache/index.db");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("src/main.rs"), "fn main() {}\n");

    let rebuilt = run(&root, &db, &["rebuild"]);
    assert!(
        rebuilt.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rebuilt.stdout),
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let marker_count: i64 = Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE key = 'django_graph_materialized_v1' AND value = '1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_count, 1, "empty Django graph was not materialized");
    let inode_before = fs::metadata(&db).unwrap().ino();

    let output = run(&root, &db, &["update"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("up to date"),
        "no-op update unexpectedly published: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        fs::metadata(&db).unwrap().ino(),
        inode_before,
        "no-op update replaced the published generation"
    );
}

#[test]
fn update_migrates_legacy_kotlin_index_cache() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let cache_home = temp.path().join("cache-home");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/views.py"), "class Stable:\n    pass\n");

    let legacy_db = cache_home
        .join("kotlin-index")
        .join(legacy_cache_key(&root))
        .join("index.db");
    assert!(run(&root, &legacy_db, &["rebuild"]).status.success());
    assert!(legacy_db.exists());

    let update = run_with_cache(&root, &cache_home, &["update"]);
    assert!(
        update.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    assert!(!legacy_db.exists(), "legacy cache was not migrated");
    assert!(
        cache_home
            .join("ast-index")
            .join(legacy_cache_key(&root))
            .join("index.db")
            .exists(),
        "new cache is missing"
    );
}
