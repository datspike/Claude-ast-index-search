use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rusqlite::{params, Connection};

use ast_index::db;

/// Create an in-memory DB with schema initialized.
fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    db::init_db(&conn).unwrap();
    conn
}

/// Populate the DB with `n` symbols spread across files, each with 3 refs.
/// Also inserts inheritance records (3 parents per class).
fn populate_db(conn: &Connection, n: usize) {
    let kinds = ["class", "interface", "function", "property", "enum"];
    let parent_names = ["BaseClass", "Serializable", "Comparable"];

    conn.execute_batch("BEGIN").unwrap();

    for i in 0..n {
        let file_path = format!("src/module{}/File{}.kt", i / 100, i);
        conn.execute(
            "INSERT OR REPLACE INTO files (path, mtime, size) VALUES (?1, ?2, ?3)",
            params![file_path, 1000i64, 500i64],
        )
        .unwrap();
        let file_id = conn.last_insert_rowid();

        let name = format!("Symbol{}", i);
        let kind = kinds[i % kinds.len()];
        let sig = format!("{} {} : SomeType", kind, name);
        conn.execute(
            "INSERT INTO symbols (file_id, name, kind, line, signature) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![file_id, name, kind, (i + 1) as i64, sig],
        )
        .unwrap();
        let symbol_id = conn.last_insert_rowid();

        // Add inheritance for class-like symbols
        if kind == "class" || kind == "interface" {
            for parent in &parent_names {
                conn.execute(
                    "INSERT INTO inheritance (child_id, parent_name, kind) VALUES (?1, ?2, ?3)",
                    params![symbol_id, parent, "extends"],
                )
                .unwrap();
            }
        }

        // Add refs
        for r in 0..3 {
            let ref_name = format!("Symbol{}", (i + r * 7) % n);
            let ctx = format!("val x = {}.create()", ref_name);
            conn.execute(
                "INSERT INTO refs (file_id, name, line, context) VALUES (?1, ?2, ?3, ?4)",
                params![file_id, ref_name, (r * 10 + 5) as i64, ctx],
            )
            .unwrap();
        }
    }

    conn.execute_batch("COMMIT").unwrap();
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_batch_insert_1000(c: &mut Criterion) {
    c.bench_function("batch_insert_1000", |b| {
        b.iter_batched(
            setup_db,
            |conn| {
                populate_db(&conn, 1000);
            },
            BatchSize::PerIteration,
        );
    });
}

fn bench_fts5_search_exact(c: &mut Criterion) {
    let conn = setup_db();
    populate_db(&conn, 10_000);

    c.bench_function("fts5_search_exact", |b| {
        b.iter(|| {
            let _ = db::search_symbols(&conn, criterion::black_box("Symbol5000"), 20);
        });
    });
}

fn bench_fts5_search_prefix(c: &mut Criterion) {
    let conn = setup_db();
    populate_db(&conn, 10_000);

    c.bench_function("fts5_search_prefix", |b| {
        b.iter(|| {
            let _ = db::search_symbols(&conn, criterion::black_box("Symbol50*"), 20);
        });
    });
}

fn bench_fts5_search_fuzzy(c: &mut Criterion) {
    let conn = setup_db();
    populate_db(&conn, 10_000);

    c.bench_function("fts5_search_fuzzy", |b| {
        b.iter(|| {
            let _ = db::search_symbols_fuzzy(&conn, criterion::black_box("Symbo"), 20);
        });
    });
}

fn bench_find_implementations(c: &mut Criterion) {
    let conn = setup_db();
    populate_db(&conn, 10_000);

    c.bench_function("find_implementations_10k", |b| {
        b.iter(|| {
            let _ = db::find_implementations(&conn, criterion::black_box("BaseClass"), 100);
        });
    });
}

fn bench_find_references(c: &mut Criterion) {
    let conn = setup_db();
    populate_db(&conn, 10_000);

    c.bench_function("find_references_10k", |b| {
        b.iter(|| {
            let _ = db::find_references(&conn, criterion::black_box("Symbol500"), 100);
        });
    });
}

criterion_group!(
    benches,
    bench_batch_insert_1000,
    bench_fts5_search_exact,
    bench_fts5_search_prefix,
    bench_fts5_search_fuzzy,
    bench_find_implementations,
    bench_find_references,
);
criterion_main!(benches);
