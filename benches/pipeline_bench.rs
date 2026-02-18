use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rusqlite::{params, Connection};

use ast_index::db;
use ast_index::parsers::{parse_file_symbols, FileType};

const KOTLIN_CODE: &str = r#"
package com.example.payments

import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

sealed class PaymentState {
    object Idle : PaymentState()
    data class Loading(val orderId: String) : PaymentState()
    data class Success(val receipt: Receipt) : PaymentState()
    data class Error(val message: String) : PaymentState()
}

data class Receipt(val id: String, val amount: Double)

interface PaymentRepository {
    suspend fun processPayment(orderId: String, amount: Double): Result<Receipt>
    suspend fun getHistory(userId: String): Flow<List<Receipt>>
}

class PaymentRepositoryImpl @Inject constructor(
    private val api: PaymentApi,
    private val cache: PaymentCache,
) : PaymentRepository {

    override suspend fun processPayment(orderId: String, amount: Double): Result<Receipt> {
        return try {
            val receipt = api.charge(orderId, amount)
            cache.save(receipt)
            Result.success(receipt)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    override suspend fun getHistory(userId: String): Flow<List<Receipt>> {
        return cache.getHistory(userId)
    }

    companion object {
        const val MAX_RETRY = 3
    }
}
"#;

const JAVA_CODE: &str = r#"
package com.example.users;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<List<UserDto>> getAll(@RequestParam(defaultValue = "0") int page) {
        return ResponseEntity.ok(userService.findAll(page, 20));
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getById(@PathVariable Long id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<UserDto> create(@RequestBody CreateUserRequest request) {
        return ResponseEntity.status(201).body(userService.create(request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}

interface UserService {
    List<UserDto> findAll(int page, int size);
    Optional<UserDto> findById(Long id);
    UserDto create(CreateUserRequest request);
    void delete(Long id);
}
"#;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    db::init_db(&conn).unwrap();
    conn
}

fn bench_parse_and_extract_refs(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_and_extract_refs");

    group.bench_function("kotlin", |b| {
        b.iter(|| {
            let _ = parse_file_symbols(criterion::black_box(KOTLIN_CODE), FileType::Kotlin);
        });
    });

    group.bench_function("java", |b| {
        b.iter(|| {
            let _ = parse_file_symbols(criterion::black_box(JAVA_CODE), FileType::Java);
        });
    });

    group.finish();
}

fn bench_full_pipeline_single_file(c: &mut Criterion) {
    c.bench_function("full_pipeline_single_file", |b| {
        b.iter_batched(
            setup_db,
            |conn| {
                // Parse
                let (symbols, refs) =
                    parse_file_symbols(criterion::black_box(KOTLIN_CODE), FileType::Kotlin)
                        .unwrap();

                // Insert file
                conn.execute(
                    "INSERT OR REPLACE INTO files (path, mtime, size) VALUES (?1, ?2, ?3)",
                    params!["src/PaymentRepository.kt", 1000i64, 500i64],
                )
                .unwrap();
                let file_id = conn.last_insert_rowid();

                // Insert symbols
                for sym in &symbols {
                    conn.execute(
                        "INSERT INTO symbols (file_id, name, kind, line, signature) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            file_id,
                            sym.name,
                            sym.kind.as_str(),
                            sym.line as i64,
                            sym.signature,
                        ],
                    )
                    .unwrap();
                    let sym_id = conn.last_insert_rowid();
                    for (parent_name, kind) in &sym.parents {
                        conn.execute(
                            "INSERT INTO inheritance (child_id, parent_name, kind) VALUES (?1, ?2, ?3)",
                            params![sym_id, parent_name, kind],
                        )
                        .unwrap();
                    }
                }

                // Insert refs
                for r in &refs {
                    conn.execute(
                        "INSERT INTO refs (file_id, name, line, context) VALUES (?1, ?2, ?3, ?4)",
                        params![file_id, r.name, r.line as i64, r.context],
                    )
                    .unwrap();
                }
            },
            BatchSize::PerIteration,
        );
    });
}

criterion_group!(
    benches,
    bench_parse_and_extract_refs,
    bench_full_pipeline_single_file,
);
criterion_main!(benches);
