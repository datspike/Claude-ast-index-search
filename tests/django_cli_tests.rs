//! End-to-end coverage for the Django/DRF graph query commands.
//!
//! Each command must honour the named subtree filter and keep text and JSON
//! output usable against rows owned by an extra root.

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{LazyLock, Mutex};

use ast_index::db;
use rusqlite::Connection;
use tempfile::TempDir;

static ENV_SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct CacheEnvironment {
    previous: Vec<(&'static str, Option<OsString>)>,
}

impl CacheEnvironment {
    fn set(cache: &Path) -> Self {
        let keys = [
            "AST_INDEX_CACHE_DIR",
            "AST_INDEX_DB_PATH",
            "KOTLIN_INDEX_DB_PATH",
        ];
        let previous = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        std::env::set_var("AST_INDEX_CACHE_DIR", cache);
        std::env::remove_var("AST_INDEX_DB_PATH");
        std::env::remove_var("KOTLIN_INDEX_DB_PATH");
        Self { previous }
    }
}

impl Drop for CacheEnvironment {
    fn drop(&mut self) {
        for (key, value) in self.previous.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ast-index"))
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn write_django_app(root: &Path, prefix: &str) {
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app/models.py"), "class User:\n    pass\n");
    write(
        &root.join("app/serializers.py"),
        "from .models import User\n\nclass UserSerializer:\n    class Meta:\n        model = User\n",
    );
    write(
        &root.join("app/views.py"),
        "from django.conf import settings\nfrom .serializers import UserSerializer\n\nclass UserViewSet:\n    serializer_class = UserSerializer\n\n    def list(self, request):\n        return settings.USER_API_URL\n",
    );
    write(
        &root.join("app/urls.py"),
        &format!("from .views import UserViewSet\nurlpatterns = [path('{prefix}/', UserViewSet.as_view({{'get': 'list'}})),]\n"),
    );
}

fn run(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .current_dir(root)
        .args(args)
        .env("AST_INDEX_CACHE_DIR", root.parent().unwrap().join("cache"))
        .env("AST_INDEX_DISABLE_GC", "1")
        .env_remove("AST_INDEX_DB_PATH")
        .env_remove("KOTLIN_INDEX_DB_PATH")
        .output()
        .unwrap()
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn partial_django_schema_migration_preserves_graph_rows_and_is_idempotent() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let db_path = temp.path().join("index.db");
    fs::create_dir_all(&root).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    db::init_db(&conn).unwrap();
    conn.execute(
        "INSERT INTO files(path, root_path, mtime, size) VALUES ('app/urls.py', '', 1, 1)",
        [],
    )
    .unwrap();
    let file_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO django_endpoints(method, path_pattern, file_id, line, handler_qname) VALUES ('GET', 'legacy/', ?1, 1, 'LegacyView')",
        [file_id],
    )
    .unwrap();
    conn.execute("DROP TABLE django_file_settings", []).unwrap();
    drop(conn);

    std::env::set_var("AST_INDEX_DB_PATH", &db_path);
    std::env::remove_var("KOTLIN_INDEX_DB_PATH");
    std::env::remove_var("AST_INDEX_CACHE_DIR");
    let migrated = db::open_db(&root).unwrap();
    let paths: Vec<String> = migrated
        .prepare("SELECT path_pattern FROM django_endpoints")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(paths, ["legacy/"]);
    assert!(db::django_graph_schema_exists(&migrated).unwrap());
    drop(migrated);

    let reopened = db::open_db(&root).unwrap();
    assert_eq!(
        reopened
            .query_row("SELECT COUNT(*) FROM django_endpoints", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "reopening a migrated partial schema must be idempotent"
    );
    drop(reopened);
    std::env::remove_var("AST_INDEX_DB_PATH");
}

#[test]
fn django_routes_partial_schema_cli_returns_json_without_migrating() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );

    std::env::set_var("AST_INDEX_CACHE_DIR", temp.path().join("cache"));
    std::env::remove_var("AST_INDEX_DB_PATH");
    std::env::remove_var("KOTLIN_INDEX_DB_PATH");
    let db_path = db::get_db_path(&root).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    db::init_db(&conn).unwrap();
    conn.execute("DROP TABLE django_file_settings", []).unwrap();
    drop(conn);

    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error"], "django_graph_schema_missing");

    let conn = Connection::open(&db_path).unwrap();
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'django_file_settings'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        table_exists, 0,
        "query command must not run graph DDL/migration"
    );
    std::env::remove_var("AST_INDEX_CACHE_DIR");
}

#[test]
fn nested_django_includes_materialize_only_composed_mounted_paths() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("project/urls.py"),
        "from django.urls import include, path\nurlpatterns = [path('api/', include('app.urls'))]\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import include, path\nurlpatterns = [path('v1/', include('.child_urls'))]\n",
    );
    write(
        &root.join("app/child_urls.py"),
        "from .views import UserView\nurlpatterns = [path('users/', UserView.as_view())]\n",
    );
    write(&root.join("app/views.py"), "class UserView:\n    pass\n");

    let mut conn = db::open_db(&root).unwrap();
    db::init_db(&conn).unwrap();
    ast_index::indexer::index_directory(&mut conn, &root, false, true).unwrap();
    ast_index::indexer::extract_django_facts(&mut conn, &root, false).unwrap();
    let endpoints = db::get_django_endpoints(&conn, None, None, usize::MAX).unwrap();
    let paths: Vec<_> = endpoints
        .iter()
        .map(|endpoint| endpoint.path_pattern.as_str())
        .collect();
    assert!(paths.contains(&"api/v1/users/"), "mounted paths: {paths:?}");
    assert!(
        !paths.contains(&"v1/users/"),
        "bare nested path leaked: {paths:?}"
    );
    assert!(
        !paths.contains(&"users/"),
        "bare child path leaked: {paths:?}"
    );
}

#[test]
fn django_graph_commands_are_subtree_aware_in_text_and_json() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let main = temp.path().join("main");
    let extra = temp.path().join("extra");
    write_django_app(&main, "aaa-main-users");
    write_django_app(&extra, "zzz-extra-users");

    assert_success(&run(&main, &["rebuild"]));
    assert_success(&run(&main, &["subtree", "add", "extra", "../extra"]));
    assert_success(&run(&main, &["rebuild"]));

    let commands: [Vec<&str>; 4] = [
        vec!["django.routes", "extra-users"],
        vec!["django.endpoint-trace", "extra-users", "--method", "GET"],
        vec!["django.setting-usage", "USER_API_URL"],
        vec!["django.model-impact", "User"],
    ];
    let scoped_limited = run(
        &main,
        &[
            "--subtree",
            "extra",
            "--format",
            "json",
            "django.routes",
            "--limit",
            "1",
        ],
    );
    assert_success(&scoped_limited);
    assert!(
        String::from_utf8_lossy(&scoped_limited.stdout).contains("zzz-extra-users"),
        "scope must be applied before django.routes limit"
    );

    for command in &commands {
        let mut text_args = vec!["--subtree", "extra"];
        text_args.extend(command.iter().copied());
        let text = run(&main, &text_args);
        assert_success(&text);
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(
            text.contains("extra"),
            "missing subtree-aware text output: {text}"
        );
        assert!(
            !text.contains("aaa-main-users"),
            "subtree filter leaked primary output: {text}"
        );

        let mut json_args = vec!["--subtree", "extra", "--format", "json"];
        json_args.extend(command.iter().copied());
        let json = run(&main, &json_args);
        assert_success(&json);
        let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_ne!(
            json,
            serde_json::Value::Array(Vec::new()),
            "empty JSON result"
        );
        assert!(
            json.to_string().contains("zzz-extra-users")
                || json.to_string().contains("USER_API_URL")
                || json.to_string().contains("User"),
            "unexpected JSON result: {json}"
        );
        assert!(
            !json.to_string().contains("aaa-main-users"),
            "subtree filter leaked primary JSON output: {json}"
        );
    }
}

#[test]
fn unknown_subtree_keeps_django_graph_queries_empty() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let main = temp.path().join("main");
    let extra = temp.path().join("extra");
    write_django_app(&main, "main-users");
    write_django_app(&extra, "extra-users");

    assert_success(&run(&main, &["rebuild"]));
    assert_success(&run(&main, &["subtree", "add", "extra", "../extra"]));
    assert_success(&run(&main, &["rebuild"]));

    for command in [
        vec!["django.routes"],
        vec!["django.endpoint-trace", "users", "--method", "GET"],
        vec!["django.setting-usage", "USER_API_URL"],
        vec!["django.model-impact", "User"],
    ] {
        let mut args = vec!["--subtree", "ghost", "--format", "json"];
        args.extend(command);
        let output = run(&main, &args);
        assert_success(&output);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!([]),
            "unknown subtree leaked graph rows for {args:?}"
        );
    }
}

#[test]
fn router_mounts_are_materialized_and_same_named_viewset_actions_stay_owner_qualified() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.conf import settings\nfrom django.urls import include, path\nfrom rest_framework.routers import DefaultRouter\n\nclass FirstViewSet(ModelViewSet):\n    class_setting = settings.FIRST_CLASS_KEY\n    def list(self, request):\n        return settings.FIRST_METHOD_KEY\n\nclass SecondViewSet(ModelViewSet):\n    class_setting = settings.SECOND_CLASS_KEY\n    def list(self, request):\n        return settings.SECOND_METHOD_KEY\n\nrouter = DefaultRouter()\nrouter.register('first', FirstViewSet)\nrouter.register('second', SecondViewSet)\nurlpatterns = [path('api/', include(router.urls))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let routes = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&routes);
    let routes: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    let paths = routes.to_string();
    assert!(paths.contains("api/first/"), "mounted routes: {paths}");
    assert!(
        paths.contains("api/second/{id}/"),
        "mounted routes: {paths}"
    );
    assert!(
        !paths.contains("\\\"first/\\\""),
        "bare router route leaked: {paths}"
    );
    assert!(
        !paths.contains("include(router.urls"),
        "false include endpoint: {paths}"
    );

    for (route, class_key, method_key, expected_line) in [
        ("api/first/", "FIRST_CLASS_KEY", "FIRST_METHOD_KEY", 7),
        ("api/second/", "SECOND_CLASS_KEY", "SECOND_METHOD_KEY", 12),
    ] {
        let trace = run(
            &root,
            &[
                "--format",
                "json",
                "django.endpoint-trace",
                route,
                "--method",
                "GET",
            ],
        );
        assert_success(&trace);
        let trace: serde_json::Value = serde_json::from_slice(&trace.stdout).unwrap();
        let trace = &trace[0];
        assert_eq!(trace["handler"]["line"], expected_line, "trace: {trace}");
        let settings = trace["settings"].to_string();
        assert!(settings.contains(class_key), "trace settings: {settings}");
        assert!(settings.contains(method_key), "trace settings: {settings}");
    }
}

#[test]
fn routers_keep_registration_identity_across_distinct_mounts() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import include, path\nfrom rest_framework.routers import DefaultRouter\n\nclass UserViewSet:\n    pass\n\nclass GroupViewSet:\n    pass\n\nrouter = DefaultRouter()\nadmin_router = DefaultRouter()\nrouter.register('users', UserViewSet)\nadmin_router.register('groups', GroupViewSet)\nurlpatterns = [path('api/', include(router.urls)), path('admin/', include(admin_router.urls))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut collection_routes: Vec<_> = routes
        .as_array()
        .unwrap()
        .iter()
        .filter(|route| route["method"].is_null())
        .map(|route| route["path_pattern"].as_str().unwrap())
        .collect();
    collection_routes.sort_unstable();
    assert_eq!(collection_routes, ["admin/groups/", "api/users/"]);
}

#[test]
fn endpoint_trace_uses_the_dispatched_viewset_serializer_in_a_shared_file() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/models.py"),
        "class FirstModel:\n    pass\n\nclass SecondModel:\n    pass\n",
    );
    write(
        &root.join("app/serializers.py"),
        "from .models import FirstModel, SecondModel\n\nclass FirstSerializer(ModelSerializer):\n    class Meta:\n        model = FirstModel\n\nclass SecondSerializer(ModelSerializer):\n    class Meta:\n        model = SecondModel\n",
    );
    write(
        &root.join("app/views.py"),
        "from .serializers import FirstSerializer, SecondSerializer\n\nclass FirstViewSet:\n    serializer_class = FirstSerializer\n\n    def list(self, request):\n        pass\n\nclass SecondViewSet:\n    serializer_class = SecondSerializer\n\n    def list(self, request):\n        pass\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import path\nfrom .views import FirstViewSet, SecondViewSet\nurlpatterns = [path('first/', FirstViewSet.as_view({'get': 'list'})), path('second/', SecondViewSet.as_view({'get': 'list'}))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(
        &root,
        &[
            "--format",
            "json",
            "django.endpoint-trace",
            "second/",
            "--method",
            "GET",
        ],
    );
    assert_success(&output);
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let trace = &trace[0];
    assert_eq!(trace["handler"]["line"], 12, "trace: {trace}");
    assert_eq!(
        trace["serializer"]["name"], "SecondSerializer",
        "trace: {trace}"
    );
    assert_eq!(trace["model"]["name"], "SecondModel", "trace: {trace}");
}

#[test]
fn django_rebuild_deduplicates_resolved_handler_serializer_pairs() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let _environment = CacheEnvironment::set(&temp.path().join("cache"));

    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/serializers.py"),
        "from rest_framework import serializers\n\nclass DefaultSerializer(serializers.Serializer):\n    pass\n\nclass ActionSerializer(serializers.Serializer):\n    pass\n",
    );
    write(
        &root.join("app/views.py"),
        "from rest_framework import viewsets\nfrom rest_framework.decorators import action\nfrom rest_framework.response import Response\nfrom .serializers import ActionSerializer, DefaultSerializer\n\nclass UserViewSet(viewsets.GenericViewSet):\n    serializer_class = DefaultSerializer\n\n    def get_serializer_class(self):\n        if self.action == \"special\":\n            return ActionSerializer\n        return DefaultSerializer\n\n    @action(detail=False, methods=[\"get\"])\n    def special(self, request):\n        return Response([])\n",
    );
    write(
        &root.join("app/urls.py"),
        "from rest_framework.routers import DefaultRouter\nfrom .views import UserViewSet\n\nrouter = DefaultRouter()\nrouter.register(\"users\", UserViewSet, basename=\"user\")\nurlpatterns = router.urls\n",
    );

    let assert_relations = |conn: &Connection| {
        let handler_id: i64 = conn
            .query_row(
                "SELECT id FROM symbols WHERE name = ?1",
                ["UserViewSet"],
                |row| row.get(0),
            )
            .unwrap();
        let default_serializer_id: i64 = conn
            .query_row(
                "SELECT id FROM symbols WHERE name = ?1",
                ["DefaultSerializer"],
                |row| row.get(0),
            )
            .unwrap();
        let action_serializer_id: i64 = conn
            .query_row(
                "SELECT id FROM symbols WHERE name = ?1",
                ["ActionSerializer"],
                |row| row.get(0),
            )
            .unwrap();

        let relation_count = |serializer_id| {
            conn.query_row(
                "SELECT COUNT(*) FROM django_handler_serializers WHERE handler_symbol_id = ?1 AND serializer_symbol_id = ?2",
                [handler_id, serializer_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(relation_count(default_serializer_id), 1);
        assert_eq!(relation_count(action_serializer_id), 1);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM django_handler_serializers WHERE handler_symbol_id = ?1",
                [handler_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM (SELECT 1 FROM django_handler_serializers GROUP BY handler_symbol_id, serializer_symbol_id HAVING COUNT(*) > 1)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    };

    assert_success(&run(&root, &["rebuild"]));
    let db_path = db::get_db_path(&root).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    assert_relations(&conn);
    drop(conn);

    assert_success(&run(&root, &["rebuild"]));
    let conn = Connection::open(&db_path).unwrap();
    assert_relations(&conn);
}

#[test]
fn repeated_router_mounts_materialize_every_prefix() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import include, path\nfrom rest_framework.decorators import action\nfrom rest_framework.routers import DefaultRouter\n\nclass UserViewSet:\n    @action(detail=False, methods=['get'], url_path='recent')\n    def recent(self, request):\n        pass\n\nrouter = DefaultRouter()\nrouter.register('users', UserViewSet)\nurlpatterns = [path('api/', include(router.urls)), path('v2/', include(router.urls))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let paths: Vec<_> = routes
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|route| route["path_pattern"].as_str())
        .collect();
    assert!(paths.contains(&"api/users/"), "mounted paths: {paths:?}");
    assert!(paths.contains(&"v2/users/"), "mounted paths: {paths:?}");
    assert!(
        paths.contains(&"api/users/recent/"),
        "first mount action missing: {paths:?}"
    );
    assert!(
        paths.contains(&"v2/users/recent/"),
        "repeated mount action missing: {paths:?}"
    );
}

#[test]
fn qualified_serializer_model_resolves_through_its_import_alias() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(&root.join("app_a/models.py"), "class User:\n    pass\n");
    write(&root.join("app_b/models.py"), "class User:\n    pass\n");
    write(
        &root.join("app_a/serializers.py"),
        "from . import models\n\nclass UserSerializer(ModelSerializer):\n    class Meta:\n        model = models.User\n",
    );
    write(
        &root.join("app_a/views.py"),
        "from .serializers import UserSerializer\n\nclass UserViewSet:\n    serializer_class = UserSerializer\n",
    );
    write(
        &root.join("app_a/urls.py"),
        "from django.urls import path\nfrom .views import UserViewSet\nurlpatterns = [path('users/', UserViewSet.as_view({'get': 'list'}))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(
        &root,
        &[
            "--format",
            "json",
            "django.endpoint-trace",
            "users/",
            "--method",
            "GET",
        ],
    );
    assert_success(&output);
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        trace[0]["model"]["path"], "app_a/models.py",
        "trace: {trace}"
    );
}

#[test]
fn relative_import_exact_miss_does_not_link_a_different_app_model() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app_a/models.py"),
        "class LocalOnly:\n    pass\n",
    );
    write(&root.join("app_b/models.py"), "class User:\n    pass\n");
    write(
        &root.join("app_a/serializers.py"),
        "from . import models\n\nclass UserSerializer(ModelSerializer):\n    class Meta:\n        model = models.User\n",
    );
    write(
        &root.join("app_a/views.py"),
        "from .serializers import UserSerializer\n\nclass UserViewSet:\n    serializer_class = UserSerializer\n",
    );
    write(
        &root.join("app_a/urls.py"),
        "from django.urls import path\nfrom .views import UserViewSet\nurlpatterns = [path('users/', UserViewSet.as_view({'get': 'list'}))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(
        &root,
        &[
            "--format",
            "json",
            "django.endpoint-trace",
            "users/",
            "--method",
            "GET",
        ],
    );
    assert_success(&output);
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        trace[0]["model"].is_null(),
        "cross-app model leaked: {trace}"
    );
}

#[test]
fn multiline_action_is_materialized_while_commented_action_is_ignored() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import include, path\nfrom rest_framework.decorators import action\nfrom rest_framework.routers import DefaultRouter\n\nclass UserViewSet:\n    # @action(detail=False, methods=['get'], url_path='ghost')\n    @action(\n        detail=False,\n        methods=['get'],\n        url_path='recent',\n    )\n    def recent(self, request):\n        pass\n\nrouter = DefaultRouter()\nrouter.register('users', UserViewSet)\nurlpatterns = [path('api/', include(router.urls))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let paths = routes.to_string();
    assert!(
        paths.contains("api/users/recent/"),
        "multiline action missing: {paths}"
    );
    assert!(!paths.contains("ghost"), "commented action leaked: {paths}");
}

#[test]
fn unmounted_viewset_action_is_not_published_as_a_route() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/views.py"),
        "from rest_framework.decorators import action\n\nclass UserViewSet:\n    @action(detail=False, methods=['get'], url_path='recent')\n    def recent(self, request):\n        pass\n",
    );
    write(&root.join("app/urls.py"), "urlpatterns = []\n");

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        routes.as_array().unwrap().is_empty(),
        "unmounted action leaked: {routes}"
    );
}

#[test]
fn qualified_router_handler_keeps_import_alias_identity() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app_a/views.py"),
        "class UserViewSet(ReadOnlyModelViewSet):\n    pass\n",
    );
    write(
        &root.join("app_b/views.py"),
        "class UserViewSet:\n    pass\n",
    );
    write(
        &root.join("app_a/urls.py"),
        "from rest_framework.routers import DefaultRouter\nfrom . import views as a_views\n\nrouter = DefaultRouter()\nrouter.register('users', a_views.UserViewSet)\nurlpatterns = [path('api/', include(router.urls))]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(
        &root,
        &["--format", "json", "django.endpoint-trace", "api/users/"],
    );
    assert_success(&output);
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        trace[0]["handler"]["path"], "app_a/views.py",
        "trace: {trace}"
    );

    let routes = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&routes);
    let routes = String::from_utf8(routes.stdout).unwrap();
    assert!(routes.contains("\"method\": \"GET\""), "routes: {routes}");
    assert!(!routes.contains("\"method\": \"POST\""), "routes: {routes}");
}

#[test]
fn direct_router_urlpatterns_honor_readonly_actions_and_ignore_commented_action_args() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from rest_framework.decorators import action\nfrom rest_framework.routers import DefaultRouter\n\nclass UserViewSet(ReadOnlyModelViewSet):\n    @action(\n        detail=False,\n        # methods=['post'], url_path='ghost',\n    )\n    def recent(self, request):\n        pass\n\nrouter = DefaultRouter()\nrouter.register('users', UserViewSet)\nurlpatterns = router.urls\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["--format", "json", "django.routes"]);
    assert_success(&output);
    let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let routes = routes.to_string();
    assert!(routes.contains("users/"), "direct router routes: {routes}");
    assert!(
        routes.contains("users/{id}/"),
        "read-only detail route: {routes}"
    );
    assert!(
        routes.contains("users/recent/"),
        "default action route: {routes}"
    );
    for forbidden in ["POST", "PUT", "PATCH", "DELETE", "ghost"] {
        assert!(
            !routes.contains(forbidden),
            "invented route {forbidden}: {routes}"
        );
    }
}

#[test]
fn django_routes_reports_scoped_total_beyond_limit() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );
    write(
        &root.join("app/urls.py"),
        "from django.urls import path\n\nclass One: pass\nclass Two: pass\nclass Three: pass\nurlpatterns = [path('one/', One.as_view()), path('two/', Two.as_view()), path('three/', Three.as_view())]\n",
    );

    assert_success(&run(&root, &["rebuild"]));
    let output = run(&root, &["django.routes", "--limit", "1"]);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("(3 found)"), "routes output: {stdout}");
    assert!(stdout.contains("... and 2 more"), "routes output: {stdout}");
}

#[test]
fn django_json_missing_index_is_parseable_and_fails() {
    let _lock = ENV_SERIAL.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0\"\n",
    );

    for command in [
        vec!["django.routes"],
        vec!["django.endpoint-trace", "missing/"],
        vec!["django.setting-usage", "MISSING_KEY"],
        vec!["django.model-impact", "MissingModel"],
    ] {
        let mut args = vec!["--format", "json"];
        args.extend(command);
        let output = run(&root, &args);
        assert!(!output.status.success(), "missing index must fail");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["error"], "index_not_found");
    }
}
