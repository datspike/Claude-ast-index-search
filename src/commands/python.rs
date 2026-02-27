//! Python-specific CLI commands
//!
//! - py.routes: list Django/DRF endpoints
//! - py.endpoint-trace: trace endpoint -> handler -> serializer -> model -> settings
//! - py.setting-usage: find settings/env key usages

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use colored::Colorize;

use crate::db;

/// List Python endpoints (Django/DRF routes)
pub fn cmd_py_routes(root: &Path, query: Option<&str>, limit: usize, format: &str) -> Result<()> {
    let start = Instant::now();

    if !db::db_exists(root) {
        println!(
            "{}",
            "Index not found. Run 'ast-index rebuild' first.".red()
        );
        return Ok(());
    }

    let conn = db::open_db(root)?;
    let total = db::count_py_endpoints(&conn, query)?;
    let endpoints = db::get_py_endpoints(&conn, query, limit)?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&endpoints)?);
        if endpoints.len() < total {
            eprintln!(
                "{}",
                format!(
                    "Showing {} of {} routes. Use --limit {} to show all.",
                    endpoints.len(),
                    total,
                    total
                )
                .dimmed()
            );
        }
        return Ok(());
    }

    println!("{}", format!("Python routes ({} found):", total).bold());

    if endpoints.is_empty() {
        println!("  No routes found. Run 'ast-index rebuild' on a Django/DRF project.");
        eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
        return Ok(());
    }

    for ep in &endpoints {
        let method = ep.method.as_deref().unwrap_or("*");
        let handler = ep.handler_qname.as_deref().unwrap_or("-");
        let confidence = ep
            .confidence
            .as_deref()
            .map(|c| format!(" [{}]", c))
            .unwrap_or_default();
        println!(
            "  {} {} -> {}{}  ({}:{})",
            method.green(),
            ep.path_pattern.yellow(),
            handler,
            confidence.dimmed(),
            ep.file_path,
            ep.line,
        );
    }

    if endpoints.len() < total {
        println!(
            "  {}",
            format!(
                "... and {} more. Use --limit {} to show all.",
                total - endpoints.len(),
                total
            )
            .dimmed()
        );
    }

    eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
    Ok(())
}

/// Trace endpoint -> handler -> serializer -> model -> settings
pub fn cmd_py_endpoint_trace(
    root: &Path,
    method: Option<&str>,
    path_pattern: &str,
    format: &str,
) -> Result<()> {
    let start = Instant::now();

    if !db::db_exists(root) {
        println!(
            "{}",
            "Index not found. Run 'ast-index rebuild' first.".red()
        );
        return Ok(());
    }

    let conn = db::open_db(root)?;
    let endpoints = db::find_py_endpoint(&conn, method, path_pattern)?;

    if endpoints.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            println!("No endpoints found matching the pattern.");
        }
        return Ok(());
    }

    // build trace for each matched endpoint
    let mut traces: Vec<db::PyEndpointTrace> = Vec::new();

    for ep in endpoints {
        let handler = db::get_py_endpoint_handler(&conn, ep.id)?;

        // serializer and model: look up via handler symbol_id
        let handler_symbol_id = get_handler_symbol_id(&conn, ep.id);
        let (serializer, model) = if let Some(h_id) = handler_symbol_id {
            // find serializer linked to handler, then resolve model through py_serializer_models
            find_serializer_model_chain(&conn, h_id)
        } else {
            (None, None)
        };

        let settings = if let Some(h_id) = handler_symbol_id {
            db::get_py_symbol_settings(&conn, h_id).unwrap_or_default()
        } else {
            Vec::new()
        };

        traces.push(db::PyEndpointTrace {
            endpoint: ep,
            handler,
            serializer,
            model,
            settings,
        });
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&traces)?);
        return Ok(());
    }

    for trace in &traces {
        let ep = &trace.endpoint;
        let method_str = ep.method.as_deref().unwrap_or("*");
        println!("{}", format!("{} {}", method_str, ep.path_pattern).bold());
        println!("  defined: {}:{}", ep.file_path, ep.line);

        if let Some(ref h) = trace.handler {
            println!(
                "  handler: {} [{}] {}:{}",
                h.name.green(),
                h.kind,
                h.path,
                h.line
            );
        }

        if let Some(ref s) = trace.serializer {
            println!("  serializer: {} {}:{}", s.name.cyan(), s.path, s.line);
        }

        if let Some(ref m) = trace.model {
            println!("  model: {} {}:{}", m.name.yellow(), m.path, m.line);
        }

        if !trace.settings.is_empty() {
            println!("  settings:");
            for s in &trace.settings {
                let reason_str = s
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                println!(
                    "    {} [{}] {}:{}{}",
                    s.key.yellow(),
                    s.key_kind,
                    s.file_path,
                    s.line,
                    reason_str.dimmed()
                );
            }
        }

        println!();
    }

    eprintln!("{}", format!("Time: {:?}", start.elapsed()).dimmed());
    Ok(())
}

/// Find usages of a settings/env key
pub fn cmd_py_setting_usage(root: &Path, key: &str, limit: usize, format: &str) -> Result<()> {
    let start = Instant::now();

    if !db::db_exists(root) {
        println!(
            "{}",
            "Index not found. Run 'ast-index rebuild' first.".red()
        );
        return Ok(());
    }

    let conn = db::open_db(root)?;
    let usages = db::find_py_setting_usages(&conn, key, limit)?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&usages)?);
        return Ok(());
    }

    println!(
        "{}",
        format!(
            "Settings/env usages for '{}' ({} found):",
            key,
            usages.len()
        )
        .bold()
    );

    if usages.is_empty() {
        println!("  No usages found.");
        eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
        return Ok(());
    }

    for u in &usages {
        let reason_str = u
            .reason
            .as_deref()
            .map(|r| format!(" ({})", r))
            .unwrap_or_default();
        println!(
            "  {} [{}] in {} -> {}:{}{}",
            u.key.yellow(),
            u.key_kind,
            u.symbol_name.green(),
            u.file_path,
            u.line,
            reason_str.dimmed()
        );
    }

    eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
    Ok(())
}

/// Blast radius for a model: model -> serializers -> handlers -> endpoints
pub fn cmd_py_model_impact(root: &Path, name: &str, limit: usize, format: &str) -> Result<()> {
    let start = Instant::now();

    if !db::db_exists(root) {
        println!(
            "{}",
            "Index not found. Run 'ast-index rebuild' first.".red()
        );
        return Ok(());
    }

    let conn = db::open_db(root)?;
    let models = db::find_py_model_symbols(&conn, name, limit)?;

    if models.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            println!("No model '{}' found in the index.", name);
        }
        return Ok(());
    }

    let mut impacts: Vec<db::PyModelImpact> = Vec::new();

    for model in models {
        let serializers_raw = db::find_py_serializers_for_model(&conn, &model.name)?;

        let mut serializers = Vec::new();
        for (ser_id, ser_result, confidence) in serializers_raw {
            let handlers_raw = db::find_py_handlers_for_serializer(&conn, ser_id)?;

            let mut handlers = Vec::new();
            for (handler_id, handler_result) in handlers_raw {
                let endpoints = db::find_py_endpoints_for_handler(&conn, handler_id)?;
                handlers.push(db::PyModelHandlerImpact {
                    handler: handler_result,
                    endpoints,
                });
            }

            serializers.push(db::PyModelSerializerImpact {
                serializer: ser_result,
                confidence,
                handlers,
            });
        }

        impacts.push(db::PyModelImpact { model, serializers });
    }

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&impacts)?);
        return Ok(());
    }

    for impact in &impacts {
        println!(
            "{}",
            format!(
                "Model: {} ({}:{})",
                impact.model.name, impact.model.path, impact.model.line
            )
            .bold()
        );

        if impact.serializers.is_empty() {
            println!("  (no serializers found)");
            println!();
            continue;
        }

        for ser in &impact.serializers {
            println!(
                "  serializer: {} [{}] {}:{}",
                ser.serializer.name.cyan(),
                ser.confidence,
                ser.serializer.path,
                ser.serializer.line,
            );

            if ser.handlers.is_empty() {
                println!("    (no handlers found)");
                continue;
            }

            for h in &ser.handlers {
                println!(
                    "    handler: {} {}:{}",
                    h.handler.name.green(),
                    h.handler.path,
                    h.handler.line,
                );

                for ep in &h.endpoints {
                    let method = ep.method.as_deref().unwrap_or("*");
                    println!(
                        "      {} {} ({}:{})",
                        method.yellow(),
                        ep.path_pattern,
                        ep.file_path,
                        ep.line,
                    );
                }

                if h.endpoints.is_empty() {
                    println!("      (no endpoints found)");
                }
            }
        }
        println!();
    }

    eprintln!("{}", format!("Time: {:?}", start.elapsed()).dimmed());
    Ok(())
}

/// Get handler symbol_id for an endpoint
fn get_handler_symbol_id(conn: &rusqlite::Connection, endpoint_id: i64) -> Option<i64> {
    conn.query_row(
        "SELECT symbol_id FROM py_endpoint_handlers WHERE endpoint_id = ?1 LIMIT 1",
        rusqlite::params![endpoint_id],
        |row| row.get(0),
    )
    .ok()
}

/// Find serializer -> model chain for a handler symbol_id.
///
/// Strategy: py_handler_serializers (direct link) first, then refs-based fallback.
fn find_serializer_model_chain(
    conn: &rusqlite::Connection,
    handler_symbol_id: i64,
) -> (Option<db::SearchResult>, Option<db::SearchResult>) {
    // Primary: py_handler_serializers (direct link from serializer_class = X)
    if let Ok(Some((ser_id, ser_result, _confidence))) =
        db::get_py_handler_serializer(conn, handler_symbol_id)
    {
        let model = db::get_py_serializer_model(conn, ser_id).unwrap_or(None);
        return (Some(ser_result), model);
    }

    // Fallback: refs-based search (serializer mentioned in handler's file)
    let handler_refs: Vec<(String, i64)> = conn
        .prepare(
            r#"
            SELECT r.name, s.id
            FROM refs r
            JOIN symbols s ON s.name = r.name AND s.kind = 'class'
            JOIN files f ON s.file_id = f.id
            WHERE r.file_id = (SELECT file_id FROM symbols WHERE id = ?1 LIMIT 1)
            AND EXISTS (
                SELECT 1 FROM py_serializer_models sm WHERE sm.serializer_symbol_id = s.id
            )
            LIMIT 5
            "#,
        )
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params![handler_symbol_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();

    if let Some((_name, serializer_id)) = handler_refs.first() {
        let serializer = conn
            .query_row(
                r#"
                SELECT s.name, s.kind, s.line, s.signature, f.path
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE s.id = ?1
                "#,
                rusqlite::params![serializer_id],
                |row| {
                    Ok(db::SearchResult {
                        name: row.get(0)?,
                        kind: row.get(1)?,
                        line: row.get(2)?,
                        signature: row.get(3)?,
                        path: row.get(4)?,
                    })
                },
            )
            .ok();

        let model = db::get_py_serializer_model(conn, *serializer_id).unwrap_or(None);
        (serializer, model)
    } else {
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, SymbolKind};
    use rusqlite::Connection;

    fn create_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn).unwrap();
        conn
    }

    /// Helper: set up full test data for endpoint-trace
    fn setup_full_trace(conn: &Connection) -> (i64, i64, i64, i64) {
        let urls_id = db::upsert_file(conn, "urls.py", 500, 50).unwrap();
        let views_id = db::upsert_file(conn, "views.py", 1000, 100).unwrap();
        let ser_file_id = db::upsert_file(conn, "serializers.py", 800, 80).unwrap();

        // handler symbol
        let handler_id = db::insert_symbol(
            conn,
            views_id,
            "UserViewSet",
            SymbolKind::Class,
            5,
            Some("class UserViewSet(ModelViewSet)"),
        )
        .unwrap();

        // serializer symbol
        let serializer_id = db::insert_symbol(
            conn,
            ser_file_id,
            "UserSerializer",
            SymbolKind::Class,
            10,
            Some("class UserSerializer(ModelSerializer)"),
        )
        .unwrap();

        // model symbol
        let model_id = db::insert_symbol(
            conn,
            views_id,
            "User",
            SymbolKind::Class,
            50,
            Some("class User(Model)"),
        )
        .unwrap();

        // endpoint
        let ep_id = db::insert_py_endpoint(
            conn,
            Some("GET"),
            "/api/v1/users/",
            urls_id,
            3,
            Some("UserViewSet"),
        )
        .unwrap();

        // endpoint -> handler
        db::insert_py_endpoint_handler(conn, ep_id, handler_id, "high", Some("router.register"))
            .unwrap();

        // serializer -> model
        db::insert_py_serializer_model(
            conn,
            serializer_id,
            model_id,
            "high",
            Some("Meta.model = User"),
        )
        .unwrap();

        // handler refs -> UserSerializer (simulating ref in the same file)
        conn.execute(
            "INSERT INTO refs (file_id, name, line, context) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                views_id,
                "UserSerializer",
                8,
                "serializer_class = UserSerializer"
            ],
        )
        .unwrap();

        // settings for handler
        db::insert_py_symbol_setting(
            conn,
            handler_id,
            "API_PAGE_SIZE",
            "settings",
            "medium",
            Some("settings.API_PAGE_SIZE"),
        )
        .unwrap();

        (ep_id, handler_id, serializer_id, model_id)
    }

    #[test]
    fn test_get_handler_symbol_id() {
        let conn = create_test_db();
        let file_id = db::upsert_file(&conn, "views.py", 1000, 100).unwrap();
        let sym_id = db::insert_symbol(
            &conn,
            file_id,
            "MyView",
            SymbolKind::Class,
            5,
            Some("class MyView"),
        )
        .unwrap();
        let ep_id =
            db::insert_py_endpoint(&conn, Some("GET"), "/test/", file_id, 10, Some("MyView"))
                .unwrap();
        db::insert_py_endpoint_handler(&conn, ep_id, sym_id, "high", None).unwrap();

        let result = get_handler_symbol_id(&conn, ep_id);
        assert_eq!(result, Some(sym_id));
    }

    #[test]
    fn test_get_handler_symbol_id_missing() {
        let conn = create_test_db();
        let result = get_handler_symbol_id(&conn, 999);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_serializer_model_chain() {
        let conn = create_test_db();
        let (_, handler_id, _, _) = setup_full_trace(&conn);

        let (serializer, model) = find_serializer_model_chain(&conn, handler_id);

        assert!(
            serializer.is_some(),
            "serializer should be found via handler refs"
        );
        assert_eq!(serializer.unwrap().name, "UserSerializer");

        assert!(
            model.is_some(),
            "model should be found via py_serializer_models"
        );
        assert_eq!(model.unwrap().name, "User");
    }

    #[test]
    fn test_find_serializer_model_chain_no_refs() {
        let conn = create_test_db();
        let file_id = db::upsert_file(&conn, "views.py", 1000, 100).unwrap();
        let handler_id = db::insert_symbol(
            &conn,
            file_id,
            "SimpleView",
            SymbolKind::Class,
            5,
            Some("class SimpleView(APIView)"),
        )
        .unwrap();

        // no refs -> no serializer/model
        let (serializer, model) = find_serializer_model_chain(&conn, handler_id);
        assert!(serializer.is_none());
        assert!(model.is_none());
    }

    #[test]
    fn test_py_routes_query() {
        let conn = create_test_db();
        let file_id = db::upsert_file(&conn, "urls.py", 500, 50).unwrap();

        db::insert_py_endpoint(
            &conn,
            Some("GET"),
            "/api/v1/users/",
            file_id,
            3,
            Some("UserViewSet"),
        )
        .unwrap();
        db::insert_py_endpoint(
            &conn,
            Some("POST"),
            "/api/v1/orders/",
            file_id,
            5,
            Some("OrderViewSet"),
        )
        .unwrap();
        db::insert_py_endpoint(&conn, None, "/health/", file_id, 7, None).unwrap();

        let routes = db::get_py_endpoints(&conn, None, 100).unwrap();
        assert_eq!(routes.len(), 3);
        // sorted by path_pattern, method
        assert_eq!(routes[0].path_pattern, "/api/v1/orders/");
        assert_eq!(routes[1].path_pattern, "/api/v1/users/");
        assert_eq!(routes[2].path_pattern, "/health/");
    }

    #[test]
    fn test_py_setting_search() {
        let conn = create_test_db();
        let file_id = db::upsert_file(&conn, "views.py", 1000, 100).unwrap();
        let sym_id = db::insert_symbol(
            &conn,
            file_id,
            "get_config",
            SymbolKind::Function,
            5,
            Some("def get_config()"),
        )
        .unwrap();

        db::insert_py_symbol_setting(
            &conn,
            sym_id,
            "DATABASE_URL",
            "env",
            "high",
            Some("os.getenv('DATABASE_URL')"),
        )
        .unwrap();
        db::insert_py_symbol_setting(
            &conn,
            sym_id,
            "DATABASE_HOST",
            "settings",
            "medium",
            Some("settings.DATABASE_HOST"),
        )
        .unwrap();

        // substring search for DATABASE
        let usages = db::find_py_setting_usages(&conn, "DATABASE", 100).unwrap();
        assert_eq!(usages.len(), 2);

        // exact match
        let usages = db::find_py_setting_usages(&conn, "DATABASE_URL", 100).unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].key_kind, "env");
    }

    #[test]
    fn test_endpoint_trace_full_chain() {
        let conn = create_test_db();
        let (ep_id, handler_id, _, _) = setup_full_trace(&conn);

        // verify each step of the trace
        let handler = db::get_py_endpoint_handler(&conn, ep_id).unwrap();
        assert!(handler.is_some());
        assert_eq!(handler.unwrap().name, "UserViewSet");

        let h_id = get_handler_symbol_id(&conn, ep_id).unwrap();
        assert_eq!(h_id, handler_id);

        let (serializer, model) = find_serializer_model_chain(&conn, h_id);
        assert!(serializer.is_some());
        assert!(model.is_some());

        let settings = db::get_py_symbol_settings(&conn, h_id).unwrap();
        assert_eq!(settings.len(), 1);
        assert_eq!(settings[0].key, "API_PAGE_SIZE");
    }
}
