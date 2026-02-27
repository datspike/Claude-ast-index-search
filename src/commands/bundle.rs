//! Bundle command: deterministic context packages by seed type.
//!
//! Collects related symbols/endpoints/settings into a compact bundle
//! for code review, impact analysis, or framework tracing.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use crate::db;

/// Single item in a bundle
#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleItem {
    pub path: String,
    pub line: i64,
    pub kind: String,
    pub name: Option<String>,
    pub reason: String,
    pub confidence: String,
}

/// Bundle result
#[derive(Debug, Serialize)]
pub struct BundleResult {
    pub seed_type: String,
    pub seed: String,
    pub items: Vec<BundleItem>,
    pub total_before_budget: usize,
    pub files_count: usize,
}

/// Collect bundle for an endpoint seed
pub fn bundle_endpoint(
    conn: &rusqlite::Connection,
    seed: &str,
    method: Option<&str>,
    max_items: usize,
) -> Result<Vec<BundleItem>> {
    let endpoints = db::find_py_endpoint(conn, method, seed)?;
    let mut items = BTreeSet::new();

    for ep in &endpoints {
        // endpoint itself
        items.insert(BundleItem {
            path: ep.file_path.clone(),
            line: ep.line,
            kind: "endpoint".to_string(),
            name: Some(ep.path_pattern.clone()),
            reason: format!(
                "{} {}",
                ep.method.as_deref().unwrap_or("*"),
                ep.path_pattern
            ),
            confidence: ep.confidence.as_deref().unwrap_or("high").to_string(),
        });

        // handler
        if let Ok(Some(handler)) = db::get_py_endpoint_handler(conn, ep.id) {
            items.insert(BundleItem {
                path: handler.path.clone(),
                line: handler.line,
                kind: "handler".to_string(),
                name: Some(handler.name.clone()),
                reason: format!("handler for {}", ep.path_pattern),
                confidence: "high".to_string(),
            });

            // handler symbol_id for serializer/settings lookup
            let handler_sym_id: Option<i64> = conn
                .query_row(
                    "SELECT symbol_id FROM py_endpoint_handlers WHERE endpoint_id = ?1 LIMIT 1",
                    rusqlite::params![ep.id],
                    |row| row.get(0),
                )
                .ok();

            if let Some(h_id) = handler_sym_id {
                // serializer via py_handler_serializers
                if let Ok(Some((ser_id, ser_result, confidence))) =
                    db::get_py_handler_serializer(conn, h_id)
                {
                    items.insert(BundleItem {
                        path: ser_result.path.clone(),
                        line: ser_result.line,
                        kind: "serializer".to_string(),
                        name: Some(ser_result.name.clone()),
                        reason: format!("serializer for {}", handler.name),
                        confidence: confidence.clone(),
                    });

                    // model via py_serializer_models
                    if let Ok(Some(model)) = db::get_py_serializer_model(conn, ser_id) {
                        items.insert(BundleItem {
                            path: model.path.clone(),
                            line: model.line,
                            kind: "model".to_string(),
                            name: Some(model.name.clone()),
                            reason: format!("model for {}", ser_result.name),
                            confidence,
                        });
                    }
                }

                // settings
                if let Ok(settings) = db::get_py_symbol_settings(conn, h_id) {
                    for s in settings {
                        items.insert(BundleItem {
                            path: s.file_path.clone(),
                            line: s.line,
                            kind: "setting".to_string(),
                            name: Some(s.key.clone()),
                            reason: format!("{} in {}", s.key_kind, handler.name),
                            confidence: s.confidence.clone(),
                        });
                    }
                }
            }
        }

        if items.len() >= max_items {
            break;
        }
    }

    Ok(items.into_iter().take(max_items).collect())
}

/// Collect bundle for a model seed
pub fn bundle_model(
    conn: &rusqlite::Connection,
    seed: &str,
    max_items: usize,
) -> Result<Vec<BundleItem>> {
    let models = db::find_py_model_symbols(conn, seed, 5)?;
    let mut items = BTreeSet::new();

    for model in &models {
        // model itself
        items.insert(BundleItem {
            path: model.path.clone(),
            line: model.line,
            kind: "model".to_string(),
            name: Some(model.name.clone()),
            reason: "seed model".to_string(),
            confidence: "high".to_string(),
        });

        // serializers
        let serializers = db::find_py_serializers_for_model(conn, &model.name)?;
        for (ser_id, ser_result, confidence) in &serializers {
            items.insert(BundleItem {
                path: ser_result.path.clone(),
                line: ser_result.line,
                kind: "serializer".to_string(),
                name: Some(ser_result.name.clone()),
                reason: format!("serializer for {}", model.name),
                confidence: confidence.clone(),
            });

            // handlers for this serializer
            let handlers = db::find_py_handlers_for_serializer(conn, *ser_id)?;
            for (handler_id, handler_result) in &handlers {
                items.insert(BundleItem {
                    path: handler_result.path.clone(),
                    line: handler_result.line,
                    kind: "handler".to_string(),
                    name: Some(handler_result.name.clone()),
                    reason: format!("handler using {}", ser_result.name),
                    confidence: "high".to_string(),
                });

                // endpoints for this handler
                let endpoints = db::find_py_endpoints_for_handler(conn, *handler_id)?;
                for ep in &endpoints {
                    items.insert(BundleItem {
                        path: ep.file_path.clone(),
                        line: ep.line,
                        kind: "endpoint".to_string(),
                        name: Some(ep.path_pattern.clone()),
                        reason: format!(
                            "{} {} via {}",
                            ep.method.as_deref().unwrap_or("*"),
                            ep.path_pattern,
                            handler_result.name,
                        ),
                        confidence: ep.confidence.as_deref().unwrap_or("high").to_string(),
                    });
                }
            }
        }

        if items.len() >= max_items {
            break;
        }
    }

    Ok(items.into_iter().take(max_items).collect())
}

/// Collect bundle for a setting seed
fn bundle_setting(
    conn: &rusqlite::Connection,
    seed: &str,
    max_items: usize,
) -> Result<Vec<BundleItem>> {
    let usages = db::find_py_setting_usages(conn, seed, max_items)?;
    let mut items = BTreeSet::new();

    for u in &usages {
        // setting usage
        items.insert(BundleItem {
            path: u.file_path.clone(),
            line: u.line,
            kind: "setting".to_string(),
            name: Some(u.key.clone()),
            reason: format!("{} in {}", u.key_kind, u.symbol_name),
            confidence: u.confidence.clone(),
        });

        // symbol that uses the setting (line is the symbol's definition line)
        items.insert(BundleItem {
            path: u.file_path.clone(),
            line: u.line,
            kind: "symbol".to_string(),
            name: Some(u.symbol_name.clone()),
            reason: format!("uses {}", u.key),
            confidence: "high".to_string(),
        });

        // find endpoints for this symbol (if it's a handler)
        if let Ok(endpoints) = db::find_py_endpoints_for_handler(conn, u.symbol_id) {
            for ep in &endpoints {
                items.insert(BundleItem {
                    path: ep.file_path.clone(),
                    line: ep.line,
                    kind: "endpoint".to_string(),
                    name: Some(ep.path_pattern.clone()),
                    reason: format!(
                        "{} {} via {}",
                        ep.method.as_deref().unwrap_or("*"),
                        ep.path_pattern,
                        u.symbol_name,
                    ),
                    confidence: ep.confidence.as_deref().unwrap_or("high").to_string(),
                });
            }
        }

        if items.len() >= max_items {
            break;
        }
    }

    Ok(items.into_iter().take(max_items).collect())
}

/// Collect bundle for a symbol seed
fn bundle_symbol(
    conn: &rusqlite::Connection,
    seed: &str,
    max_items: usize,
) -> Result<Vec<BundleItem>> {
    let symbols = db::find_symbols_by_name(conn, seed, None, 5)?;
    let mut items = BTreeSet::new();

    for sym in &symbols {
        // symbol itself
        items.insert(BundleItem {
            path: sym.path.clone(),
            line: sym.line,
            kind: sym.kind.clone(),
            name: Some(sym.name.clone()),
            reason: "seed symbol".to_string(),
            confidence: "high".to_string(),
        });

        // symbol_id for linking queries
        let sym_id: Option<i64> = conn
            .query_row(
                "SELECT s.id FROM symbols s JOIN files f ON s.file_id = f.id WHERE s.name = ?1 AND f.path = ?2 AND s.line = ?3 LIMIT 1",
                rusqlite::params![sym.name, sym.path, sym.line],
                |row| row.get(0),
            )
            .ok();

        if let Some(s_id) = sym_id {
            // settings
            if let Ok(settings) = db::get_py_symbol_settings(conn, s_id) {
                for s in &settings {
                    items.insert(BundleItem {
                        path: s.file_path.clone(),
                        line: s.line,
                        kind: "setting".to_string(),
                        name: Some(s.key.clone()),
                        reason: format!("{} in {}", s.key_kind, sym.name),
                        confidence: s.confidence.clone(),
                    });
                }
            }

            // endpoints (if this symbol is a handler)
            if let Ok(endpoints) = db::find_py_endpoints_for_handler(conn, s_id) {
                for ep in &endpoints {
                    items.insert(BundleItem {
                        path: ep.file_path.clone(),
                        line: ep.line,
                        kind: "endpoint".to_string(),
                        name: Some(ep.path_pattern.clone()),
                        reason: format!(
                            "{} {} via {}",
                            ep.method.as_deref().unwrap_or("*"),
                            ep.path_pattern,
                            sym.name,
                        ),
                        confidence: ep.confidence.as_deref().unwrap_or("high").to_string(),
                    });
                }
            }

            // serializer -> model (if this symbol is a serializer)
            if let Ok(Some(model)) = db::get_py_serializer_model(conn, s_id) {
                items.insert(BundleItem {
                    path: model.path.clone(),
                    line: model.line,
                    kind: "model".to_string(),
                    name: Some(model.name.clone()),
                    reason: format!("model for {}", sym.name),
                    confidence: "high".to_string(),
                });
            }

            // handler -> serializer (if this symbol is a handler)
            if let Ok(Some((_ser_id, ser_result, confidence))) =
                db::get_py_handler_serializer(conn, s_id)
            {
                items.insert(BundleItem {
                    path: ser_result.path.clone(),
                    line: ser_result.line,
                    kind: "serializer".to_string(),
                    name: Some(ser_result.name.clone()),
                    reason: format!("serializer for {}", sym.name),
                    confidence,
                });
            }
        }

        if items.len() >= max_items {
            break;
        }
    }

    Ok(items.into_iter().take(max_items).collect())
}

/// Apply max-files budget: keep items from top N unique files
fn apply_file_budget(items: Vec<BundleItem>, max_files: usize) -> Vec<BundleItem> {
    if max_files == 0 {
        return items;
    }

    let mut seen_files = BTreeSet::new();
    let mut result = Vec::new();

    for item in items {
        seen_files.insert(item.path.clone());
        if seen_files.len() <= max_files {
            result.push(item);
        }
    }

    result
}

/// Entry point for `ast-index bundle`
pub fn cmd_bundle(
    root: &Path,
    seed_type: &str,
    seed: &str,
    method: Option<&str>,
    max_items: usize,
    max_files: usize,
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

    let all_items = match seed_type {
        "endpoint" => bundle_endpoint(&conn, seed, method, max_items)?,
        "model" => bundle_model(&conn, seed, max_items)?,
        "setting" => bundle_setting(&conn, seed, max_items)?,
        "symbol" => bundle_symbol(&conn, seed, max_items)?,
        _ => {
            eprintln!(
                "{}",
                format!(
                    "Unknown seed type '{}'. Use: endpoint, model, setting, symbol.",
                    seed_type
                )
                .red()
            );
            return Ok(());
        }
    };

    let total_before_budget = all_items.len();
    let items = if max_files > 0 {
        apply_file_budget(all_items, max_files)
    } else {
        all_items
    };

    let files_count = items
        .iter()
        .map(|i| i.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    let result = BundleResult {
        seed_type: seed_type.to_string(),
        seed: seed.to_string(),
        items,
        total_before_budget,
        files_count,
    };

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    println!(
        "{}",
        format!(
            "Bundle for {} '{}' ({} items, {} files):",
            result.seed_type,
            result.seed,
            result.items.len(),
            result.files_count
        )
        .bold()
    );

    if result.items.is_empty() {
        println!("  No items found.");
        eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
        return Ok(());
    }

    for item in &result.items {
        let name_str = item
            .name
            .as_deref()
            .map(|n| format!(" {}", n))
            .unwrap_or_default();
        println!(
            "  [{}]{} {}:{} ({}) [{}]",
            item.kind.cyan(),
            name_str.green(),
            item.path,
            item.line,
            item.reason.dimmed(),
            item.confidence,
        );
    }

    if result.total_before_budget > result.items.len() {
        println!(
            "  {}",
            format!(
                "... {} items trimmed by file budget",
                result.total_before_budget - result.items.len()
            )
            .dimmed()
        );
    }

    eprintln!("\n{}", format!("Time: {:?}", start.elapsed()).dimmed());
    Ok(())
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

    /// Setup a full Django chain: endpoint -> handler -> serializer -> model + settings
    fn setup_django_chain(conn: &Connection) -> (i64, i64, i64, i64, i64) {
        let urls_id = db::upsert_file(conn, "urls.py", 500, 50).unwrap();
        let views_id = db::upsert_file(conn, "views.py", 1000, 100).unwrap();
        let ser_file_id = db::upsert_file(conn, "serializers.py", 800, 80).unwrap();
        let models_id = db::upsert_file(conn, "models.py", 600, 60).unwrap();

        let model_id = db::insert_symbol(
            conn,
            models_id,
            "User",
            SymbolKind::Class,
            10,
            Some("class User(Model)"),
        )
        .unwrap();

        let serializer_id = db::insert_symbol(
            conn,
            ser_file_id,
            "UserSerializer",
            SymbolKind::Class,
            5,
            Some("class UserSerializer(ModelSerializer)"),
        )
        .unwrap();

        let handler_id = db::insert_symbol(
            conn,
            views_id,
            "UserViewSet",
            SymbolKind::Class,
            10,
            Some("class UserViewSet(ModelViewSet)"),
        )
        .unwrap();

        // model -> serializer
        db::insert_py_serializer_model(
            conn,
            serializer_id,
            model_id,
            "high",
            Some("Meta.model = User"),
        )
        .unwrap();

        // handler -> serializer
        db::insert_py_handler_serializer(
            conn,
            handler_id,
            serializer_id,
            "high",
            Some("serializer_class = UserSerializer"),
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

        // setting
        db::insert_py_symbol_setting(
            conn,
            handler_id,
            "PAGE_SIZE",
            "settings",
            "medium",
            Some("settings.PAGE_SIZE"),
        )
        .unwrap();

        (ep_id, handler_id, serializer_id, model_id, urls_id)
    }

    #[test]
    fn test_bundle_endpoint_full_chain() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items = bundle_endpoint(&conn, "users", None, 50).unwrap();

        assert!(!items.is_empty(), "bundle should have items");

        let kinds: Vec<&str> = items.iter().map(|i| i.kind.as_str()).collect();
        assert!(kinds.contains(&"endpoint"), "should contain endpoint");
        assert!(kinds.contains(&"handler"), "should contain handler");
        assert!(kinds.contains(&"serializer"), "should contain serializer");
        assert!(kinds.contains(&"model"), "should contain model");
        assert!(kinds.contains(&"setting"), "should contain setting");
    }

    #[test]
    fn test_bundle_model_chain() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items = bundle_model(&conn, "User", 50).unwrap();

        assert!(!items.is_empty());
        let kinds: Vec<&str> = items.iter().map(|i| i.kind.as_str()).collect();
        assert!(kinds.contains(&"model"));
        assert!(kinds.contains(&"serializer"));
        assert!(kinds.contains(&"handler"));
        assert!(kinds.contains(&"endpoint"));
    }

    #[test]
    fn test_bundle_setting_chain() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items = bundle_setting(&conn, "PAGE_SIZE", 50).unwrap();

        assert!(!items.is_empty());
        let kinds: Vec<&str> = items.iter().map(|i| i.kind.as_str()).collect();
        assert!(kinds.contains(&"setting"));
        assert!(kinds.contains(&"symbol"));
    }

    #[test]
    fn test_bundle_empty_result() {
        let conn = create_test_db();

        let items = bundle_endpoint(&conn, "nonexistent", None, 50).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_bundle_max_items_budget() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items = bundle_endpoint(&conn, "users", None, 2).unwrap();
        assert!(items.len() <= 2, "should respect max_items budget");
    }

    #[test]
    fn test_bundle_file_budget() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items = bundle_endpoint(&conn, "users", None, 50).unwrap();
        let trimmed = apply_file_budget(items, 2);

        let files: BTreeSet<&str> = trimmed.iter().map(|i| i.path.as_str()).collect();
        assert!(files.len() <= 2, "should respect file budget");
    }

    #[test]
    fn test_bundle_deterministic_order() {
        let conn = create_test_db();
        setup_django_chain(&conn);

        let items1 = bundle_endpoint(&conn, "users", None, 50).unwrap();
        let items2 = bundle_endpoint(&conn, "users", None, 50).unwrap();

        assert_eq!(items1, items2, "bundle should be deterministic");
    }
}
