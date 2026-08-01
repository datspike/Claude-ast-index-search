//! Django/DRF-specific CLI commands
//!
//! - django.routes: list Django/DRF endpoints
//! - django.endpoint-trace: trace endpoint -> handler -> serializer -> model -> settings
//! - django.setting-usage: find settings/env key usages

use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::commands::PathResolver;
use crate::db;

/// Acquire a graph query connection without opening migrations or issuing DDL.
///
/// `None` means the index itself is absent; a partial legacy graph gets an
/// explicit user-facing response instead of silently producing EOF on stdout.
fn require_django_index(root: &Path, format: &str) -> Result<()> {
    if db::db_exists(root) {
        return Ok(());
    }

    let message = "Index not found. Run 'ast-index rebuild' first.";
    if format == "json" {
        println!(
            "{}",
            serde_json::json!({ "error": "index_not_found", "message": message })
        );
    } else {
        println!("{}", message.red());
    }
    anyhow::bail!(message)
}

fn open_django_db(root: &Path, format: &str) -> Result<Option<db::LeasedConnection>> {
    let Some(conn) = db::open_existing_db_read_only_leased(root)? else {
        return Ok(None);
    };
    if !db::django_graph_schema_exists(&conn)? {
        let message = "Django graph schema is incomplete. Run 'ast-index rebuild' or 'ast-index update' to upgrade the index.";
        if format == "json" {
            println!(
                "{}",
                serde_json::json!({ "error": "django_graph_schema_missing", "message": message })
            );
        } else {
            println!("{message}");
        }
        return Ok(None);
    }
    Ok(Some(conn))
}

/// List Django/DRF endpoints (Django/DRF routes)
pub fn cmd_django_routes(
    root: &Path,
    query: Option<&str>,
    limit: usize,
    format: &str,
) -> Result<()> {
    require_django_index(root, format)?;

    let Some(conn) = open_django_db(root, format)? else {
        return Ok(());
    };
    let path_resolver = PathResolver::from_conn(root, &conn);
    // Scope first. Applying LIMIT in SQL before this filter makes a named
    // subtree disappear behind unrelated primary-root rows.
    let root_path = path_resolver.active_root_path();
    let endpoints = db::get_django_endpoints(&conn, query, root_path, limit)?;
    let total = db::count_django_endpoints(&conn, query, root_path)?;

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

    println!("{}", format!("Django/DRF routes ({} found):", total).bold());

    if endpoints.is_empty() {
        println!("  No routes found. Run 'ast-index rebuild' on a Django/DRF project.");
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
            path_resolver.resolve_with_root(&ep.file_path, ep.root_path.as_deref()),
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

    Ok(())
}

/// Trace endpoint -> handler -> serializer -> model -> settings
pub fn cmd_django_endpoint_trace(
    root: &Path,
    method: Option<&str>,
    path_pattern: &str,
    format: &str,
) -> Result<()> {
    require_django_index(root, format)?;

    let Some(conn) = open_django_db(root, format)? else {
        return Ok(());
    };
    let endpoints = db::find_django_endpoint(&conn, method, path_pattern)?;
    let path_resolver = PathResolver::from_conn(root, &conn);
    let endpoints: Vec<_> = endpoints
        .into_iter()
        .filter(|ep| path_resolver.matches_filter(ep.root_path.as_deref()))
        .collect();

    if endpoints.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            println!("No endpoints found matching the pattern.");
        }
        return Ok(());
    }

    let mut traces: Vec<db::DjangoEndpointTrace> = Vec::new();

    for ep in endpoints {
        let handler = db::get_django_endpoint_handler(&conn, ep.id)?;
        let handler_symbol_id = db::find_django_endpoint_handler_symbol_id(&conn, ep.id);
        let owner_symbol_id = handler.as_ref().and_then(|h| {
            find_owner_handler_symbol_id(
                &conn,
                ep.handler_qname.as_deref(),
                &h.path,
                h.root_path.as_deref(),
            )
        });
        let (serializer, model) =
            find_serializer_model_chain(&conn, handler_symbol_id, owner_symbol_id);
        let settings = find_endpoint_settings(&conn, handler_symbol_id, owner_symbol_id);

        traces.push(db::DjangoEndpointTrace {
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
        println!(
            "  defined: {}:{}",
            path_resolver.resolve_with_root(&ep.file_path, ep.root_path.as_deref()),
            ep.line
        );

        if let Some(ref h) = trace.handler {
            println!(
                "  handler: {} [{}] {}:{}",
                h.name.green(),
                h.kind,
                path_resolver.resolve_with_root(&h.path, h.root_path.as_deref()),
                h.line
            );
        }

        if let Some(ref s) = trace.serializer {
            println!(
                "  serializer: {} {}:{}",
                s.name.cyan(),
                path_resolver.resolve_with_root(&s.path, s.root_path.as_deref()),
                s.line
            );
        }

        if let Some(ref m) = trace.model {
            println!(
                "  model: {} {}:{}",
                m.name.yellow(),
                path_resolver.resolve_with_root(&m.path, m.root_path.as_deref()),
                m.line
            );
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
                    path_resolver.resolve_with_root(&s.file_path, s.root_path.as_deref()),
                    s.line,
                    reason_str.dimmed()
                );
            }
        }

        println!();
    }

    Ok(())
}

/// Find usages of a settings/env key
pub fn cmd_django_setting_usage(root: &Path, key: &str, limit: usize, format: &str) -> Result<()> {
    require_django_index(root, format)?;

    let Some(conn) = open_django_db(root, format)? else {
        return Ok(());
    };
    let path_resolver = PathResolver::from_conn(root, &conn);
    let usages =
        db::find_django_setting_usages(&conn, key, path_resolver.active_root_path(), limit)?;

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
            path_resolver.resolve_with_root(&u.file_path, u.root_path.as_deref()),
            u.line,
            reason_str.dimmed()
        );
    }

    Ok(())
}

/// Blast radius for a model: model -> serializers -> handlers -> endpoints
pub fn cmd_django_model_impact(root: &Path, name: &str, limit: usize, format: &str) -> Result<()> {
    require_django_index(root, format)?;

    let Some(conn) = open_django_db(root, format)? else {
        return Ok(());
    };
    let path_resolver = PathResolver::from_conn(root, &conn);
    let models =
        db::find_django_model_symbols(&conn, name, path_resolver.active_root_path(), limit)?;

    if models.is_empty() {
        if format == "json" {
            println!("[]");
        } else {
            println!("No model '{}' found in the index.", name);
        }
        return Ok(());
    }

    let mut impacts: Vec<db::DjangoModelImpact> = Vec::new();

    for (model_id, model) in models {
        let serializers_raw = db::find_django_serializers_for_model(&conn, model_id)?;

        let mut serializers = Vec::new();
        for (ser_id, ser_result, confidence) in serializers_raw {
            let handlers_raw = db::find_django_handlers_for_serializer(&conn, ser_id)?;

            let mut handlers = Vec::new();
            for (handler_id, handler_result) in handlers_raw {
                let endpoints = db::find_django_endpoints_for_handler(&conn, handler_id)?;
                handlers.push(db::DjangoModelHandlerImpact {
                    handler: handler_result,
                    endpoints,
                });
            }

            serializers.push(db::DjangoModelSerializerImpact {
                serializer: ser_result,
                confidence,
                handlers,
            });
        }

        impacts.push(db::DjangoModelImpact { model, serializers });
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
                impact.model.name,
                path_resolver
                    .resolve_with_root(&impact.model.path, impact.model.root_path.as_deref()),
                impact.model.line
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
                path_resolver
                    .resolve_with_root(&ser.serializer.path, ser.serializer.root_path.as_deref()),
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
                    path_resolver
                        .resolve_with_root(&h.handler.path, h.handler.root_path.as_deref()),
                    h.handler.line,
                );

                for ep in &h.endpoints {
                    let method = ep.method.as_deref().unwrap_or("*");
                    println!(
                        "      {} {} ({}:{})",
                        method.yellow(),
                        ep.path_pattern,
                        path_resolver.resolve_with_root(&ep.file_path, ep.root_path.as_deref()),
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

    Ok(())
}

fn find_owner_handler_symbol_id(
    conn: &rusqlite::Connection,
    handler_qname: Option<&str>,
    handler_path: &str,
    handler_root_path: Option<&str>,
) -> Option<i64> {
    let owner_name = handler_qname?.split('.').next()?.trim();
    if owner_name.is_empty() {
        return None;
    }

    db::find_django_owner_class_symbol(conn, owner_name, handler_path, handler_root_path)
}

fn find_serializer_model_chain_for_symbol(
    conn: &rusqlite::Connection,
    handler_symbol_id: i64,
) -> (Option<db::SearchResult>, Option<db::SearchResult>) {
    if let Ok(Some((ser_id, ser_result, _confidence))) =
        db::get_django_handler_serializer(conn, handler_symbol_id)
    {
        let model = db::get_django_serializer_model(conn, ser_id).unwrap_or(None);
        return (Some(ser_result), model);
    }

    let handler_refs = db::find_django_serializer_refs_for_handler(conn, handler_symbol_id);
    if let Some((_name, serializer_id)) = handler_refs.first() {
        let serializer = db::get_django_symbol(conn, *serializer_id);
        let model = db::get_django_serializer_model(conn, *serializer_id).unwrap_or(None);
        (serializer, model)
    } else {
        (None, None)
    }
}

/// Find serializer -> model chain for a handler symbol_id.
///
/// A dispatched ViewSet method has a class-owned `serializer_class`. Resolve
/// direct links before any refs fallback: refs are lexical and must never let
/// another ViewSet in the same file donate its serializer to this endpoint.
fn find_serializer_model_chain(
    conn: &rusqlite::Connection,
    handler_symbol_id: Option<i64>,
    owner_symbol_id: Option<i64>,
) -> (Option<db::SearchResult>, Option<db::SearchResult>) {
    for symbol_id in [handler_symbol_id, owner_symbol_id].into_iter().flatten() {
        if let Ok(Some((serializer_id, serializer, _confidence))) =
            db::get_django_handler_serializer(conn, symbol_id)
        {
            let model = db::get_django_serializer_model(conn, serializer_id).unwrap_or(None);
            return (Some(serializer), model);
        }
    }

    if let Some(handler_symbol_id) = handler_symbol_id {
        let result = find_serializer_model_chain_for_symbol(conn, handler_symbol_id);
        if result.0.is_some() || result.1.is_some() {
            return result;
        }
    }

    if let Some(owner_symbol_id) = owner_symbol_id {
        return find_serializer_model_chain_for_symbol(conn, owner_symbol_id);
    }

    (None, None)
}

fn find_endpoint_settings(
    conn: &rusqlite::Connection,
    handler_symbol_id: Option<i64>,
    owner_symbol_id: Option<i64>,
) -> Vec<db::DjangoSettingUsage> {
    let mut settings = owner_symbol_id
        .and_then(|symbol_id| db::get_django_symbol_settings(conn, symbol_id).ok())
        .unwrap_or_default();
    if let Some(handler_symbol_id) = handler_symbol_id {
        settings
            .extend(db::get_django_symbol_settings(conn, handler_symbol_id).unwrap_or_default());
    }
    settings.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then(left.line.cmp(&right.line))
            .then(left.symbol_id.cmp(&right.symbol_id))
    });
    settings.dedup_by(|left, right| {
        left.symbol_id == right.symbol_id
            && left.key == right.key
            && left.key_kind == right.key_kind
            && left.line == right.line
    });
    settings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer;
    use tempfile::TempDir;

    #[test]
    fn endpoint_trace_falls_back_to_owner_viewset_for_action_serializer_and_settings() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("app")).unwrap();
        std::fs::write(dir.path().join("app/models.py"), "class User:\n    pass\n").unwrap();
        std::fs::write(
            dir.path().join("app/serializers.py"),
            "from .models import User\n\nclass UserSerializer:\n    class Meta:\n        model = User\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("app/views.py"),
            "from django.conf import settings\nfrom .serializers import UserSerializer\n\nclass UserViewSet:\n    serializer_class = UserSerializer\n\n    def list(self, request):\n        return settings.USER_API_URL\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("app/urls.py"),
            "from .views import UserViewSet\nurlpatterns = [path('users/', UserViewSet.as_view({'get': 'list'})),]\n",
        )
        .unwrap();

        let mut conn = db::open_db(dir.path()).unwrap();
        db::init_db(&conn).unwrap();
        indexer::index_directory(&mut conn, dir.path(), false, true).unwrap();
        indexer::extract_django_facts(&mut conn, dir.path(), false).unwrap();

        let endpoints = db::find_django_endpoint(&conn, Some("GET"), "users").unwrap();
        let ep = endpoints.into_iter().next().unwrap();
        let handler = db::get_django_endpoint_handler(&conn, ep.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            handler.name, "list",
            "as_view action must retain the dispatched method"
        );
        let handler_symbol_id = db::find_django_endpoint_handler_symbol_id(&conn, ep.id);
        let owner_symbol_id = find_owner_handler_symbol_id(
            &conn,
            ep.handler_qname.as_deref(),
            &handler.path,
            handler.root_path.as_deref(),
        );

        let (serializer, model) =
            find_serializer_model_chain(&conn, handler_symbol_id, owner_symbol_id);
        let settings = find_endpoint_settings(&conn, handler_symbol_id, owner_symbol_id);

        assert_eq!(
            serializer.as_ref().map(|s| s.name.as_str()),
            Some("UserSerializer")
        );
        assert_eq!(model.as_ref().map(|m| m.name.as_str()), Some("User"));
        assert!(settings.iter().any(|s| s.key == "USER_API_URL"));
    }
}
