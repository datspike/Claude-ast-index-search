//! Tree-sitter based Python parser

use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use tree_sitter::{Language, Query, QueryCursor, StreamingIterator};

use super::{line_text, node_line, node_text, parse_tree, LanguageParser};
use crate::db::SymbolKind;
use crate::parsers::{truncate_context, ParsedRef, ParsedSymbol};

static PY_LANGUAGE: LazyLock<Language> = LazyLock::new(|| tree_sitter_python::LANGUAGE.into());

static PY_QUERY: LazyLock<Query> = LazyLock::new(|| {
    Query::new(&PY_LANGUAGE, include_str!("queries/python.scm"))
        .expect("Failed to compile Python tree-sitter query")
});

pub static PYTHON_PARSER: PythonParser = PythonParser;

pub struct PythonParser;

/// Python keywords to filter out false-positive refs
static PY_KEYWORDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "if",
        "else",
        "elif",
        "while",
        "for",
        "do",
        "try",
        "except",
        "finally",
        "return",
        "break",
        "continue",
        "raise",
        "is",
        "in",
        "as",
        "not",
        "and",
        "or",
        "True",
        "False",
        "None",
        "pass",
        "with",
        "yield",
        "assert",
        "del",
        "global",
        "nonlocal",
        "lambda",
        "from",
        "import",
        "class",
        "def",
        "async",
        "await",
        "print",
        "len",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "list",
        "dict",
        "set",
        "tuple",
        "int",
        "str",
        "float",
        "bool",
        "bytes",
        "type",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "super",
        "property",
        "staticmethod",
        "classmethod",
        "object",
        "self",
        "cls",
        // standard types that create noise
        "Exception",
        "ValueError",
        "TypeError",
        "KeyError",
        "AttributeError",
        "RuntimeError",
        "NotImplementedError",
        "StopIteration",
        "OSError",
    ]
    .into_iter()
    .collect()
});

/// Regex for function calls: snake_case, _private, CamelCase
/// Matches: func_name(, _private(, ClassName(
static PY_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap());

/// Regex for dot-call methods: obj.method(, self._method(
/// Group 1 is the method name
static PY_METHOD_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap());

/// Regex for CamelCase identifiers (types, classes) without call parentheses
static PY_TYPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Z][a-zA-Z0-9]*)\b").unwrap());

impl LanguageParser for PythonParser {
    fn extract_refs(&self, content: &str, defined: &[ParsedSymbol]) -> Result<Vec<ParsedRef>> {
        let mut refs = Vec::new();
        let defined_names: HashSet<&str> = defined
            .iter()
            .filter(|s| s.kind != SymbolKind::Import)
            .map(|s| s.name.as_str())
            .collect();
        let keywords = &*PY_KEYWORDS;

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // skip long lines (minified/generated)
            if trimmed.len() > 2000 {
                continue;
            }

            // skip import/from lines
            if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                continue;
            }

            // skip comments
            if trimmed.starts_with('#') {
                continue;
            }

            // skip def/class definitions - filter out the defined name itself,
            // but keep arguments and line body
            let is_def_line = trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ");

            // CamelCase types
            for caps in PY_TYPE_RE.captures_iter(line) {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !name.is_empty() && !keywords.contains(name) && !defined_names.contains(name) {
                    refs.push(ParsedRef {
                        name: name.to_string(),
                        line: line_num,
                        context: truncate_context(trimmed),
                    });
                }
            }

            // direct function calls: func_name(, _private(
            for caps in PY_CALL_RE.captures_iter(line) {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if name.is_empty() || keywords.contains(name) || defined_names.contains(name) {
                    continue;
                }
                // on def line, skip the name being defined
                if is_def_line && trimmed.contains(&format!("def {name}")) {
                    continue;
                }
                if name.len() > 2 {
                    refs.push(ParsedRef {
                        name: name.to_string(),
                        line: line_num,
                        context: truncate_context(trimmed),
                    });
                }
            }

            // dot-call methods: self._method(, obj.method(
            // do NOT filter defined_names -- self._method() is a ref even if defined in the same file
            for caps in PY_METHOD_CALL_RE.captures_iter(line) {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if name.is_empty() || keywords.contains(name) {
                    continue;
                }
                if name.len() > 2 {
                    refs.push(ParsedRef {
                        name: name.to_string(),
                        line: line_num,
                        context: truncate_context(trimmed),
                    });
                }
            }
        }

        Ok(refs)
    }

    fn parse_symbols(&self, content: &str) -> Result<Vec<ParsedSymbol>> {
        let tree = parse_tree(content, &PY_LANGUAGE)?;
        let mut symbols = Vec::new();
        let query = &*PY_QUERY;
        let mut cursor = QueryCursor::new();

        let capture_names = query.capture_names();
        let idx = |name: &str| -> Option<u32> {
            capture_names
                .iter()
                .position(|n| *n == name)
                .map(|i| i as u32)
        };

        let idx_import_name = idx("import_name");
        let idx_import_from_module = idx("import_from_module");
        let idx_import_from_name = idx("import_from_name");
        let idx_import_from_module_alias = idx("import_from_module_alias");
        let idx_import_from_aliased_name = idx("import_from_aliased_name");
        let idx_class_name = idx("class_name");
        let idx_class_parents = idx("class_parents");
        let idx_decorator = idx("decorator");
        let idx_func_decorator = idx("func_decorator");
        let idx_func_name = idx("func_name");
        let idx_decorated_func_name = idx("decorated_func_name");
        let idx_method_name = idx("method_name");
        let idx_decorated_method_name = idx("decorated_method_name");
        let idx_assignment_name = idx("assignment_name");
        let idx_assignment_value = idx("assignment_value");

        let mut emitted_classes = std::collections::HashSet::new();
        let mut emitted_funcs = std::collections::HashSet::new();

        let mut matches = cursor.matches(query, tree.root_node(), content.as_bytes());

        while let Some(m) = matches.next() {
            // Import: import X
            if let Some(cap) = find_capture(m, idx_import_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                symbols.push(ParsedSymbol {
                    name: name.to_string(),
                    kind: SymbolKind::Import,
                    line,
                    signature: line_text(content, line).trim().to_string(),
                    parents: vec![],
                });
                continue;
            }

            // Import: from X import Y
            if let Some(mod_cap) = find_capture(m, idx_import_from_module) {
                let module = node_text(content, &mod_cap.node);
                let line = node_line(&mod_cap.node);
                let sig = line_text(content, line).trim().to_string();

                symbols.push(ParsedSymbol {
                    name: module.to_string(),
                    kind: SymbolKind::Import,
                    line,
                    signature: sig.clone(),
                    parents: vec![],
                });

                for cap in m
                    .captures
                    .iter()
                    .filter(|c| Some(c.index) == idx_import_from_name)
                {
                    let item = node_text(content, &cap.node);
                    if item != "*" {
                        symbols.push(ParsedSymbol {
                            name: item.to_string(),
                            kind: SymbolKind::Import,
                            line,
                            signature: sig.clone(),
                            parents: vec![],
                        });
                    }
                }
                continue;
            }

            // Import: from X import Y as Z
            if let Some(mod_cap) = find_capture(m, idx_import_from_module_alias) {
                let module = node_text(content, &mod_cap.node);
                let line = node_line(&mod_cap.node);
                let sig = line_text(content, line).trim().to_string();

                symbols.push(ParsedSymbol {
                    name: module.to_string(),
                    kind: SymbolKind::Import,
                    line,
                    signature: sig.clone(),
                    parents: vec![],
                });

                if let Some(name_cap) = find_capture(m, idx_import_from_aliased_name) {
                    let item = node_text(content, &name_cap.node);
                    symbols.push(ParsedSymbol {
                        name: item.to_string(),
                        kind: SymbolKind::Import,
                        line,
                        signature: sig,
                        parents: vec![],
                    });
                }
                continue;
            }

            // Class definition (with or without parents)
            if let Some(cap) = find_capture(m, idx_class_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                if emitted_classes.insert(line) {
                    let parents = find_capture(m, idx_class_parents)
                        .map(|pc| parse_python_parents(content, &pc.node))
                        .unwrap_or_default();
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Class,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents,
                    });
                }
                continue;
            }

            // Decorator for class
            if let Some(cap) = find_capture(m, idx_decorator) {
                let dec_text = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                let name = dec_text.trim_start_matches('@');
                if is_significant_decorator(name) {
                    symbols.push(ParsedSymbol {
                        name: format!("@{}", name),
                        kind: SymbolKind::Annotation,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents: vec![],
                    });
                }
                continue;
            }

            // Decorator for function
            if let Some(cap) = find_capture(m, idx_func_decorator) {
                let dec_text = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                let name = dec_text.trim_start_matches('@');
                let name = name.split('(').next().unwrap_or(name);
                if is_significant_decorator(name) {
                    symbols.push(ParsedSymbol {
                        name: format!("@{}", name),
                        kind: SymbolKind::Annotation,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents: vec![],
                    });
                }
                continue;
            }

            // Decorated function at module level
            if let Some(cap) = find_capture(m, idx_decorated_func_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                if emitted_funcs.insert(line) {
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Function,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents: vec![],
                    });
                }
                continue;
            }

            // Function at module level
            if let Some(cap) = find_capture(m, idx_func_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                if emitted_funcs.insert(line) {
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Function,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents: vec![],
                    });
                }
                continue;
            }

            // Method inside class
            if let Some(cap) = find_capture(m, idx_method_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                symbols.push(ParsedSymbol {
                    name: name.to_string(),
                    kind: SymbolKind::Function,
                    line,
                    signature: line_text(content, line).trim().to_string(),
                    parents: vec![],
                });
                continue;
            }

            // Decorated method inside class
            if let Some(cap) = find_capture(m, idx_decorated_method_name) {
                let name = node_text(content, &cap.node);
                let line = node_line(&cap.node);
                symbols.push(ParsedSymbol {
                    name: name.to_string(),
                    kind: SymbolKind::Function,
                    line,
                    signature: line_text(content, line).trim().to_string(),
                    parents: vec![],
                });
                continue;
            }

            // Module-level assignments
            if let Some(name_cap) = find_capture(m, idx_assignment_name) {
                let name = node_text(content, &name_cap.node);
                let line = node_line(&name_cap.node);
                let sig = line_text(content, line).trim().to_string();

                if let Some(val_cap) = find_capture(m, idx_assignment_value) {
                    let val = node_text(content, &val_cap.node);
                    if is_type_alias_value(val)
                        && name
                            .chars()
                            .next()
                            .map(|c| c.is_uppercase())
                            .unwrap_or(false)
                    {
                        symbols.push(ParsedSymbol {
                            name: name.to_string(),
                            kind: SymbolKind::TypeAlias,
                            line,
                            signature: sig,
                            parents: vec![],
                        });
                        continue;
                    }
                }

                if is_constant_name(name) {
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Constant,
                        line,
                        signature: sig,
                        parents: vec![],
                    });
                }
                continue;
            }
        }

        Ok(symbols)
    }
}

fn parse_python_parents(content: &str, node: &tree_sitter::Node) -> Vec<(String, String)> {
    let mut parents = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "attribute" {
            let name = node_text(content, &child);
            if name != "object" {
                parents.push((name.to_string(), "extends".to_string()));
            }
        }
    }
    parents
}

fn is_constant_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
        && name
            .chars()
            .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_type_alias_value(val: &str) -> bool {
    val.starts_with("Union")
        || val.starts_with("Optional")
        || val.starts_with("List")
        || val.starts_with("Dict")
        || val.starts_with("Tuple")
        || val.starts_with("Callable")
        || val.starts_with("Type")
}

fn is_significant_decorator(name: &str) -> bool {
    name.contains("route")
        || name.contains("handler")
        || name.contains("pytest")
        || name.contains("fixture")
        || name.contains("dataclass")
        || name.contains("property")
        // DRF
        || name.contains("action")
        || name.contains("api_view")
        || name.contains("permission_classes")
        || name.contains("throttle_classes")
        || name.contains("authentication_classes")
        || name.contains("renderer_classes")
        || name.contains("parser_classes")
        // Django
        || name.contains("login_required")
        || name.contains("require_http_methods")
        || name.contains("csrf_exempt")
        || name.contains("cache_page")
        || name.contains("receiver")
        || name.contains("register")
        || name.contains("admin")
        // Celery
        || name.contains("task")
        || name.contains("shared_task")
        // common patterns
        || name.contains("middleware")
        || name.contains("decorator")
        || name.contains("override")
        || name.contains("abstractmethod")
        || name.contains("staticmethod")
        || name.contains("classmethod")
        || name.contains("cached_property")
        || name.contains("validator")
        || name.contains("serializer")
}

fn find_capture<'a>(
    m: &'a tree_sitter::QueryMatch<'a, 'a>,
    idx: Option<u32>,
) -> Option<&'a tree_sitter::QueryCapture<'a>> {
    let idx = idx?;
    m.captures.iter().find(|c| c.index == idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_class() {
        let content = "class MyClass:\n    pass\n\nclass ChildClass(ParentClass):\n    pass\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "MyClass" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "ChildClass" && s.parents.iter().any(|(p, _)| p == "ParentClass")));
    }

    #[test]
    fn test_parse_functions() {
        let content = "def handle(request, context):\n    pass\n\nasync def async_handler(request):\n    pass\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "handle" && s.kind == SymbolKind::Function));
        assert!(symbols
            .iter()
            .any(|s| s.name == "async_handler" && s.kind == SymbolKind::Function));
    }

    #[test]
    fn test_parse_imports() {
        let content = "import logging\nfrom driver_referrals.common import db\nfrom typing import Optional, List\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "logging" && s.kind == SymbolKind::Import));
        assert!(symbols
            .iter()
            .any(|s| s.name == "driver_referrals.common" && s.kind == SymbolKind::Import));
    }

    #[test]
    fn test_parse_decorators() {
        let content = "@dataclass\nclass Config:\n    host: str\n\n@property\ndef name(self):\n    return self._name\n\n@pytest.fixture\ndef client():\n    return Client()\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "@dataclass"));
        assert!(symbols.iter().any(|s| s.name == "@property"));
        assert!(symbols.iter().any(|s| s.name == "@pytest.fixture"));
    }

    #[test]
    fn test_parse_constants() {
        let content = "MAX_RETRIES = 5\nDEFAULT_TIMEOUT = 30\nAPI_KEY = \"secret\"\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "MAX_RETRIES" && s.kind == SymbolKind::Constant));
        assert!(symbols
            .iter()
            .any(|s| s.name == "DEFAULT_TIMEOUT" && s.kind == SymbolKind::Constant));
        assert!(symbols
            .iter()
            .any(|s| s.name == "API_KEY" && s.kind == SymbolKind::Constant));
    }

    #[test]
    fn test_parse_type_aliases() {
        let content = "UserList = List[User]\nCallback = Callable[[str], None]\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "UserList" && s.kind == SymbolKind::TypeAlias));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Callback" && s.kind == SymbolKind::TypeAlias));
    }

    #[test]
    fn test_parse_class_multiple_inheritance() {
        let content = "class MyView(BaseView, PermissionMixin, LoggingMixin):\n    pass\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let cls = symbols.iter().find(|s| s.name == "MyView").unwrap();
        assert!(cls.parents.iter().any(|(p, _)| p == "BaseView"));
        assert!(cls.parents.iter().any(|(p, _)| p == "PermissionMixin"));
        assert!(cls.parents.iter().any(|(p, _)| p == "LoggingMixin"));
    }

    #[test]
    fn test_parse_function_with_return_type() {
        let content = "def get_name(self) -> str:\n    return \"\"\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "get_name"));
    }

    #[test]
    fn test_comments_ignored() {
        let content = "# class FakeClass:\n#     pass\nclass RealClass:\n    pass\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "RealClass"));
        assert!(!symbols.iter().any(|s| s.name == "FakeClass"));
    }

    #[test]
    fn test_async_functions() {
        let content = "async def fetch_data(url) -> str:\n    pass\n\nasync def process_event(event):\n    pass\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "fetch_data" && s.kind == SymbolKind::Function));
        assert!(symbols
            .iter()
            .any(|s| s.name == "process_event" && s.kind == SymbolKind::Function));
    }

    #[test]
    fn test_parse_private_methods() {
        let content = r#"
class AuthService:
    def __init__(self, config):
        self.config = config

    def _get_jwt(self, user_id):
        return jwt.encode({"sub": user_id}, self.config.secret)

    def _validate_token(self, token):
        return jwt.decode(token, self.config.secret)

    def __repr__(self):
        return "AuthService"

def _helper_func():
    pass

def _another_private():
    return 42
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        // private methods should be indexed
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_get_jwt" && s.kind == SymbolKind::Function),
            "private method _get_jwt should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_validate_token" && s.kind == SymbolKind::Function),
            "private method _validate_token should be indexed"
        );
        // dunder methods should be indexed
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "__init__" && s.kind == SymbolKind::Function),
            "__init__ should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "__repr__" && s.kind == SymbolKind::Function),
            "__repr__ should be indexed"
        );
        // module-level private functions should be indexed
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_helper_func" && s.kind == SymbolKind::Function),
            "private module-level function should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_another_private" && s.kind == SymbolKind::Function),
            "private module-level function should be indexed"
        );
    }

    #[test]
    fn test_parse_drf_decorators() {
        let content = r#"
from rest_framework.decorators import action, api_view

class UserViewSet(ModelViewSet):
    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        pass

    @action(detail=False)
    def bulk_delete(self, request):
        pass

@api_view(["GET", "POST"])
def user_list(request):
    pass
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@action" && s.kind == SymbolKind::Annotation),
            "@action decorator should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@api_view" && s.kind == SymbolKind::Annotation),
            "@api_view decorator should be indexed"
        );
    }

    #[test]
    fn test_extract_refs_snake_case_calls() {
        let content = r#"
result = get_user_data(user_id)
token = _generate_token(payload)
validate_input(data)
"#;
        let symbols = vec![];
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        assert!(
            refs.iter().any(|r| r.name == "get_user_data"),
            "should find snake_case function call"
        );
        assert!(
            refs.iter().any(|r| r.name == "_generate_token"),
            "should find _private function call"
        );
        assert!(
            refs.iter().any(|r| r.name == "validate_input"),
            "should find simple snake_case call"
        );
    }

    #[test]
    fn test_extract_refs_method_calls() {
        let content = r#"
class Service:
    def process(self):
        token = self._get_jwt(user_id)
        self._validate_token(token)
        result = self.repo.find_by_id(pk)
        obj.do_something(arg)
"#;
        let symbols = vec![];
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        assert!(
            refs.iter().any(|r| r.name == "_get_jwt"),
            "should find self._method() call"
        );
        assert!(
            refs.iter().any(|r| r.name == "_validate_token"),
            "should find self._validate_token() call"
        );
        assert!(
            refs.iter().any(|r| r.name == "find_by_id"),
            "should find chained method call"
        );
        assert!(
            refs.iter().any(|r| r.name == "do_something"),
            "should find obj.method() call"
        );
    }

    #[test]
    fn test_extract_refs_skips_imports_and_defs() {
        let content = r#"
import logging
from utils import helper_func

def my_function(arg):
    result = helper_func(arg)
    data = external_call(result)
    return data

class MyClass:
    pass
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        // import lines should not generate refs
        assert!(
            !refs.iter().any(|r| r.name == "logging"),
            "should skip import line refs"
        );
        // defined symbols (including imports) should not appear in refs
        assert!(
            !refs.iter().any(|r| r.name == "my_function"),
            "should skip locally defined function"
        );
        // helper_func is imported, so its calls should appear in refs
        assert!(
            refs.iter().any(|r| r.name == "helper_func"),
            "should find call to imported function"
        );
        // calls to non-locally-defined symbols should appear in refs
        assert!(
            refs.iter().any(|r| r.name == "external_call"),
            "should find call to non-defined function"
        );
    }

    #[test]
    fn test_extract_refs_skips_python_keywords() {
        let content = r#"
if isinstance(obj, MyModel):
    for item in range(10):
        print(item)
"#;
        let symbols = vec![];
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        assert!(
            !refs.iter().any(|r| r.name == "isinstance"),
            "should skip builtin isinstance"
        );
        assert!(
            !refs.iter().any(|r| r.name == "range"),
            "should skip builtin range"
        );
        assert!(
            !refs.iter().any(|r| r.name == "print"),
            "should skip builtin print"
        );
        // but CamelCase type should be found
        assert!(
            refs.iter().any(|r| r.name == "MyModel"),
            "should find CamelCase type reference"
        );
    }

    /// Regression: private method like _get_jwt -- definition + refs
    #[test]
    fn test_regression_private_method_get_jwt() {
        let content = r#"
class AuthService:
    def _get_jwt(self, user_id: int) -> str:
        """Генерация JWT токена."""
        return jwt.encode({"user_id": user_id}, self._secret_key)

    def authenticate(self, request):
        token = self._get_jwt(request.user.id)
        self._validate_token(token)
        return token

    def _validate_token(self, token: str) -> bool:
        return jwt.decode(token, self._secret_key)
"#;
        // 1. private method definitions should be indexed
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_get_jwt" && s.kind == SymbolKind::Function),
            "_get_jwt definition must be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_validate_token" && s.kind == SymbolKind::Function),
            "_validate_token definition must be indexed"
        );

        // 2. refs should find self._get_jwt() and self._validate_token() calls
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        assert!(
            refs.iter().any(|r| r.name == "_get_jwt"),
            "self._get_jwt() call must appear in refs"
        );
        assert!(
            refs.iter().any(|r| r.name == "_validate_token"),
            "self._validate_token() call must appear in refs"
        );
    }

    #[test]
    fn test_parse_django_decorators() {
        let content = r#"
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

@login_required
def dashboard(request):
    pass

@csrf_exempt
def webhook(request):
    pass

@staticmethod
def helper():
    pass

@classmethod
def create(cls, **kwargs):
    pass

@abstractmethod
def process(self):
    pass

@cached_property
def full_name(self):
    return f"{self.first} {self.last}"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@login_required" && s.kind == SymbolKind::Annotation),
            "@login_required should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@csrf_exempt" && s.kind == SymbolKind::Annotation),
            "@csrf_exempt should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@staticmethod" && s.kind == SymbolKind::Annotation),
            "@staticmethod should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@classmethod" && s.kind == SymbolKind::Annotation),
            "@classmethod should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@abstractmethod" && s.kind == SymbolKind::Annotation),
            "@abstractmethod should be indexed"
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "@cached_property" && s.kind == SymbolKind::Annotation),
            "@cached_property should be indexed"
        );
    }

    /// Regression: multi-line import + direct call in class method
    /// Bug: annotate_tempo( should appear in refs but was missing
    #[test]
    fn test_extract_refs_multiline_import_then_call() {
        let content = r#"
from power_exchange.viewsets.performance.utils import (
    annotate_all_changes,
    annotate_tempo,
    determine_quadrant,
)


class OrganizationPerformanceViewSet:
    def quadrant_distribution(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(year=year)
        queryset = annotate_tempo(queryset, base_year)
        return queryset
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();

        // annotate_tempo should be Import, NOT in defined_names
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "annotate_tempo" && s.kind == SymbolKind::Import),
            "annotate_tempo should be parsed as Import"
        );
        assert!(
            !symbols
                .iter()
                .any(|s| s.name == "annotate_tempo" && s.kind != SymbolKind::Import),
            "annotate_tempo should NOT have non-Import kind"
        );

        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        assert!(
            refs.iter().any(|r| r.name == "annotate_tempo"),
            "annotate_tempo( call should appear in refs, got: {:?}",
            refs.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    /// Regression: test with real file content to reproduce the missing refs bug
    #[test]
    fn test_extract_refs_real_file_annotate_tempo() {
        let content = std::fs::read_to_string(
            "/home/spike/work/industry/backend/power_exchange/viewsets/performance/views.py",
        );
        if content.is_err() {
            // skip if file not available
            return;
        }
        let content = content.unwrap();
        let symbols = PYTHON_PARSER.parse_symbols(&content).unwrap();

        // verify annotate_tempo is parsed as Import only
        let at_symbols: Vec<_> = symbols
            .iter()
            .filter(|s| s.name == "annotate_tempo")
            .collect();
        assert!(
            !at_symbols.is_empty(),
            "annotate_tempo should be in symbols"
        );
        for s in &at_symbols {
            assert_eq!(
                s.kind,
                SymbolKind::Import,
                "annotate_tempo should be Import, got {:?}",
                s.kind
            );
        }

        let refs = PYTHON_PARSER.extract_refs(&content, &symbols).unwrap();
        let at_refs: Vec<_> = refs.iter().filter(|r| r.name == "annotate_tempo").collect();
        assert!(
            !at_refs.is_empty(),
            "annotate_tempo should appear in refs (found {} total refs)",
            refs.len()
        );
    }
}
