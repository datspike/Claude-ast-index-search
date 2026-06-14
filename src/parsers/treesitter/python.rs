//! Tree-sitter based Python parser

use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use tree_sitter::{Language, Query, QueryCursor, StreamingIterator};

use super::{line_text, node_line, node_text, parse_tree, LanguageParser};
use crate::db::SymbolKind;
use crate::parsers::{FileType, ParsedRef, ParsedSymbol};

static PY_LANGUAGE: LazyLock<Language> = LazyLock::new(|| tree_sitter_python::LANGUAGE.into());

static PY_QUERY: LazyLock<Query> = LazyLock::new(|| {
    Query::new(&PY_LANGUAGE, include_str!("queries/python.scm"))
        .expect("Failed to compile Python tree-sitter query")
});

pub static PYTHON_PARSER: PythonParser = PythonParser;

pub struct PythonParser;

static PY_KEYWORDS_AND_BUILTINS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "False",
        "None",
        "True",
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
        "abs",
        "all",
        "any",
        "bool",
        "bytes",
        "callable",
        "classmethod",
        "dict",
        "dir",
        "enumerate",
        "filter",
        "float",
        "getattr",
        "hasattr",
        "int",
        "isinstance",
        "issubclass",
        "len",
        "list",
        "map",
        "object",
        "print",
        "property",
        "range",
        "set",
        "setattr",
        "sorted",
        "staticmethod",
        "str",
        "super",
        "tuple",
        "type",
        "zip",
        "self",
        "cls",
        "Exception",
        "ValueError",
        "TypeError",
        "KeyError",
        "AttributeError",
        "RuntimeError",
        "NotImplementedError",
        "OSError",
        "Any",
        "Annotated",
        "Callable",
        "ClassVar",
        "Dict",
        "Final",
        "Generic",
        "Iterable",
        "Iterator",
        "List",
        "Literal",
        "Mapping",
        "Never",
        "NoReturn",
        "Optional",
        "Protocol",
        "Self",
        "Sequence",
        "Set",
        "Tuple",
        "Type",
        "TypedDict",
        "Union",
    ]
    .into_iter()
    .collect()
});

static PY_DIRECT_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());

static PY_DOTTED_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());

static PY_CAMEL_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^A-Za-z0-9_])(_?[A-Z][A-Za-z0-9_]*)\b").unwrap());

// Python refs остаются текстовыми: scanner не разрешает imports, типы и symbol id,
// а извлекает устойчивые `name + line + context` для текущей модели `ParsedRef`.
impl LanguageParser for PythonParser {
    fn extract_refs(&self, content: &str, _defined: &[ParsedSymbol]) -> Result<Vec<ParsedRef>> {
        let mut refs = Vec::new();
        let mut seen = HashSet::new();
        let mut state = PythonRefScanState::default();

        for (line_index, raw_line) in content.lines().enumerate() {
            let line_num = line_index + 1;
            let context = raw_line.trim();
            let raw_line_without_comment = python_line_without_comment(raw_line);
            if state.in_multiline_string.is_none() && state.in_multiline_fstring.is_none() {
                record_python_typing_literal_aliases(&raw_line_without_comment, &mut state);
            }

            if state.in_multiline_string.is_none() || state.in_multiline_fstring.is_some() {
                let fstring_scan_line = if state.in_multiline_fstring.is_some() {
                    raw_line
                } else {
                    &raw_line_without_comment
                };
                for expr in extract_python_fstring_expressions(
                    fstring_scan_line,
                    &mut state,
                    line_num,
                    context,
                ) {
                    let expr_without_strings = strip_python_inline_strings(&expr.content);
                    push_python_refs_from_segment(
                        &mut refs,
                        &mut seen,
                        &expr_without_strings,
                        expr.line,
                        &expr.context,
                    );
                }
            }

            let Some(scan_line) = sanitize_python_ref_line(raw_line, &mut state) else {
                continue;
            };
            let signature_context =
                state.in_multiline_signature || is_python_signature_line(&scan_line);
            let call_scan_line = python_call_scan_segment(&scan_line, &mut state);

            if let Some(call_scan_line) = call_scan_line.as_deref() {
                push_python_refs_from_segment(
                    &mut refs,
                    &mut seen,
                    call_scan_line,
                    line_num,
                    context,
                );
            }

            let variable_annotation_context = is_python_variable_annotation_line(&scan_line);
            let statement_continuation_context =
                !signature_context && state.statement_paren_depth > 0;
            if signature_context || variable_annotation_context {
                let annotation_scan_line = python_quoted_annotation_scan_line(
                    raw_line,
                    signature_context,
                    variable_annotation_context,
                );
                for annotation in extract_python_quoted_annotation_refs(
                    &annotation_scan_line,
                    &state.typing_literal_aliases,
                ) {
                    for nested_caps in PY_CAMEL_REF_RE.captures_iter(&annotation) {
                        if let Some(name_match) = nested_caps.get(1) {
                            let name = name_match.as_str();
                            push_python_ref(&mut refs, &mut seen, name, line_num, context, true);
                        }
                    }
                }
            }

            if !signature_context {
                state.reset_signature_default_scan();
            }

            let camel_scan_line = strip_python_definition_targets(
                if signature_context {
                    strip_python_signature_default_values(&scan_line, &mut state)
                } else {
                    scan_line.clone()
                },
                !statement_continuation_context,
            );

            for caps in PY_CAMEL_REF_RE.captures_iter(&camel_scan_line) {
                if let Some(name_match) = caps.get(1) {
                    let name = name_match.as_str();
                    push_python_ref(&mut refs, &mut seen, name, line_num, context, true);
                }
            }

            if signature_context {
                state.statement_paren_depth = 0;
            } else {
                state.statement_paren_depth =
                    (state.statement_paren_depth + python_paren_delta(&scan_line)).max(0);
            }
        }

        Ok(refs)
    }

    fn extract_refs_for_lang(
        &self,
        content: &str,
        defined: &[ParsedSymbol],
        _file_type: FileType,
    ) -> Result<Vec<ParsedRef>> {
        self.extract_refs(content, defined)
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
        let idx_import_alias_original = idx("import_alias_original");
        let idx_import_alias_name = idx("import_alias_name");
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

            // Import: import X as Y
            if let Some(orig_cap) = find_capture(m, idx_import_alias_original) {
                let original = node_text(content, &orig_cap.node);
                let line = node_line(&orig_cap.node);
                let sig = line_text(content, line).trim().to_string();

                symbols.push(ParsedSymbol {
                    name: original.to_string(),
                    kind: SymbolKind::Import,
                    line,
                    signature: sig.clone(),
                    parents: vec![],
                });

                if let Some(alias_cap) = find_capture(m, idx_import_alias_name) {
                    let alias = node_text(content, &alias_cap.node);
                    symbols.push(ParsedSymbol {
                        name: alias.to_string(),
                        kind: SymbolKind::Import,
                        line,
                        signature: sig,
                        parents: vec![],
                    });
                }
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

#[derive(Default)]
struct PythonRefScanState {
    in_multiline_import: bool,
    multiline_import_closes_with_paren: bool,
    in_multiline_signature: bool,
    signature_paren_depth: i32,
    in_multiline_string: Option<&'static str>,
    in_multiline_fstring: Option<char>,
    fstring_expr_depth: i32,
    fstring_expr_buffer: String,
    fstring_expr_in_single: bool,
    fstring_expr_in_double: bool,
    fstring_expr_escaped: bool,
    fstring_expr_start_line: Option<usize>,
    fstring_expr_start_context: String,
    in_signature_default: bool,
    signature_default_paren_depth: i32,
    signature_default_bracket_depth: i32,
    signature_default_brace_depth: i32,
    statement_paren_depth: i32,
    typing_literal_aliases: HashSet<String>,
}

struct PythonFstringExpression {
    content: String,
    line: usize,
    context: String,
}

impl PythonRefScanState {
    fn reset_signature_default_scan(&mut self) {
        self.in_signature_default = false;
        self.signature_default_paren_depth = 0;
        self.signature_default_bracket_depth = 0;
        self.signature_default_brace_depth = 0;
    }
}

fn sanitize_python_ref_line(line: &str, state: &mut PythonRefScanState) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.len() > 2000 || trimmed.is_empty() {
        return None;
    }

    if state.in_multiline_import {
        if state.multiline_import_closes_with_paren {
            if trimmed.contains(')') {
                state.in_multiline_import = false;
                state.multiline_import_closes_with_paren = false;
            }
        } else if !trimmed.ends_with('\\') {
            state.in_multiline_import = false;
        }
        return None;
    }

    if is_python_parenthesized_from_import(trimmed) {
        if !trimmed.contains(')') {
            state.in_multiline_import = true;
            state.multiline_import_closes_with_paren = true;
        }
        return None;
    }

    if (trimmed.starts_with("from ") || trimmed.starts_with("import ")) && trimmed.ends_with('\\') {
        state.in_multiline_import = true;
        state.multiline_import_closes_with_paren = false;
        return None;
    }

    let sanitized = strip_python_comments_and_strings(line, &mut state.in_multiline_string);
    let sanitized_trimmed = sanitized.trim();
    if sanitized_trimmed.is_empty()
        || sanitized_trimmed.starts_with("import ")
        || sanitized_trimmed.starts_with("from ")
    {
        return None;
    }

    Some(sanitized)
}

fn record_python_typing_literal_aliases(line: &str, state: &mut PythonRefScanState) {
    let trimmed = line.trim();
    let Some(imports) = trimmed.strip_prefix("from typing import ") else {
        return;
    };

    for import_part in imports
        .trim_matches(|ch| ch == '(' || ch == ')')
        .split(',')
        .map(|part| part.trim().trim_end_matches(';').trim())
    {
        if let Some(alias) = import_part.strip_prefix("Literal as ") {
            let alias = alias.trim();
            if is_python_identifier_part(alias) {
                state.typing_literal_aliases.insert(alias.to_string());
            }
        }
    }
}

fn is_python_parenthesized_from_import(trimmed: &str) -> bool {
    if !trimmed.starts_with("from ") {
        return false;
    }

    let Some(import_index) = trimmed.find(" import") else {
        return false;
    };

    trimmed[import_index + " import".len()..]
        .trim_start()
        .starts_with('(')
}

fn is_python_signature_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("class ")
}

fn is_python_variable_annotation_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if is_python_signature_line(trimmed) {
        return false;
    }

    let Some(colon_idx) = find_python_top_level_colon(trimmed) else {
        return false;
    };
    let target = trimmed[..colon_idx].trim();
    if target.is_empty() || target.contains(char::is_whitespace) {
        return false;
    }

    let Some(first) = target.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    target.split('.').all(is_python_identifier_part)
}

fn find_python_top_level_colon(line: &str) -> Option<usize> {
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;

    for (idx, ch) in line.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = (paren_depth - 1).max(0),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = (bracket_depth - 1).max(0),
            '{' => brace_depth += 1,
            '}' => brace_depth = (brace_depth - 1).max(0),
            ':' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return Some(idx);
            }
            _ => {}
        }
    }

    None
}

fn is_python_identifier_part(part: &str) -> bool {
    let mut chars = part.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn python_call_scan_segment(line: &str, state: &mut PythonRefScanState) -> Option<String> {
    let trimmed = line.trim_start();

    if state.in_multiline_signature {
        state.signature_paren_depth =
            (state.signature_paren_depth + python_paren_delta(trimmed)).max(0);
        let inline_body = python_signature_inline_body(trimmed, state.signature_paren_depth);
        if state.signature_paren_depth == 0 && trimmed.rfind(':').is_some() {
            state.in_multiline_signature = false;
        }
        return inline_body;
    }

    if is_python_signature_line(trimmed) {
        state.signature_paren_depth = python_paren_delta(trimmed).max(0);
        let has_signature_colon = trimmed.rfind(':').is_some();
        let inline_body = python_signature_inline_body(trimmed, state.signature_paren_depth);
        state.in_multiline_signature = state.signature_paren_depth > 0 || !has_signature_colon;
        return inline_body;
    }

    Some(trimmed.to_string())
}

fn python_signature_inline_body(line: &str, paren_depth: i32) -> Option<String> {
    if paren_depth > 0 {
        return None;
    }

    let colon_idx = find_python_signature_colon(line)?;
    let tail = line[colon_idx + 1..].trim_start();
    if tail.is_empty() {
        None
    } else {
        Some(tail.to_string())
    }
}

fn find_python_signature_colon(line: &str) -> Option<usize> {
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;

    for (idx, ch) in line.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = (paren_depth - 1).max(0),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = (bracket_depth - 1).max(0),
            '{' => brace_depth += 1,
            '}' => brace_depth = (brace_depth - 1).max(0),
            ':' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => return Some(idx),
            _ => {}
        }
    }

    None
}

fn python_paren_delta(line: &str) -> i32 {
    let opens = line.chars().filter(|&ch| ch == '(').count() as i32;
    let closes = line.chars().filter(|&ch| ch == ')').count() as i32;
    opens - closes
}

fn strip_python_comments_and_strings(
    line: &str,
    in_multiline_string: &mut Option<&'static str>,
) -> String {
    let mut sanitized = String::with_capacity(line.len());
    let mut index = 0;

    while index < line.len() {
        if let Some(delimiter) = *in_multiline_string {
            if let Some(offset) = line[index..].find(delimiter) {
                index += offset + delimiter.len();
                *in_multiline_string = None;
            } else {
                return sanitized;
            }
            continue;
        }

        let remaining = &line[index..];

        if remaining.starts_with("\"\"\"") {
            *in_multiline_string = Some("\"\"\"");
            index += 3;
            continue;
        }

        if remaining.starts_with("'''") {
            *in_multiline_string = Some("'''");
            index += 3;
            continue;
        }

        let mut chars = remaining.chars();
        let Some(ch) = chars.next() else {
            break;
        };
        let ch_len = ch.len_utf8();

        if ch == '#' {
            break;
        }

        if ch == '\'' || ch == '"' {
            index += ch_len;
            let quote = ch;
            let mut escaped = false;
            while index < line.len() {
                let mut inner_chars = line[index..].chars();
                let Some(inner) = inner_chars.next() else {
                    break;
                };
                let inner_len = inner.len_utf8();
                index += inner_len;

                if escaped {
                    escaped = false;
                    continue;
                }

                if inner == '\\' {
                    escaped = true;
                    continue;
                }

                if inner == quote {
                    break;
                }
            }
            continue;
        }

        sanitized.push(ch);
        index += ch_len;
    }

    sanitized
}

fn push_python_ref(
    refs: &mut Vec<ParsedRef>,
    seen: &mut HashSet<(String, usize)>,
    name: &str,
    line: usize,
    context: &str,
    enforce_min_len: bool,
) {
    if name.is_empty()
        || PY_KEYWORDS_AND_BUILTINS.contains(name)
        || (enforce_min_len && name.len() <= 2)
    {
        return;
    }

    if seen.insert((name.to_string(), line)) {
        refs.push(ParsedRef {
            name: name.to_string(),
            line,
            context: truncate_python_context(context),
        });
    }
}

fn push_python_refs_from_segment(
    refs: &mut Vec<ParsedRef>,
    seen: &mut HashSet<(String, usize)>,
    segment: &str,
    line: usize,
    context: &str,
) {
    for caps in PY_DOTTED_CALL_RE.captures_iter(segment) {
        if let Some(name_match) = caps.get(1) {
            push_python_ref(refs, seen, name_match.as_str(), line, context, false);
        }
    }

    for caps in PY_DIRECT_CALL_RE.captures_iter(segment) {
        let Some(name_match) = caps.get(1) else {
            continue;
        };
        let name_start = name_match.start();
        if name_start > 0 && segment.as_bytes().get(name_start - 1) == Some(&b'.') {
            continue;
        }
        let name = name_match.as_str();
        push_python_ref(refs, seen, name, line, context, true);
    }
}

fn raw_line_has_fstring(raw_line: &str) -> bool {
    let lower = raw_line.to_ascii_lowercase();
    lower.contains("f\"")
        || lower.contains("f'")
        || lower.contains("rf\"")
        || lower.contains("rf'")
        || lower.contains("fr\"")
        || lower.contains("fr'")
}

struct PythonFstringScanContext<'a> {
    line_num: usize,
    context: &'a str,
}

fn extract_python_fstring_expressions(
    line: &str,
    state: &mut PythonRefScanState,
    line_num: usize,
    context: &str,
) -> Vec<PythonFstringExpression> {
    let mut expressions = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0usize;

    if let Some(quote) = state.in_multiline_fstring {
        index = consume_python_fstring_literal(
            &chars,
            0,
            quote,
            true,
            state,
            &mut expressions,
            PythonFstringScanContext { line_num, context },
        );
        if state.in_multiline_fstring.is_some()
            || chars[index..]
                .iter()
                .all(|ch| ch.is_whitespace() || *ch == '#')
            || chars[index..]
                .iter()
                .position(|ch| !ch.is_whitespace())
                .is_some_and(|offset| chars[index + offset] == '#')
        {
            return expressions;
        }
    }

    if !raw_line_has_fstring(line) {
        return expressions;
    }

    while index < chars.len() {
        let ch = chars[index];
        if ch != '\'' && ch != '"' {
            index += 1;
            continue;
        }

        let mut prefix_start = index;
        while prefix_start > 0 && chars[prefix_start - 1].is_ascii_alphabetic() {
            prefix_start -= 1;
        }
        let prefix: String = chars[prefix_start..index].iter().collect();
        let prefix_lower = prefix.to_ascii_lowercase();
        let is_fstring = prefix_lower.contains('f');

        let quote = ch;
        let triple =
            index + 2 < chars.len() && chars[index + 1] == quote && chars[index + 2] == quote;
        index += if triple { 3 } else { 1 };

        if !is_fstring {
            skip_python_string_literal(&chars, &mut index, quote, triple);
            continue;
        }

        index = consume_python_fstring_literal(
            &chars,
            index,
            quote,
            triple,
            state,
            &mut expressions,
            PythonFstringScanContext { line_num, context },
        );
    }

    expressions
}

fn consume_python_fstring_literal(
    chars: &[char],
    mut index: usize,
    quote: char,
    triple: bool,
    state: &mut PythonRefScanState,
    expressions: &mut Vec<PythonFstringExpression>,
    scan_context: PythonFstringScanContext<'_>,
) -> usize {
    while index < chars.len() {
        if triple {
            if index + 2 < chars.len()
                && chars[index] == quote
                && chars[index + 1] == quote
                && chars[index + 2] == quote
            {
                state.in_multiline_fstring = None;
                flush_pending_python_fstring_expr(state, expressions);
                return index + 3;
            }
        } else if chars[index] == quote {
            flush_pending_python_fstring_expr(state, expressions);
            return index + 1;
        }

        let ch = chars[index];

        if state.fstring_expr_depth == 0 {
            if ch == '{' {
                if index + 1 < chars.len() && chars[index + 1] == '{' {
                    index += 2;
                    continue;
                }
                reset_pending_python_fstring_expr(state);
                state.fstring_expr_start_line = Some(scan_context.line_num);
                state.fstring_expr_start_context = scan_context.context.to_string();
                state.fstring_expr_depth = 1;
                index += 1;
                continue;
            }

            if ch == '}' && index + 1 < chars.len() && chars[index + 1] == '}' {
                index += 2;
                continue;
            }

            if ch == '\\' && !triple && index + 1 < chars.len() {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        consume_python_fstring_expr_char(ch, state, expressions);
        index += 1;
    }

    if triple {
        state.in_multiline_fstring = Some(quote);
        state.fstring_expr_buffer.push('\n');
    }

    index
}

fn consume_python_fstring_expr_char(
    ch: char,
    state: &mut PythonRefScanState,
    expressions: &mut Vec<PythonFstringExpression>,
) {
    if state.fstring_expr_escaped {
        state.fstring_expr_buffer.push(ch);
        state.fstring_expr_escaped = false;
        return;
    }

    if (state.fstring_expr_in_single || state.fstring_expr_in_double) && ch == '\\' {
        state.fstring_expr_buffer.push(ch);
        state.fstring_expr_escaped = true;
        return;
    }

    if !state.fstring_expr_in_double && ch == '\'' {
        state.fstring_expr_in_single = !state.fstring_expr_in_single;
        state.fstring_expr_buffer.push(ch);
        return;
    }

    if !state.fstring_expr_in_single && ch == '"' {
        state.fstring_expr_in_double = !state.fstring_expr_in_double;
        state.fstring_expr_buffer.push(ch);
        return;
    }

    if state.fstring_expr_in_single || state.fstring_expr_in_double {
        state.fstring_expr_buffer.push(ch);
        return;
    }

    match ch {
        '{' => {
            state.fstring_expr_depth += 1;
            state.fstring_expr_buffer.push(ch);
        }
        '}' => {
            state.fstring_expr_depth -= 1;
            if state.fstring_expr_depth == 0 {
                flush_pending_python_fstring_expr(state, expressions);
            } else {
                state.fstring_expr_buffer.push(ch);
            }
        }
        _ => state.fstring_expr_buffer.push(ch),
    }
}

fn flush_pending_python_fstring_expr(
    state: &mut PythonRefScanState,
    expressions: &mut Vec<PythonFstringExpression>,
) {
    if !state.fstring_expr_buffer.trim().is_empty() {
        let start_line = state.fstring_expr_start_line.unwrap_or(0);
        let (line, context) = python_fstring_expr_location(
            &state.fstring_expr_buffer,
            start_line,
            &state.fstring_expr_start_context,
        );
        expressions.push(PythonFstringExpression {
            content: state.fstring_expr_buffer.clone(),
            line,
            context,
        });
    }
    reset_pending_python_fstring_expr(state);
}

fn python_fstring_expr_location(
    expression: &str,
    start_line: usize,
    start_context: &str,
) -> (usize, String) {
    let mut first_non_empty = None;

    for (offset, line) in expression.lines().enumerate() {
        let context = line.trim();
        if context.is_empty() {
            continue;
        }

        let line_location = (start_line + offset, context.to_string());
        if first_non_empty.is_none() {
            first_non_empty = Some(line_location.clone());
        }

        let scan_line = strip_python_inline_strings(context);
        if PY_DOTTED_CALL_RE.is_match(&scan_line)
            || PY_DIRECT_CALL_RE.is_match(&scan_line)
            || PY_CAMEL_REF_RE.is_match(&scan_line)
        {
            return line_location;
        }
    }

    first_non_empty.unwrap_or_else(|| (start_line, start_context.to_string()))
}

fn reset_pending_python_fstring_expr(state: &mut PythonRefScanState) {
    state.fstring_expr_depth = 0;
    state.fstring_expr_buffer.clear();
    state.fstring_expr_in_single = false;
    state.fstring_expr_in_double = false;
    state.fstring_expr_escaped = false;
    state.fstring_expr_start_line = None;
    state.fstring_expr_start_context.clear();
}

fn skip_python_string_literal(chars: &[char], index: &mut usize, quote: char, triple: bool) {
    while *index < chars.len() {
        if triple {
            if *index + 2 < chars.len()
                && chars[*index] == quote
                && chars[*index + 1] == quote
                && chars[*index + 2] == quote
            {
                *index += 3;
                break;
            }
        } else if chars[*index] == quote {
            *index += 1;
            break;
        }

        if chars[*index] == '\\' && *index + 1 < chars.len() {
            *index += 2;
        } else {
            *index += 1;
        }
    }
}

fn python_quoted_annotation_scan_line(
    line: &str,
    signature_context: bool,
    _variable_annotation_context: bool,
) -> String {
    let without_comment = python_line_without_comment(line);
    if signature_context && should_trim_python_signature_suite(&without_comment) {
        if let Some(colon_idx) = find_python_top_level_colon_ignoring_strings(&without_comment) {
            return without_comment[..colon_idx].to_string();
        }
    }

    without_comment
}

fn should_trim_python_signature_suite(line: &str) -> bool {
    let trimmed = line.trim_start();
    is_python_signature_line(trimmed) || trimmed.starts_with(')')
}

fn find_python_top_level_colon_ignoring_strings(line: &str) -> Option<usize> {
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut chars = line.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        match ch {
            '\'' | '"' => {
                let quote = ch;
                let triple = chars.peek().is_some_and(|(_, next)| *next == quote)
                    && line[idx + ch.len_utf8()..]
                        .chars()
                        .nth(1)
                        .is_some_and(|next| next == quote);
                if triple {
                    chars.next();
                    chars.next();
                }
                skip_python_string_literal_in_iter(&mut chars, quote, triple);
            }
            '(' => paren_depth += 1,
            ')' => paren_depth = (paren_depth - 1).max(0),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = (bracket_depth - 1).max(0),
            '{' => brace_depth += 1,
            '}' => brace_depth = (brace_depth - 1).max(0),
            ':' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return Some(idx);
            }
            _ => {}
        }
    }

    None
}

fn skip_python_string_literal_in_iter(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    quote: char,
    triple: bool,
) {
    let mut consecutive_quotes = 0usize;
    let mut escaped = false;

    for (_, ch) in chars.by_ref() {
        if escaped {
            escaped = false;
            consecutive_quotes = 0;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            consecutive_quotes = 0;
            continue;
        }

        if ch == quote {
            if triple {
                consecutive_quotes += 1;
                if consecutive_quotes == 3 {
                    break;
                }
            } else {
                break;
            }
        } else {
            consecutive_quotes = 0;
        }
    }
}

fn extract_python_quoted_annotation_refs(
    line: &str,
    typing_literal_aliases: &HashSet<String>,
) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut refs = Vec::new();
    let mut index = 0usize;
    let mut in_annotation = false;
    let mut bracket_depth = 0i32;
    let mut paren_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut literal_bracket_depth: Option<i32> = None;

    while index < chars.len() {
        let ch = chars[index];

        if !in_annotation {
            if ch == ':' {
                in_annotation = true;
                bracket_depth = 0;
                paren_depth = 0;
                brace_depth = 0;
                literal_bracket_depth = None;
            } else if ch == '-' && index + 1 < chars.len() && chars[index + 1] == '>' {
                in_annotation = true;
                bracket_depth = 0;
                paren_depth = 0;
                brace_depth = 0;
                literal_bracket_depth = None;
                index += 1;
            }
            index += 1;
            continue;
        }

        match ch {
            '[' => {
                bracket_depth += 1;
                if literal_bracket_depth.is_none()
                    && is_python_literal_annotation_bracket(&chars, index, typing_literal_aliases)
                {
                    literal_bracket_depth = Some(bracket_depth);
                }
            }
            ']' => {
                bracket_depth = (bracket_depth - 1).max(0);
                if literal_bracket_depth.is_some_and(|depth| bracket_depth < depth) {
                    literal_bracket_depth = None;
                }
            }
            '(' => paren_depth += 1,
            ')' => {
                if bracket_depth == 0 && paren_depth == 0 && brace_depth == 0 {
                    in_annotation = false;
                    literal_bracket_depth = None;
                } else {
                    paren_depth = (paren_depth - 1).max(0);
                }
            }
            '{' => brace_depth += 1,
            '}' => brace_depth = (brace_depth - 1).max(0),
            '=' | ',' | ';' if bracket_depth == 0 && paren_depth == 0 && brace_depth == 0 => {
                in_annotation = false;
                literal_bracket_depth = None;
            }
            '\'' | '"' => {
                let quote = ch;
                index += 1;
                let start = index;
                let mut escaped = false;
                while index < chars.len() {
                    let inner = chars[index];
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == quote {
                        if literal_bracket_depth.is_none() {
                            refs.push(chars[start..index].iter().collect());
                        }
                        break;
                    }
                    index += 1;
                }
            }
            _ => {}
        }

        index += 1;
    }

    refs
}

fn is_python_literal_annotation_bracket(
    chars: &[char],
    bracket_index: usize,
    typing_literal_aliases: &HashSet<String>,
) -> bool {
    let Some(before_bracket) = chars.get(..bracket_index) else {
        return false;
    };

    let end = before_bracket
        .iter()
        .rposition(|ch| !ch.is_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(0);
    if end == 0 {
        return false;
    }

    let start = before_bracket[..end]
        .iter()
        .rposition(|ch| !(ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.'))
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let type_path: String = before_bracket[start..end].iter().collect();

    type_path
        .rsplit('.')
        .next()
        .is_some_and(|segment| segment == "Literal" || typing_literal_aliases.contains(segment))
}

fn strip_python_inline_strings(segment: &str) -> String {
    let mut sanitized = String::with_capacity(segment.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in segment.chars() {
        if escaped {
            escaped = false;
            if !in_single && !in_double {
                sanitized.push(ch);
            }
            continue;
        }

        if (in_single || in_double) && ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }

        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }

        if !in_single && !in_double {
            sanitized.push(ch);
        }
    }

    sanitized
}

fn python_line_without_comment(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (_idx, ch) in line.char_indices() {
        if escaped {
            result.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && (in_single || in_double) {
            result.push(ch);
            escaped = true;
            continue;
        }

        if ch == '\'' && !in_double {
            in_single = !in_single;
            result.push(ch);
            continue;
        }

        if ch == '"' && !in_single {
            in_double = !in_double;
            result.push(ch);
            continue;
        }

        if ch == '#' && !in_single && !in_double {
            return result;
        }

        result.push(ch);
    }

    result
}

fn strip_python_definition_targets(segment: String, strip_assignments: bool) -> String {
    let trimmed = segment.trim_start();
    let leading_len = segment.len() - trimmed.len();

    for prefix in ["async def ", "def ", "class "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let name_len = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .map(char::len_utf8)
                .sum::<usize>();
            if name_len > 0 {
                let name_start = leading_len + prefix.len();
                let name_end = name_start + name_len;
                let mut stripped = segment;
                stripped.replace_range(name_start..name_end, "");
                return stripped;
            }
        }
    }

    if strip_assignments {
        if let Some(eq_idx) = find_python_assignment_equal(&segment) {
            if let Some(colon_idx) = segment[..eq_idx].find(':') {
                return segment[colon_idx + 1..].to_string();
            }
            return segment[eq_idx + 1..].to_string();
        }
    }

    segment
}

fn find_python_assignment_equal(segment: &str) -> Option<usize> {
    let bytes = segment.as_bytes();
    let chars: Vec<(usize, char)> = segment.char_indices().collect();
    let mut index = 0usize;
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;

    while index < chars.len() {
        let (idx, ch) = chars[index];
        match ch {
            '\'' | '"' => {
                let quote = ch;
                let mut escaped = false;
                index += 1;
                while index < chars.len() {
                    let (_, inner) = chars[index];
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == quote {
                        break;
                    }
                    index += 1;
                }
            }
            '(' => paren_depth += 1,
            ')' => paren_depth = (paren_depth - 1).max(0),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = (bracket_depth - 1).max(0),
            '{' => brace_depth += 1,
            '}' => brace_depth = (brace_depth - 1).max(0),
            '=' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                let prev = idx.checked_sub(1).and_then(|prev_idx| bytes.get(prev_idx));
                let next = bytes.get(idx + 1);
                if !matches!(prev, Some(b'=' | b'!' | b'<' | b'>' | b':'))
                    && !matches!(next, Some(b'='))
                {
                    return Some(idx);
                }
            }
            _ => {}
        }

        index += 1;
    }

    None
}

fn strip_python_signature_default_values(segment: &str, state: &mut PythonRefScanState) -> String {
    let mut result = String::with_capacity(segment.len());
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;

    for ch in segment.chars() {
        if state.in_signature_default {
            match ch {
                '(' => state.signature_default_paren_depth += 1,
                '[' => state.signature_default_bracket_depth += 1,
                '{' => state.signature_default_brace_depth += 1,
                ')' => {
                    if state.signature_default_paren_depth == 0
                        && state.signature_default_bracket_depth == 0
                        && state.signature_default_brace_depth == 0
                    {
                        state.in_signature_default = false;
                        result.push(ch);
                    } else {
                        state.signature_default_paren_depth =
                            (state.signature_default_paren_depth - 1).max(0);
                    }
                }
                ']' => {
                    state.signature_default_bracket_depth =
                        (state.signature_default_bracket_depth - 1).max(0);
                }
                '}' => {
                    state.signature_default_brace_depth =
                        (state.signature_default_brace_depth - 1).max(0);
                }
                ',' if state.signature_default_paren_depth == 0
                    && state.signature_default_bracket_depth == 0
                    && state.signature_default_brace_depth == 0 =>
                {
                    state.in_signature_default = false;
                    result.push(ch);
                }
                _ => {}
            }
            continue;
        }

        match ch {
            '(' => {
                paren_depth += 1;
                result.push(ch);
            }
            ')' => {
                paren_depth = (paren_depth - 1).max(0);
                result.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                result.push(ch);
            }
            ']' => {
                bracket_depth = (bracket_depth - 1).max(0);
                result.push(ch);
            }
            '{' => {
                brace_depth += 1;
                result.push(ch);
            }
            '}' => {
                brace_depth = (brace_depth - 1).max(0);
                result.push(ch);
            }
            '=' if bracket_depth == 0 && brace_depth == 0 => {
                state.in_signature_default = true;
                state.signature_default_paren_depth = 0;
                state.signature_default_bracket_depth = 0;
                state.signature_default_brace_depth = 0;
            }
            _ => result.push(ch),
        }
    }

    result
}

fn truncate_python_context(context: &str) -> String {
    const MAX_CONTEXT_LEN: usize = 200;
    if context.len() <= MAX_CONTEXT_LEN {
        context.to_string()
    } else {
        let truncated: String = context.chars().take(MAX_CONTEXT_LEN).collect();
        format!("{}...", truncated)
    }
}

fn parse_python_parents(content: &str, node: &tree_sitter::Node) -> Vec<(String, String)> {
    let mut parents = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "attribute") {
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
    use crate::parsers::parse_file_symbols;

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
    fn test_parse_private_functions() {
        let content = r#"
def _module_helper():
    pass

@pytest.fixture
def _client():
    return Client()

class Worker:
    def _run(self):
        pass

    @property
    def _value(self):
        return 1
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        for name in ["_module_helper", "_client", "_run", "_value"] {
            assert!(
                symbols
                    .iter()
                    .any(|s| s.name == name && s.kind == SymbolKind::Function),
                "expected private Python function {name} to be indexed"
            );
        }
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
    fn test_parse_import_alias() {
        let content = "import sqlalchemy as sa\nimport numpy as np\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        assert!(symbols
            .iter()
            .any(|s| s.name == "sqlalchemy" && s.kind == SymbolKind::Import));
        assert!(symbols
            .iter()
            .any(|s| s.name == "sa" && s.kind == SymbolKind::Import));
        assert!(symbols
            .iter()
            .any(|s| s.name == "numpy" && s.kind == SymbolKind::Import));
        assert!(symbols
            .iter()
            .any(|s| s.name == "np" && s.kind == SymbolKind::Import));
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
    fn test_extract_refs_python_calls_and_filters_noise() {
        let content = r#"
from utils import helper_func
import logging

class LocalModel:
    pass

def _generate_token(payload):
    return payload

def handle(repo, obj, payload):
    token = _generate_token(payload)
    user = repo.find_by_id(payload["pk"])
    obj.do_something(user)
    if isinstance(user, MyModel):
        for index in range(10):
            print(index)
    return helper_func(token)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(!refs.iter().any(|r| r.name == "logging"));
        assert!(!refs.iter().any(|r| r.name == "LocalModel"));
        assert!(!refs.iter().any(|r| r.name == "handle"));
        assert!(!refs.iter().any(|r| r.name == "isinstance"));
        assert!(!refs.iter().any(|r| r.name == "range"));
        assert!(!refs.iter().any(|r| r.name == "print"));
        assert!(refs.iter().any(|r| r.name == "_generate_token"));
        assert!(refs.iter().any(|r| r.name == "find_by_id"));
        assert!(refs.iter().any(|r| r.name == "do_something"));
        assert!(refs.iter().any(|r| r.name == "helper_func"));
        assert!(refs.iter().any(|r| r.name == "MyModel"));
    }

    #[test]
    fn test_extract_refs_ignores_comments_and_docstrings() {
        let content = r#"
def handle(repo, payload):
    """Calls FakeService in docs only."""
    # _comment_only(payload)
    token = _generate_token(payload)  # InlineRef(payload)
    return repo.find_by_id(token)
"""
TrailingDocRef()
"""
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "_generate_token"));
        assert!(refs.iter().any(|r| r.name == "find_by_id"));
        assert!(!refs.iter().any(|r| r.name == "FakeService"));
        assert!(!refs.iter().any(|r| r.name == "_comment_only"));
        assert!(!refs.iter().any(|r| r.name == "InlineRef"));
        assert!(!refs.iter().any(|r| r.name == "TrailingDocRef"));
    }

    #[test]
    fn test_extract_refs_ignores_fstring_examples_inside_docstrings() {
        let content = r#"
def real():
    """
    Example:
        f"{DangerCall()}"
    """
    return helper()
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DangerCall"));
    }

    #[test]
    fn test_extract_refs_keeps_inline_body_calls_with_slice_colons() {
        let content = r#"
def wrapper(items): return helper(items[1:])
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_keeps_inline_body_calls_with_lambda_colons() {
        let content = r#"
def wrapper(): return helper(lambda x: x + 1)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_keeps_inline_body_calls_with_dict_comp_colons() {
        let content = r#"
def wrapper(xs): return helper({k: make(v) for k, v in xs})
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(refs.iter().any(|r| r.name == "make"));
    }

    #[test]
    fn test_extract_refs_keeps_fstring_expressions() {
        let content = r#"
def render(user):
    return f"{helper(user)} {service.format_user(user)}"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(refs.iter().any(|r| r.name == "format_user"));
    }

    #[test]
    fn test_extract_refs_keeps_nested_fstring_expressions() {
        let content = r#"
def render():
    return f"{helper({'a': 1})}"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_keeps_multiline_triple_quoted_fstring_expressions() {
        let content = "def render(user):\n    return f\"\"\"\n{helper(user)}\n\"\"\"\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_ignores_string_calls_inside_fstring_expressions() {
        let content = "def render():\n    return f'{helper(\"DangerCall()\")} {service.render(\"Boom()\")}'\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(refs.iter().any(|r| r.name == "render"));
        assert!(!refs.iter().any(|r| r.name == "DangerCall"));
        assert!(!refs.iter().any(|r| r.name == "Boom"));
    }

    #[test]
    fn test_extract_refs_keeps_mixed_case_fstring_prefixes() {
        let content = r#"
def render(user):
    return fR"{helper(user)} {service.format_user(user)}"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(refs.iter().any(|r| r.name == "format_user"));
    }

    #[test]
    fn test_extract_refs_ignores_fstring_comment_noise() {
        let content = "def render():\n    return helper()  # f\"{Danger()}\"\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "Danger"));
    }

    #[test]
    fn test_extract_refs_keeps_hash_line_multiline_fstring_interpolation() {
        let content = r##"
def build(service):
    return f"""
status
# {service.render()}
"""
"##;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "render"));
    }

    #[test]
    fn test_extract_refs_keeps_stringified_type_annotations() {
        let content = r#"
def build(user: "User") -> "Response":
    return helper(user)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "User"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_skips_literal_annotation_values() {
        let content = r#"
import typing
import typing as t
from typing import Literal
from typing import Literal as L

def build(
    method: Literal["GET", "POST"],
    patch_method: t.Literal["PATCH"],
    delete_method: typing.Literal["DELETE"],
    head_method: L["HEAD"],
    user: "User",
) -> "Response":
    return helper(user)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "User"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "GET"));
        assert!(!refs.iter().any(|r| r.name == "POST"));
        assert!(!refs.iter().any(|r| r.name == "PATCH"));
        assert!(!refs.iter().any(|r| r.name == "DELETE"));
        assert!(!refs.iter().any(|r| r.name == "HEAD"));
    }

    #[test]
    fn test_extract_refs_skips_typing_literal_alias_annotation_values() {
        let content = r#"
from typing import Literal as L

method: L["GET"]
response: "Response"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "GET"));
    }

    #[test]
    fn test_extract_refs_skips_typing_literal_alias_with_trailing_semicolon() {
        let content = r#"
from typing import Literal as L;

method: L["GET"]
response: "Response"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "GET"));
    }

    #[test]
    fn test_extract_refs_ignores_typing_literal_alias_text_inside_docstring() {
        let content = r#"
def docs():
    """
    from typing import Literal as L
    """

method: L["ResponseModel"]
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "ResponseModel"));
    }

    #[test]
    fn test_extract_refs_ignores_default_string_values_in_signatures() {
        let content = "def build(msg: str = \"ErrorMessage\"):\n    return helper()\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "ErrorMessage"));
    }

    #[test]
    fn test_extract_refs_ignores_camelcase_default_constructor_values_in_signatures() {
        let content = r#"
def build(service: Service = DefaultService(), response: Response = Factory.make()) -> Result:
    return helper(service, response)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Service"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "Result"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DefaultService"));
        assert!(!refs.iter().any(|r| r.name == "Factory"));
    }

    #[test]
    fn test_extract_refs_ignores_conditional_default_expression_tails_in_signatures() {
        let content = r#"
def build(
    service: Service = DefaultService() if enabled else FallbackService(),
) -> Response:
    return helper(service)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Service"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DefaultService"));
        assert!(!refs.iter().any(|r| r.name == "FallbackService"));
    }

    #[test]
    fn test_extract_refs_ignores_multiline_camelcase_default_values_in_signatures() {
        let content = r#"
def build(
    service: Service = DefaultService(
        config=DefaultConfig(),
    ),
) -> Response:
    return helper(service)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Service"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DefaultService"));
        assert!(!refs.iter().any(|r| r.name == "DefaultConfig"));
    }

    #[test]
    fn test_extract_refs_ignores_multiline_default_continuation_without_equals() {
        let content = r#"
def build(
    service: Service = (
        DefaultService()
    ),
) -> Response:
    return helper(service)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Service"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DefaultService"));
    }

    #[test]
    fn test_extract_refs_keeps_composite_stringified_type_annotations() {
        let content = r#"
def build(user: "User | None", items: "list[Item]") -> "Response | Error":
    return helper(user, items)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "User"));
        assert!(refs.iter().any(|r| r.name == "Item"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "Error"));
        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_keeps_same_file_public_symbol_usages() {
        let content = r#"
def helper(payload):
    return payload

class User:
    pass

def caller(payload):
    return helper(payload)

def build():
    return User()
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper" && r.line == 9));
        assert!(refs.iter().any(|r| r.name == "User" && r.line == 12));
        assert!(!refs.iter().any(|r| r.name == "helper" && r.line == 2));
        assert!(!refs.iter().any(|r| r.name == "User" && r.line == 5));
        assert!(!refs.iter().any(|r| r.name == "caller" && r.line == 8));
        assert!(!refs.iter().any(|r| r.name == "build" && r.line == 11));
    }

    #[test]
    fn test_extract_refs_keeps_positional_camelcase_before_keyword_argument() {
        let content = r#"
def configure(registry):
    registry.register(MyHandler, name="users")
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "MyHandler"));
        assert!(refs.iter().any(|r| r.name == "register"));
        assert!(!refs.iter().any(|r| r.name == "users"));
    }

    #[test]
    fn test_extract_refs_keeps_multiline_positional_camelcase_before_keyword_argument() {
        let content = r#"
def configure(registry):
    registry.register(
        MyHandler, name="users"
    )
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "MyHandler"));
        assert!(refs.iter().any(|r| r.name == "register"));
        assert!(!refs.iter().any(|r| r.name == "users"));
    }

    #[test]
    fn test_extract_refs_private_dotted_method_without_duplicates() {
        let content = r#"
class AuthService:
    def _get_jwt(self, user_id):
        return jwt.encode({"sub": user_id})

    def authenticate(self, user_id):
        return self._get_jwt(user_id)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        let private_method_refs = refs
            .iter()
            .filter(|reference| reference.name == "_get_jwt")
            .count();

        assert_eq!(private_method_refs, 1);
    }

    #[test]
    fn test_extract_refs_multiline_import_skips_import_block_and_keeps_call() {
        let content = r#"
from utils import (
    annotate_all_changes,
    annotate_tempo,
    determine_quadrant,
)

from models import (
    UserService,
    RepoFactory,
)

def build_queryset(queryset):
    return annotate_tempo(queryset)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(!refs.iter().any(|r| r.name == "annotate_all_changes"));
        assert!(!refs.iter().any(|r| r.name == "determine_quadrant"));
        assert!(!refs.iter().any(|r| r.name == "UserService"));
        assert!(!refs.iter().any(|r| r.name == "RepoFactory"));
        assert!(refs.iter().any(|r| r.name == "annotate_tempo"));
    }

    #[test]
    fn test_extract_refs_multiline_import_without_space_after_import_is_skipped() {
        let content = r#"
from models import(
    UserService,
    RepoFactory,
)

def build_queryset(queryset):
    return helper(queryset)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(!refs.iter().any(|r| r.name == "UserService"));
        assert!(!refs.iter().any(|r| r.name == "RepoFactory"));
        assert!(refs.iter().any(|r| r.name == "helper"));
    }

    #[test]
    fn test_extract_refs_backslash_import_skips_import_continuation() {
        let content = "from models import Foo, \\\n    Bar\n\ndef build(item: Foo) -> Foo:\n    return item\n";
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Foo"));
        assert!(!refs.iter().any(|r| r.name == "Bar"));
    }

    #[test]
    fn test_extract_refs_multiline_signature_skips_default_value_calls() {
        let content = r#"
def build_handler(
    service: Service = build_service(),
    repo: Repo = repo_factory.make_default(),
) -> Response:
    return Response.from_service(service)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Service"));
        assert!(refs.iter().any(|r| r.name == "Repo"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "build_service"));
        assert!(!refs.iter().any(|r| r.name == "make_default"));
    }

    #[test]
    fn test_extract_refs_inline_body_after_signature_still_indexes_calls() {
        let content = r#"
def wrapper(): return helper()
class Handler(BaseHandler): factory.make_default()
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(refs.iter().any(|r| r.name == "make_default"));
        assert!(refs.iter().any(|r| r.name == "BaseHandler"));
    }

    #[test]
    fn test_extract_refs_preserves_inheritance_and_type_annotation_refs() {
        let content = r#"
class ChildHandler(BaseHandler):
    def build(self, user: User, payload: Payload) -> Response:
        return Response.from_user(user)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "BaseHandler"));
        assert!(refs.iter().any(|r| r.name == "User"));
        assert!(refs.iter().any(|r| r.name == "Payload"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "ChildHandler"));
    }

    #[test]
    fn test_extract_refs_preserves_private_inheritance_and_type_annotation_refs() {
        let content = r#"
class _PrivateModel(_Base):
    def build(self, item: _Result) -> _Result:
        return self.convert(item)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "_Base"));
        assert!(refs.iter().any(|r| r.name == "_Result"));
        assert!(!refs.iter().any(|r| r.name == "_PrivateModel"));
    }

    #[test]
    fn test_extract_refs_keeps_nested_quoted_forward_annotations_only() {
        let content = r#"
def build(
    items: list["Item"],
    mapping: dict[str, "Response"] = "DefaultResponse",
) -> "_Result":
    return helper(items, mapping)
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Item"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(refs.iter().any(|r| r.name == "_Result"));
        assert!(refs.iter().any(|r| r.name == "helper"));
        assert!(!refs.iter().any(|r| r.name == "DefaultResponse"));
    }

    #[test]
    fn test_extract_refs_keeps_class_and_module_quoted_forward_annotations_only() {
        let content = r#"
module_field: list["Item"]
plain_default = "OrdinaryLiteral"

class Holder:
    field: list["Item"]
    mapping: dict[str, "Response"]
    title: str = "DefaultTitle"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Item"));
        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "OrdinaryLiteral"));
        assert!(!refs.iter().any(|r| r.name == "DefaultTitle"));
    }

    #[test]
    fn test_extract_refs_ignores_inline_body_string_after_quoted_return_annotation() {
        let content = r#"
def build() -> "Response": return "InlineBodyLiteral"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "InlineBodyLiteral"));
    }

    #[test]
    fn test_extract_refs_ignores_comment_string_after_quoted_variable_annotation() {
        let content = r#"
class Holder:
    field: "Response"  # "CommentLiteral"
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "CommentLiteral"));
    }

    #[test]
    fn test_extract_refs_stops_quoted_variable_annotation_at_semicolon() {
        let content = r#"
class Holder:
    field: "Response"; "InlineBodyLiteral"
    other: "Response"; print("CallLiteral")
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "Response"));
        assert!(!refs.iter().any(|r| r.name == "InlineBodyLiteral"));
        assert!(!refs.iter().any(|r| r.name == "CallLiteral"));
    }

    #[test]
    fn test_extract_refs_multiline_fstring_expression_uses_call_line_context() {
        let content = r#"
def render(service, user):
    return f"""
{
    service.render_user(
        user,
    )
}
"""
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        let reference = refs.iter().find(|r| r.name == "render_user").unwrap();

        assert_eq!(reference.line, 5);
        assert_eq!(reference.context, "service.render_user(");
    }

    #[test]
    fn test_extract_refs_multiline_fstring_expression_skips_wrapper_punctuation_context() {
        let content = r#"
def render(service, user):
    return f"""
{(
    service.render_user(
        user,
    )
)}
{[
    service.render_group(
        user,
    )
]}
"""
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();
        let user_reference = refs.iter().find(|r| r.name == "render_user").unwrap();
        let group_reference = refs.iter().find(|r| r.name == "render_group").unwrap();

        assert_eq!(user_reference.line, 5);
        assert_eq!(user_reference.context, "service.render_user(");
        assert_eq!(group_reference.line, 10);
        assert_eq!(group_reference.context, "service.render_group(");
    }

    #[test]
    fn test_extract_refs_ignores_fstring_marker_in_comment_after_multiline_fstring_close() {
        let content = r##"
def render():
    return f"""
{safe.render()}
"""  # f"{Danger()}"
"##;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "render"));
        assert!(!refs.iter().any(|r| r.name == "Danger"));
    }

    #[test]
    fn test_extract_refs_skips_typing_noise_from_annotations() {
        let content = r#"
from typing import Any, Callable, List, Optional
from models import User


def build_users(users: List[User], formatter: Callable[[User], str]) -> Optional[User]:
    return users[0] if users else None
"#;
        let symbols = PYTHON_PARSER.parse_symbols(content).unwrap();
        let refs = PYTHON_PARSER.extract_refs(content, &symbols).unwrap();

        assert!(refs.iter().any(|r| r.name == "User"));
        assert!(!refs.iter().any(|r| r.name == "List"));
        assert!(!refs.iter().any(|r| r.name == "Callable"));
        assert!(!refs.iter().any(|r| r.name == "Optional"));
        assert!(!refs.iter().any(|r| r.name == "Any"));
    }

    #[test]
    fn test_parse_file_symbols_uses_python_specific_refs() {
        let content = r#"
from utils import helper_func

def _generate_token(payload):
    return payload

def handle(repo, payload):
    token = _generate_token(payload)
    row = repo.find_by_id(payload["pk"])
    return helper_func(row, token)
"#;
        let (_symbols, refs) = parse_file_symbols(content, FileType::Python).unwrap();

        assert!(refs.iter().any(|r| r.name == "_generate_token"));
        assert!(refs.iter().any(|r| r.name == "find_by_id"));
        assert!(refs.iter().any(|r| r.name == "helper_func"));
    }

    #[test]
    fn test_parse_file_symbols_contract_for_python_refs_foundation() {
        let content = r#"
from models import User

class AuthService:
    def _get_jwt(self, user: "User") -> "Token":
        """Docs mention FakeService() but this is not code."""
        return jwt.encode({"sub": user.id})

    def authenticate(self, user: User):
        return self._get_jwt(user)
"#;
        let (symbols, refs) = parse_file_symbols(content, FileType::Python).unwrap();

        assert!(symbols
            .iter()
            .any(|s| s.name == "User" && s.kind == SymbolKind::Import));
        assert!(symbols
            .iter()
            .any(|s| s.name == "_get_jwt" && s.kind == SymbolKind::Function));

        assert!(refs.iter().any(|r| r.name == "_get_jwt" && r.line == 10));
        assert!(refs.iter().any(|r| r.name == "User" && r.line == 5));
        assert!(refs.iter().any(|r| r.name == "User" && r.line == 9));
        assert!(!refs.iter().any(|r| r.name == "FakeService"));
    }
}
