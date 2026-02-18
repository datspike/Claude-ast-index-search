//! Tree-sitter based Java parser

use anyhow::Result;
use tree_sitter::{Language, Query, QueryCursor, StreamingIterator};
use std::sync::LazyLock;

use crate::db::SymbolKind;
use crate::parsers::ParsedSymbol;
use super::{LanguageParser, parse_tree, node_text, node_line, line_text};

static JAVA_LANGUAGE: LazyLock<Language> = LazyLock::new(|| tree_sitter_java::LANGUAGE.into());

static JAVA_QUERY: LazyLock<Query> = LazyLock::new(|| {
    Query::new(&JAVA_LANGUAGE, include_str!("queries/java.scm"))
        .expect("Failed to compile Java tree-sitter query")
});

pub static JAVA_PARSER: JavaParser = JavaParser;

pub struct JavaParser;

/// Significant Java/Spring annotations to track
const SIGNIFICANT_ANNOTATIONS: &[&str] = &[
    "RestController", "Controller", "Service", "Repository", "Component",
    "Entity", "Table", "Configuration", "Bean",
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "RequestMapping", "Autowired", "Override", "Transactional",
    "SpringBootApplication", "EnableAutoConfiguration",
    "Test", "BeforeEach", "AfterEach", "BeforeAll", "AfterAll",
    "Inject", "Singleton", "Provides", "Binds", "Module",
    "Data", "Value", "Builder", "AllArgsConstructor", "NoArgsConstructor",
    "Getter", "Setter", "Slf4j", "Log4j2",
];

impl LanguageParser for JavaParser {
    fn parse_symbols(&self, content: &str) -> Result<Vec<ParsedSymbol>> {
        let tree = parse_tree(content, &JAVA_LANGUAGE)?;
        let mut symbols = Vec::new();
        let query = &*JAVA_QUERY;
        let mut cursor = QueryCursor::new();

        let capture_names = query.capture_names();
        let idx = |name: &str| -> Option<u32> {
            capture_names.iter().position(|n| *n == name).map(|i| i as u32)
        };

        let idx_class_name = idx("class_name");
        let idx_class_node = idx("class_node");
        let idx_interface_name = idx("interface_name");
        let idx_interface_node = idx("interface_node");
        let idx_enum_name = idx("enum_name");
        let idx_enum_node = idx("enum_node");
        let idx_method_name = idx("method_name");
        let idx_method_node = idx("method_node");
        let idx_constructor_name = idx("constructor_name");
        let idx_constructor_node = idx("constructor_node");
        let idx_field_name = idx("field_name");
        let idx_field_node = idx("field_node");
        let idx_annotation_name = idx("annotation_name");
        let idx_annotation_call_name = idx("annotation_call_name");

        let mut emitted: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();

        let mut matches = cursor.matches(query, tree.root_node(), content.as_bytes());

        while let Some(m) = matches.next() {
            // === Classes ===
            if let Some(name_cap) = find_capture(m, idx_class_name) {
                let name = node_text(content, &name_cap.node);
                let line = node_line(&name_cap.node);
                if emitted.insert((name.to_string(), line)) {
                    let parents = find_capture(m, idx_class_node)
                        .map(|n| extract_class_parents(content, &n.node))
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

            // === Interfaces ===
            if let Some(name_cap) = find_capture(m, idx_interface_name) {
                let name = node_text(content, &name_cap.node);
                let line = node_line(&name_cap.node);
                if emitted.insert((name.to_string(), line)) {
                    let parents = find_capture(m, idx_interface_node)
                        .map(|n| extract_interface_parents(content, &n.node))
                        .unwrap_or_default();
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Interface,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents,
                    });
                }
                continue;
            }

            // === Enums ===
            if let Some(name_cap) = find_capture(m, idx_enum_name) {
                let name = node_text(content, &name_cap.node);
                let line = node_line(&name_cap.node);
                if emitted.insert((name.to_string(), line)) {
                    let parents = find_capture(m, idx_enum_node)
                        .map(|n| extract_enum_parents(content, &n.node))
                        .unwrap_or_default();
                    symbols.push(ParsedSymbol {
                        name: name.to_string(),
                        kind: SymbolKind::Enum,
                        line,
                        signature: line_text(content, line).trim().to_string(),
                        parents,
                    });
                }
                continue;
            }

            // === Methods (only inside class/interface/enum body) ===
            if let Some(name_cap) = find_capture(m, idx_method_name) {
                if let Some(node_cap) = find_capture(m, idx_method_node) {
                    if is_inside_type_body(&node_cap.node) {
                        let name = node_text(content, &name_cap.node);
                        let line = node_line(&name_cap.node);
                        if emitted.insert((name.to_string(), line)) {
                            symbols.push(ParsedSymbol {
                                name: name.to_string(),
                                kind: SymbolKind::Function,
                                line,
                                signature: line_text(content, line).trim().to_string(),
                                parents: vec![],
                            });
                        }
                    }
                }
                continue;
            }

            // === Constructors ===
            if let Some(name_cap) = find_capture(m, idx_constructor_name) {
                if let Some(node_cap) = find_capture(m, idx_constructor_node) {
                    if is_inside_type_body(&node_cap.node) {
                        let name = node_text(content, &name_cap.node);
                        let line = node_line(&name_cap.node);
                        if emitted.insert((name.to_string(), line)) {
                            symbols.push(ParsedSymbol {
                                name: name.to_string(),
                                kind: SymbolKind::Function,
                                line,
                                signature: line_text(content, line).trim().to_string(),
                                parents: vec![],
                            });
                        }
                    }
                }
                continue;
            }

            // === Fields (only inside class/enum body) ===
            if let Some(name_cap) = find_capture(m, idx_field_name) {
                if let Some(node_cap) = find_capture(m, idx_field_node) {
                    if is_inside_type_body(&node_cap.node) {
                        let name = node_text(content, &name_cap.node);
                        let line = node_line(&name_cap.node);
                        if emitted.insert((name.to_string(), line)) {
                            symbols.push(ParsedSymbol {
                                name: name.to_string(),
                                kind: SymbolKind::Property,
                                line,
                                signature: line_text(content, line).trim().to_string(),
                                parents: vec![],
                            });
                        }
                    }
                }
                continue;
            }

            // === Marker annotations (no arguments) ===
            if let Some(name_cap) = find_capture(m, idx_annotation_name) {
                let name = node_text(content, &name_cap.node);
                if SIGNIFICANT_ANNOTATIONS.contains(&name) {
                    let line = node_line(&name_cap.node);
                    if emitted.insert((format!("@{}", name), line)) {
                        symbols.push(ParsedSymbol {
                            name: format!("@{}", name),
                            kind: SymbolKind::Annotation,
                            line,
                            signature: line_text(content, line).trim().to_string(),
                            parents: vec![],
                        });
                    }
                }
                continue;
            }

            // === Annotations with arguments ===
            if let Some(name_cap) = find_capture(m, idx_annotation_call_name) {
                let name = node_text(content, &name_cap.node);
                if SIGNIFICANT_ANNOTATIONS.contains(&name) {
                    let line = node_line(&name_cap.node);
                    if emitted.insert((format!("@{}", name), line)) {
                        symbols.push(ParsedSymbol {
                            name: format!("@{}", name),
                            kind: SymbolKind::Annotation,
                            line,
                            signature: line_text(content, line).trim().to_string(),
                            parents: vec![],
                        });
                    }
                }
                continue;
            }
        }

        Ok(symbols)
    }
}

/// Check if a node is inside a class_body, interface_body, or enum_body
fn is_inside_type_body(node: &tree_sitter::Node) -> bool {
    node.parent()
        .map(|p| matches!(p.kind(), "class_body" | "interface_body" | "enum_body" | "enum_body_declarations"))
        .unwrap_or(false)
}

/// Extract parent types from a class_declaration (extends + implements)
fn extract_class_parents(content: &str, class_node: &tree_sitter::Node) -> Vec<(String, String)> {
    let mut parents = Vec::new();
    let mut cursor = class_node.walk();

    for child in class_node.children(&mut cursor) {
        match child.kind() {
            "superclass" => {
                // superclass -> "extends" type_identifier/generic_type
                if let Some(name) = extract_type_from_parent_node(&child, content) {
                    parents.push((name, "extends".to_string()));
                }
            }
            "super_interfaces" => {
                // super_interfaces -> "implements" type_list -> type_identifier+
                extract_type_list(&child, content, "implements", &mut parents);
            }
            _ => {}
        }
    }

    parents
}

/// Extract parent types from an interface_declaration (extends)
fn extract_interface_parents(content: &str, iface_node: &tree_sitter::Node) -> Vec<(String, String)> {
    let mut parents = Vec::new();
    let mut cursor = iface_node.walk();

    for child in iface_node.children(&mut cursor) {
        if child.kind() == "extends_interfaces" {
            extract_type_list(&child, content, "extends", &mut parents);
        }
    }

    parents
}

/// Extract parent types from an enum_declaration (implements)
fn extract_enum_parents(content: &str, enum_node: &tree_sitter::Node) -> Vec<(String, String)> {
    let mut parents = Vec::new();
    let mut cursor = enum_node.walk();

    for child in enum_node.children(&mut cursor) {
        if child.kind() == "super_interfaces" {
            extract_type_list(&child, content, "implements", &mut parents);
        }
    }

    parents
}

/// Extract a single type name from a superclass node
fn extract_type_from_parent_node(node: &tree_sitter::Node, content: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "type_identifier" => {
                return Some(node_text(content, &child).to_string());
            }
            "generic_type" => {
                // generic_type -> type_identifier type_arguments
                if let Some(first) = child.named_child(0) {
                    if first.kind() == "type_identifier" {
                        return Some(node_text(content, &first).to_string());
                    }
                }
            }
            "scoped_type_identifier" => {
                // Get the last identifier (e.g., com.example.MyClass -> MyClass)
                let text = node_text(content, &child);
                if let Some(last) = text.rsplit('.').next() {
                    return Some(last.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract types from a type_list (used in super_interfaces, extends_interfaces)
fn extract_type_list(
    node: &tree_sitter::Node,
    content: &str,
    inherit_kind: &str,
    parents: &mut Vec<(String, String)>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "type_list" => {
                // Recurse into type_list
                extract_type_list(&child, content, inherit_kind, parents);
            }
            "type_identifier" => {
                let name = node_text(content, &child);
                parents.push((name.to_string(), inherit_kind.to_string()));
            }
            "generic_type" => {
                if let Some(first) = child.named_child(0) {
                    if first.kind() == "type_identifier" {
                        let name = node_text(content, &first);
                        parents.push((name.to_string(), inherit_kind.to_string()));
                    }
                }
            }
            "scoped_type_identifier" => {
                let text = node_text(content, &child);
                if let Some(last) = text.rsplit('.').next() {
                    parents.push((last.to_string(), inherit_kind.to_string()));
                }
            }
            _ => {}
        }
    }
}

/// Find a capture by index in a match
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
        let content = "public class UserService {\n}\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "UserService" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn test_parse_class_with_extends() {
        let content = "public class UserController extends BaseController implements Serializable {\n}\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        let cls = symbols.iter().find(|s| s.name == "UserController").unwrap();
        assert!(cls.parents.iter().any(|(p, k)| p == "BaseController" && k == "extends"));
        assert!(cls.parents.iter().any(|(p, k)| p == "Serializable" && k == "implements"));
    }

    #[test]
    fn test_parse_interface() {
        let content = "public interface UserRepository extends JpaRepository {\n    User findByName(String name);\n}\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        let iface = symbols.iter().find(|s| s.name == "UserRepository").unwrap();
        assert_eq!(iface.kind, SymbolKind::Interface);
        assert!(iface.parents.iter().any(|(p, k)| p == "JpaRepository" && k == "extends"));
    }

    #[test]
    fn test_parse_enum() {
        let content = "public enum Status {\n    ACTIVE,\n    INACTIVE;\n}\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "Status" && s.kind == SymbolKind::Enum));
    }

    #[test]
    fn test_parse_methods() {
        let content = r#"public class UserService {
    public List<User> getUsers() { return null; }
    private void validate(User user) {}
    protected String format(String input) { return input; }
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "getUsers" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "validate" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "format" && s.kind == SymbolKind::Function));
    }

    #[test]
    fn test_parse_constructor() {
        let content = r#"public class User {
    private String name;
    public User(String name) {
        this.name = name;
    }
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "User" && s.kind == SymbolKind::Class));
        // Constructor is indexed as a function with the class name
        assert!(symbols.iter().filter(|s| s.name == "User").count() >= 2);
    }

    #[test]
    fn test_parse_fields() {
        let content = r#"public class Config {
    private String apiUrl;
    public static final int MAX_RETRIES = 3;
    protected List<String> items;
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "apiUrl" && s.kind == SymbolKind::Property));
        assert!(symbols.iter().any(|s| s.name == "MAX_RETRIES" && s.kind == SymbolKind::Property));
        assert!(symbols.iter().any(|s| s.name == "items" && s.kind == SymbolKind::Property));
    }

    #[test]
    fn test_parse_annotations() {
        let content = r#"@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/users")
    public List<User> getUsers() { return null; }

    @Override
    public String toString() { return ""; }
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "@RestController" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "@RequestMapping" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "@GetMapping" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "@Override" && s.kind == SymbolKind::Annotation));
    }

    #[test]
    fn test_spring_service() {
        let content = r#"@Service
public class PaymentService {
    @Autowired
    private PaymentRepository repository;

    @Transactional
    public Payment processPayment(PaymentRequest request) {
        return repository.save(request.toPayment());
    }
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "@Service" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "@Autowired" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "@Transactional" && s.kind == SymbolKind::Annotation));
        assert!(symbols.iter().any(|s| s.name == "PaymentService" && s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.name == "processPayment" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "repository" && s.kind == SymbolKind::Property));
    }

    #[test]
    fn test_comments_ignored() {
        let content = "// class FakeClass {}\npublic class RealClass {}\n/* void fakeMethod() {} */\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        assert!(symbols.iter().any(|s| s.name == "RealClass"));
        assert!(!symbols.iter().any(|s| s.name == "FakeClass"));
        assert!(!symbols.iter().any(|s| s.name == "fakeMethod"));
    }

    #[test]
    fn test_nonsignificant_annotations_skipped() {
        let content = r#"@SuppressWarnings("unchecked")
public class Foo {
    @Deprecated
    public void bar() {}
}
"#;
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        // SuppressWarnings and Deprecated are not in SIGNIFICANT_ANNOTATIONS
        assert!(!symbols.iter().any(|s| s.name == "@SuppressWarnings"));
        assert!(!symbols.iter().any(|s| s.name == "@Deprecated"));
        // But class and method should still be indexed
        assert!(symbols.iter().any(|s| s.name == "Foo" && s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.name == "bar" && s.kind == SymbolKind::Function));
    }

    #[test]
    fn test_generic_class_inheritance() {
        let content = "public class UserRepo extends CrudRepository<User, Long> implements UserRepository {\n}\n";
        let symbols = JAVA_PARSER.parse_symbols(content).unwrap();
        let cls = symbols.iter().find(|s| s.name == "UserRepo").unwrap();
        assert!(cls.parents.iter().any(|(p, k)| p == "CrudRepository" && k == "extends"));
        assert!(cls.parents.iter().any(|(p, k)| p == "UserRepository" && k == "implements"));
    }
}
