use std::borrow::Cow;

#[derive(Clone, Copy)]
struct SeparateTokens<'a>(&'a str);

/// Rust keywords that cannot be used as identifiers without escaping.
const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
];

pub fn from_sleigh(input: &str) -> Cow<'_, str> {
    let result = input
        .find('.')
        .map(|_| Cow::Owned(input.replace('.', "_")))
        .unwrap_or(Cow::Borrowed(input));
    // Append underscore to Rust keywords to avoid conflicts
    if RUST_KEYWORDS.contains(&result.as_ref()) {
        Cow::Owned(format!("{}_", result))
    } else {
        result
    }
}
