//! Minimal Icicle `.ins` corpus support.
//!
//! This intentionally starts as a decode/disassembly harness. Icicle's
//! upstream runner executes semantics in its VM; rsleigh does not have an
//! equivalent P-code executor yet, so semantics blocks are parsed and counted
//! but not evaluated.

use rsleigh_api::{Architecture, Decoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    pub load_addr: u64,
    pub isa_mode: u64,
    pub start_line: usize,
    pub instructions: Vec<InstructionTest>,
    pub semantics: Vec<SemanticsTest>,
    pub skip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionTest {
    pub bytes: Vec<u8>,
    pub expected_len: usize,
    pub disasm: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticsTest {
    pub inputs: Vec<Assignment>,
    pub outputs: Vec<Assignment>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assignment {
    Mem {
        addr: u64,
        perm: Option<String>,
        value: Vec<u8>,
    },
    Register {
        name: String,
        value: u128,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DecodeSummary {
    pub cases: usize,
    pub instructions: usize,
    pub skipped: usize,
    pub semantics_unsupported: usize,
}

pub fn parse(input: &str) -> Result<Vec<TestCase>, String> {
    Parser::new(input).parse_all()
}

pub fn check_decode(input: &str, arch: Architecture) -> Result<DecodeSummary, String> {
    let cases = parse(input)?;
    check_cases_decode(&cases, arch)
}

pub fn check_cases_decode(cases: &[TestCase], arch: Architecture) -> Result<DecodeSummary, String> {
    let mut summary = DecodeSummary::default();
    let mut decoder = Decoder::new(arch);

    for case in cases {
        summary.cases += 1;
        if case.skip {
            summary.skipped += 1;
            continue;
        }
        summary.semantics_unsupported += case.semantics.len();

        let mut addr = case.load_addr;
        for inst_test in &case.instructions {
            let inst = decoder.decode(&inst_test.bytes, addr).map_err(|err| {
                format!(
                    "line {}: decode failed at {addr:#x} for {:?}: {err}",
                    inst_test.line, inst_test.bytes
                )
            })?;

            if inst.len as usize != inst_test.expected_len {
                return Err(format!(
                    "line {}: decoded length {} != expected {} for {}",
                    inst_test.line, inst.len, inst_test.expected_len, inst_test.disasm
                ));
            }

            if normalize_disasm(&inst.disassembly) != normalize_disasm(&inst_test.disasm) {
                return Err(format!(
                    "line {}: decoded disasm `{}` != expected `{}`",
                    inst_test.line, inst.disassembly, inst_test.disasm
                ));
            }

            summary.instructions += 1;
            addr += inst.len;
        }
    }

    Ok(summary)
}

/// One per-instruction failure. `kind` carries which check tripped so a
/// triage script can bucket parse-vs-decode-vs-length-vs-disasm gaps.
#[derive(Debug, Clone)]
pub struct DecodeFailure {
    pub line: usize,
    pub addr: u64,
    pub kind: FailureKind,
    pub bytes: Vec<u8>,
    pub expected_disasm: String,
    pub got: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Decode,
    Length,
    Disasm,
}

#[derive(Default, Debug, Clone)]
pub struct DecodeReport {
    pub cases: usize,
    pub instructions_attempted: usize,
    pub instructions_passed: usize,
    pub skipped: usize,
    pub semantics_unsupported: usize,
    /// Cases skipped because they require an ISA-mode the rsleigh
    /// decoder cannot currently switch into (notably ARM Thumb,
    /// MIPS16). Tracked separately so they don't dilute the real
    /// pass rate or count as failures.
    pub unsupported_isa_mode: usize,
    pub failures: Vec<DecodeFailure>,
}

impl DecodeReport {
    pub fn instructions_failed(&self) -> usize {
        self.failures.len()
    }

    pub fn pass_rate(&self) -> f64 {
        if self.instructions_attempted == 0 {
            0.0
        } else {
            self.instructions_passed as f64 / self.instructions_attempted as f64
        }
    }
}

/// Tolerant variant: never returns `Err` for a per-case mismatch. Collects
/// every decode/length/disasm failure into the returned report. Used for
/// ground-truth corpora (e.g. Icicle's `.ins` fixtures) where bulk pass-rate
/// is the signal, not strict equality on the first byte stream.
pub fn check_cases_decode_report(cases: &[TestCase], arch: Architecture) -> DecodeReport {
    let mut report = DecodeReport::default();
    let mut decoder = Decoder::new(arch);

    for case in cases {
        report.cases += 1;
        if case.skip {
            report.skipped += 1;
            continue;
        }
        // ISA-mode != 0 means "non-default decoding mode" in the
        // upstream icicle DSL (e.g. ARM Thumb, MIPS16). rsleigh's
        // Decoder API doesn't currently accept an isa_mode hint —
        // skip those cases rather than treat them as decode failures.
        // Filed in .opt/ideas.md as a structural API gap.
        if case.isa_mode != 0 {
            report.unsupported_isa_mode += 1;
            continue;
        }
        report.semantics_unsupported += case.semantics.len();

        let mut addr = case.load_addr;
        for inst_test in &case.instructions {
            report.instructions_attempted += 1;

            // Icicle's negative-test convention: unencodable bytes carry
            // expected disasm == "invalid_instruction". Rsleigh signals
            // those as `Err`, which is the correct behaviour — count as
            // pass when the corpus is asserting non-decode.
            let expected_invalid = normalize_disasm(&inst_test.disasm)
                == normalize_disasm("invalid_instruction");

            let inst = match decoder.decode(&inst_test.bytes, addr) {
                Ok(i) => i,
                Err(err) => {
                    if expected_invalid {
                        report.instructions_passed += 1;
                    } else {
                        report.failures.push(DecodeFailure {
                            line: inst_test.line,
                            addr,
                            kind: FailureKind::Decode,
                            bytes: inst_test.bytes.clone(),
                            expected_disasm: inst_test.disasm.clone(),
                            got: format!("{err}"),
                        });
                    }
                    // Can't advance `addr` reliably without a length —
                    // skip remaining instructions in this case.
                    break;
                }
            };

            if expected_invalid {
                // Decoder returned a "valid" instruction where icicle
                // expects an invalid_instruction signal. That IS a
                // semantic failure — record as Decode-class.
                report.failures.push(DecodeFailure {
                    line: inst_test.line,
                    addr,
                    kind: FailureKind::Decode,
                    bytes: inst_test.bytes.clone(),
                    expected_disasm: inst_test.disasm.clone(),
                    got: format!("decoded as `{}`", inst.disassembly),
                });
                addr += inst.len;
                continue;
            }

            if inst.len as usize != inst_test.expected_len {
                report.failures.push(DecodeFailure {
                    line: inst_test.line,
                    addr,
                    kind: FailureKind::Length,
                    bytes: inst_test.bytes.clone(),
                    expected_disasm: inst_test.disasm.clone(),
                    got: format!("len={}", inst.len),
                });
            } else if normalize_disasm(&inst.disassembly) != normalize_disasm(&inst_test.disasm) {
                report.failures.push(DecodeFailure {
                    line: inst_test.line,
                    addr,
                    kind: FailureKind::Disasm,
                    bytes: inst_test.bytes.clone(),
                    expected_disasm: inst_test.disasm.clone(),
                    got: inst.disassembly.clone(),
                });
            } else {
                report.instructions_passed += 1;
            }

            addr += inst.len;
        }
    }

    report
}

fn normalize_disasm(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Number(String),
    String(String),
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,
    Colon,
    Semicolon,
    Equals,
    RightArrow,
    Comma,
    Bar,
    Minus,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
    col: usize,
}

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn next_token(&mut self) -> Result<Token, String> {
        self.skip_ws_and_comments();
        let line = self.line;
        let col = self.col;
        let Some(ch) = self.peek_char() else {
            return Ok(Token {
                kind: TokenKind::Eof,
                line,
                col,
            });
        };

        let kind = match ch {
            '[' => {
                self.bump_char();
                TokenKind::OpenBracket
            }
            ']' => {
                self.bump_char();
                TokenKind::CloseBracket
            }
            '{' => {
                self.bump_char();
                TokenKind::OpenBrace
            }
            '}' => {
                self.bump_char();
                TokenKind::CloseBrace
            }
            ':' => {
                self.bump_char();
                TokenKind::Colon
            }
            ';' => {
                self.bump_char();
                TokenKind::Semicolon
            }
            ',' => {
                self.bump_char();
                TokenKind::Comma
            }
            '|' => {
                self.bump_char();
                TokenKind::Bar
            }
            '-' => {
                self.bump_char();
                TokenKind::Minus
            }
            '=' => {
                self.bump_char();
                if self.peek_char() == Some('>') {
                    self.bump_char();
                    TokenKind::RightArrow
                } else {
                    TokenKind::Equals
                }
            }
            '"' => TokenKind::String(self.read_string(line, col)?),
            '@' => {
                self.bump_char();
                let ident = self.read_while(|c| is_ident_tail(c));
                TokenKind::Ident(format!("@{ident}"))
            }
            c if c.is_ascii_digit() => TokenKind::Number(self.read_while(is_word_char)),
            c if is_ident_head(c) => TokenKind::Ident(self.read_while(is_word_char)),
            _ => return Err(format!("line {line}:{col}: unexpected character `{ch}`")),
        };

        Ok(Token { kind, line, col })
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while self.peek_char().is_some_and(|c| c.is_ascii_whitespace()) {
                self.bump_char();
            }
            if self.input[self.pos..].starts_with("//") {
                while self.peek_char().is_some_and(|c| c != '\n') {
                    self.bump_char();
                }
                continue;
            }
            break;
        }
    }

    fn read_string(&mut self, line: usize, col: usize) -> Result<String, String> {
        self.bump_char();
        let mut out = String::new();
        while let Some(ch) = self.peek_char() {
            match ch {
                '"' => {
                    self.bump_char();
                    return Ok(out);
                }
                '\n' | '\r' => return Err(format!("line {line}:{col}: unterminated string")),
                '\\' => {
                    self.bump_char();
                    let Some(escaped) = self.bump_char() else {
                        return Err(format!("line {line}:{col}: unterminated escape"));
                    };
                    out.push(escaped);
                }
                _ => {
                    self.bump_char();
                    out.push(ch);
                }
            }
        }
        Err(format!("line {line}:{col}: unterminated string"))
    }

    fn read_while(&mut self, mut pred: impl FnMut(char) -> bool) -> String {
        let mut out = String::new();
        while let Some(ch) = self.peek_char() {
            if !pred(ch) {
                break;
            }
            self.bump_char();
            out.push(ch);
        }
        out
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }
}

fn is_ident_head(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '.'
}

fn is_ident_tail(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

fn is_word_char(c: char) -> bool {
    is_ident_tail(c)
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    peeked: Option<Token>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lexer: Lexer::new(input),
            peeked: None,
        }
    }

    fn parse_all(&mut self) -> Result<Vec<TestCase>, String> {
        let mut cases = Vec::new();
        while !matches!(self.peek()?.kind, TokenKind::Eof) {
            cases.push(self.parse_case()?);
        }
        Ok(cases)
    }

    fn parse_case(&mut self) -> Result<TestCase, String> {
        let skip = self.consume_ident("@skip")?;
        let load_addr = self.parse_num()?;
        let isa_mode = if matches!(self.peek()?.kind, TokenKind::Bar) {
            self.bump()?;
            self.parse_num()?
        } else {
            0
        };
        let start_line = self.peek()?.line;
        let instructions = if matches!(self.peek()?.kind, TokenKind::OpenBrace) {
            self.bump()?;
            let mut entries = Vec::new();
            while !matches!(self.peek()?.kind, TokenKind::CloseBrace) {
                entries.push(self.parse_instruction()?);
            }
            self.expect_simple(TokenKind::CloseBrace)?;
            entries
        } else {
            vec![self.parse_instruction()?]
        };

        let semantics = match self.peek()?.kind {
            TokenKind::Semicolon => {
                self.bump()?;
                Vec::new()
            }
            TokenKind::OpenBrace => {
                self.bump()?;
                let mut entries = Vec::new();
                while !matches!(self.peek()?.kind, TokenKind::CloseBrace) {
                    entries.push(self.parse_semantics()?);
                    self.expect_simple(TokenKind::Semicolon)?;
                }
                self.expect_simple(TokenKind::CloseBrace)?;
                entries
            }
            _ => {
                let entry = self.parse_semantics()?;
                self.expect_simple(TokenKind::Semicolon)?;
                vec![entry]
            }
        };

        Ok(TestCase {
            load_addr,
            isa_mode,
            start_line,
            instructions,
            semantics,
            skip,
        })
    }

    fn parse_instruction(&mut self) -> Result<InstructionTest, String> {
        let bytes = self.parse_byte_array()?;
        let expected_len = if matches!(self.peek()?.kind, TokenKind::Equals) {
            self.bump()?;
            self.parse_num::<usize>()?
        } else {
            bytes.len()
        };
        let token = self.bump()?;
        let line = token.line;
        let disasm = match token.kind {
            TokenKind::String(s) => s,
            other => return Err(self.unexpected(token.line, token.col, "string", &other)),
        };
        Ok(InstructionTest {
            bytes,
            expected_len,
            disasm,
            line,
        })
    }

    fn parse_byte_array(&mut self) -> Result<Vec<u8>, String> {
        self.expect_simple(TokenKind::OpenBracket)?;
        let mut bytes = Vec::new();
        while !matches!(self.peek()?.kind, TokenKind::CloseBracket) {
            let token = self.bump()?;
            let raw = match &token.kind {
                TokenKind::Ident(s) | TokenKind::Number(s) => s,
                other => return Err(self.unexpected(token.line, token.col, "hex byte", other)),
            };
            let byte =
                u8::from_str_radix(raw.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .map_err(|err| {
                        format!(
                            "line {}:{}: invalid byte literal `{raw}`: {err}",
                            token.line, token.col
                        )
                    })?;
            bytes.push(byte);
        }
        self.expect_simple(TokenKind::CloseBracket)?;
        Ok(bytes)
    }

    fn parse_semantics(&mut self) -> Result<SemanticsTest, String> {
        let line = self.peek()?.line;
        let inputs = if matches!(self.peek()?.kind, TokenKind::RightArrow) {
            Vec::new()
        } else {
            self.parse_assignments_until_arrow()?
        };
        self.expect_simple(TokenKind::RightArrow)?;
        let outputs = self.parse_assignment_list()?;
        Ok(SemanticsTest {
            inputs,
            outputs,
            line,
        })
    }

    fn parse_assignments_until_arrow(&mut self) -> Result<Vec<Assignment>, String> {
        let mut entries = Vec::new();
        loop {
            entries.push(self.parse_assignment()?);
            match self.peek()?.kind {
                TokenKind::Comma => {
                    self.bump()?;
                }
                TokenKind::RightArrow => break,
                ref other => {
                    let t = self.peek()?;
                    return Err(self.unexpected(t.line, t.col, "`,` or `=>`", other));
                }
            }
        }
        Ok(entries)
    }

    fn parse_assignment_list(&mut self) -> Result<Vec<Assignment>, String> {
        let mut entries = Vec::new();
        loop {
            entries.push(self.parse_assignment()?);
            if !matches!(self.peek()?.kind, TokenKind::Comma) {
                break;
            }
            self.bump()?;
        }
        Ok(entries)
    }

    fn parse_assignment(&mut self) -> Result<Assignment, String> {
        let token = self.bump()?;
        let name = match token.kind {
            TokenKind::Ident(s) => s,
            other => {
                return Err(self.unexpected(token.line, token.col, "assignment target", &other))
            }
        };

        if name == "mem" {
            self.expect_simple(TokenKind::OpenBracket)?;
            let addr = self.parse_num()?;
            self.expect_simple(TokenKind::CloseBracket)?;
            let perm = if matches!(self.peek()?.kind, TokenKind::Colon) {
                self.bump()?;
                let tok = self.bump()?;
                match tok.kind {
                    TokenKind::Ident(s) => Some(s),
                    other => return Err(self.unexpected(tok.line, tok.col, "permission", &other)),
                }
            } else {
                None
            };
            self.expect_simple(TokenKind::Equals)?;
            let value = if matches!(self.peek()?.kind, TokenKind::OpenBracket) {
                self.parse_byte_array()?
            } else {
                let len = self.parse_num::<usize>()?;
                vec![0; len]
            };
            Ok(Assignment::Mem { addr, perm, value })
        } else {
            self.expect_simple(TokenKind::Equals)?;
            let value = self.parse_num()?;
            Ok(Assignment::Register { name, value })
        }
    }

    fn parse_num<T>(&mut self) -> Result<T, String>
    where
        T: TryFrom<u128>,
    {
        let negative = if matches!(self.peek()?.kind, TokenKind::Minus) {
            self.bump()?;
            true
        } else {
            false
        };
        let token = self.bump()?;
        let raw = match &token.kind {
            TokenKind::Number(s) | TokenKind::Ident(s) => s.replace('_', ""),
            other => return Err(self.unexpected(token.line, token.col, "number", other)),
        };
        let value = parse_num_literal(&raw).map_err(|err| {
            format!(
                "line {}:{}: invalid number literal `{raw}`: {err}",
                token.line, token.col
            )
        })?;
        let signed = if negative {
            (-(value as i128)) as u128
        } else {
            value
        };
        T::try_from(signed)
            .map_err(|_| format!("line {}:{}: number out of range", token.line, token.col))
    }

    fn consume_ident(&mut self, expected: &str) -> Result<bool, String> {
        let token = self.peek()?;
        if matches!(&token.kind, TokenKind::Ident(s) if s == expected) {
            self.bump()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect_simple(&mut self, expected: TokenKind) -> Result<(), String> {
        let token = self.bump()?;
        if std::mem::discriminant(&token.kind) == std::mem::discriminant(&expected) {
            Ok(())
        } else {
            Err(self.unexpected(token.line, token.col, &format!("{expected:?}"), &token.kind))
        }
    }

    fn peek(&mut self) -> Result<Token, String> {
        if self.peeked.is_none() {
            self.peeked = Some(self.lexer.next_token()?);
        }
        Ok(self.peeked.clone().expect("peeked token"))
    }

    fn bump(&mut self) -> Result<Token, String> {
        if let Some(token) = self.peeked.take() {
            Ok(token)
        } else {
            self.lexer.next_token()
        }
    }

    fn unexpected(&self, line: usize, col: usize, expected: &str, got: &TokenKind) -> String {
        format!("line {line}:{col}: expected {expected}, got {got:?}")
    }
}

fn parse_num_literal(raw: &str) -> Result<u128, std::num::ParseIntError> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u128::from_str_radix(trim_leading_zeros(hex), 16)
    } else if raw.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        u128::from_str_radix(trim_leading_zeros(raw), 16)
    } else {
        raw.parse()
    }
}

fn trim_leading_zeros(input: &str) -> &str {
    let trimmed = input.trim_start_matches('0');
    if !input.is_empty() && trimmed.is_empty() {
        "0"
    } else {
        trimmed
    }
}
