//! `cargo xtask bindgen`: the C headers vendored in `crates/cronet-sys/include`
//! become `crates/cronet-sys/src/bindings.rs`.
//!
//! The headers are machine-generated themselves (from `cronet.idl`) and use a
//! small, regular subset of C, so a hand-written reader is enough: no libclang.
//! Every function goes into one `cronet_api!` invocation, which `cronet-sys`
//! expands either into `extern "C"` declarations or into a table resolved from
//! a library loaded at run time.

use std::{fmt::Write as _, fs};

use anyhow::{Context, Result, bail};

use crate::{Workspace, rustfmt};

/// Read in this order; a later full definition replaces an earlier forward
/// declaration of the same struct.
const HEADERS: [&str; 3] = ["cronet.idl_c.h", "cronet_c.h", "bidirectional_stream_c.h"];

const EXPORT_MACROS: [&str; 2] = ["CRONET_EXPORT", "GRPC_SUPPORT_EXPORT"];

/// Declared as exported, but Chromium never defines them, so no build of the
/// library has them: binding them would only make loading fail.
const UNDEFINED: [&str; 2] = ["Cronet_UploadDataSink_Create", "bidirectional_stream_is_done"];

pub(crate) fn run(workspace: &Workspace) -> Result<()> {
    let include = workspace.sys_include();
    let mut items = Vec::new();
    for header in HEADERS {
        let path = include.join(header);
        let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        for declaration in split(&strip_preprocessor(&text)) {
            items.extend(parse(&declaration).with_context(|| format!("in {header}: `{}`", declaration.code))?);
        }
    }
    let output = workspace.root().join("crates/cronet-sys/src/bindings.rs");
    fs::write(&output, render(&items))?;
    rustfmt(&output)?;
    let functions = items
        .iter()
        .filter(|item| matches!(item.kind, Kind::Function(..)))
        .count();
    eprintln!("wrote {} ({functions} functions)", output.display());
    Ok(())
}

/// One top-level declaration, with the comment block right above it.
#[derive(Debug)]
struct Declaration {
    doc: Vec<String>,
    code: String,
}

#[derive(Debug)]
struct Item {
    doc: Vec<String>,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    /// `typedef struct X X;`
    Opaque(String),
    /// `typedef struct X { ... } X;`
    Struct(String, Vec<Field>),
    /// `typedef struct X* XPtr;`, `typedef const char* Cronet_String;`
    Alias(String, CType),
    /// `typedef enum X { A = 0, ... } X;`
    Enum(String, Vec<(String, i64)>),
    /// `typedef R (*X)(...);`
    FunctionPointer(String, Signature),
    /// `CRONET_EXPORT R x(...);`
    Function(String, Signature),
}

#[derive(Debug)]
struct Field {
    doc: Vec<String>,
    name: String,
    ty: FieldType,
}

#[derive(Debug)]
enum FieldType {
    Value(CType),
    Callback(Signature),
}

#[derive(Debug)]
struct Signature {
    returns: CType,
    parameters: Vec<(String, CType)>,
}

/// A C type: a base name, `const` on the base, and a pointer depth.
#[derive(Debug, Clone)]
struct CType {
    base: String,
    constant: bool,
    pointers: usize,
}

impl CType {
    fn parse(text: &str) -> Result<Self> {
        let pointers = text.matches('*').count();
        let mut words: Vec<&str> = text
            .split(|c: char| c == '*' || c.is_whitespace())
            .filter(|w| !w.is_empty())
            .collect();
        let constant = words.first() == Some(&"const");
        words.retain(|w| *w != "const");
        let [base] = words[..] else {
            bail!("cannot read type `{text}`")
        };
        Ok(Self {
            base: base.to_owned(),
            constant,
            pointers,
        })
    }

    fn is_void(&self) -> bool {
        self.base == "void" && self.pointers == 0
    }

    fn rust(&self) -> String {
        let base = match self.base.as_str() {
            "void" if self.pointers > 0 => "c_void",
            "char" => "c_char",
            "int" => "c_int",
            "bool" => "bool",
            "double" => "f64",
            "size_t" => "usize",
            "intptr_t" => "isize",
            "int32_t" => "i32",
            "int64_t" => "i64",
            "uint16_t" => "u16",
            "uint32_t" => "u32",
            "uint64_t" => "u64",
            other => other,
        };
        let mut rust = base.to_owned();
        for level in 0..self.pointers {
            let mutability = if self.constant && level == 0 { "const" } else { "mut" };
            rust = format!("*{mutability} {rust}");
        }
        rust
    }
}

/// Drops the preprocessor, and the `extern "C" {` / `}` that C++ sees.
fn strip_preprocessor(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_cplusplus = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#ifdef __cplusplus") {
            in_cplusplus = true;
        } else if in_cplusplus {
            in_cplusplus = !trimmed.starts_with("#endif");
        } else if !trimmed.starts_with('#') {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Splits source into `;`-terminated declarations. A comment block directly
/// above a declaration becomes its doc; a blank line detaches it. Comments
/// inside braces stay in the code, so struct bodies can be split the same way.
fn split(source: &str) -> Vec<Declaration> {
    let mut declarations = Vec::new();
    let mut doc = Vec::new();
    let mut code = String::new();
    let mut depth = 0usize;
    let mut blank_line = true;
    let mut rest = source;

    while let Some(c) = rest.chars().next() {
        let between = code.trim().is_empty();
        if let Some(after) = rest.strip_prefix("//") {
            let end = after.find('\n').unwrap_or(after.len());
            if depth > 0 {
                // As a block comment, so that joining lines cannot extend it.
                write!(code, "/*{}*/", &after[..end]).unwrap();
            } else if between {
                doc.extend(doc_lines(&after[..end]));
            }
            rest = &after[end..];
            blank_line = false;
            continue;
        }
        if let Some(after) = rest.strip_prefix("/*") {
            let end = after.find("*/").unwrap_or(after.len());
            if depth > 0 {
                code.push_str(&rest[..(end + 4).min(rest.len())]);
            } else if between {
                doc.extend(doc_lines(&after[..end]));
            }
            rest = after.get(end + 2..).unwrap_or("");
            blank_line = false;
            continue;
        }
        rest = &rest[c.len_utf8()..];
        match c {
            '\n' => {
                if blank_line && between {
                    doc.clear();
                }
                blank_line = true;
                code.push(' ');
            }
            ';' if depth == 0 => {
                declarations.push(Declaration {
                    doc: std::mem::take(&mut doc),
                    code: normalize(&code),
                });
                code.clear();
            }
            _ => {
                if !c.is_whitespace() {
                    blank_line = false;
                }
                match c {
                    '{' => depth += 1,
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                code.push(c);
            }
        }
    }
    declarations
}

/// Comment text as doc lines: `*` margins and indentation removed (an indented
/// line would read as a code block), rules such as `///////` dropped.
fn doc_lines(comment: &str) -> Vec<String> {
    if comment.trim().chars().all(|c| c == '/' || c == '*') {
        return Vec::new();
    }
    let mut lines: Vec<String> = comment
        .lines()
        .map(|line| {
            let line = line.trim();
            line.strip_prefix('*').unwrap_or(line).trim().to_owned()
        })
        .collect();
    while lines.first().is_some_and(String::is_empty) {
        lines.remove(0);
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

fn normalize(code: &str) -> String {
    code.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `None` for a function the library does not export: the header declares a
/// few (`Cronet_Metrics_*_move`) without `CRONET_EXPORT`, and some it never
/// defines ([`UNDEFINED`]). Binding them would fail to load or to link.
fn parse(declaration: &Declaration) -> Result<Option<Item>> {
    let code = declaration.code.as_str();
    let kind = if let Some(rest) = code.strip_prefix("typedef ") {
        parse_typedef(rest)?
    } else {
        let Some(code) = EXPORT_MACROS.iter().find_map(|export| code.strip_prefix(export)) else {
            return Ok(None);
        };
        let (name, signature) = parse_function(code.trim_start())?;
        if UNDEFINED.contains(&name.as_str()) {
            return Ok(None);
        }
        Kind::Function(name, signature)
    };
    Ok(Some(Item {
        doc: declaration.doc.clone(),
        kind,
    }))
}

fn parse_typedef(rest: &str) -> Result<Kind> {
    if let Some(body) = rest.strip_prefix("enum ") {
        let (name, variants, alias) = braced(body)?;
        ensure_same(name, alias)?;
        let variants = variants
            .split(',')
            .map(str::trim)
            .filter(|variant| !variant.is_empty())
            .map(|variant| {
                let (name, value) = variant.split_once('=').context("enum variant without a value")?;
                Ok((name.trim().to_owned(), value.trim().parse()?))
            })
            .collect::<Result<_>>()?;
        return Ok(Kind::Enum(name.to_owned(), variants));
    }
    if let Some(body) = rest.strip_prefix("struct ")
        && body.contains('{')
    {
        let (name, fields, alias) = braced(body)?;
        ensure_same(name, alias)?;
        let fields = split(fields).iter().map(parse_field).collect::<Result<_>>()?;
        return Ok(Kind::Struct(name.to_owned(), fields));
    }
    if rest.contains("(*") {
        let (name, signature) = parse_function_pointer(rest)?;
        return Ok(Kind::FunctionPointer(name, signature));
    }
    let (ty, name) = rest.rsplit_once(' ').context("typedef without a name")?;
    match ty.strip_prefix("struct ") {
        Some(tag) if !tag.contains('*') => {
            ensure_same(tag, name)?;
            Ok(Kind::Opaque(name.to_owned()))
        }
        Some(pointer) => Ok(Kind::Alias(name.to_owned(), CType::parse(pointer)?)),
        None => Ok(Kind::Alias(name.to_owned(), CType::parse(ty)?)),
    }
}

/// `Name { body } Alias` into its three parts.
fn braced(text: &str) -> Result<(&str, &str, &str)> {
    let open = text.find('{').context("expected `{`")?;
    let close = text.rfind('}').context("expected `}`")?;
    Ok((text[..open].trim(), &text[open + 1..close], text[close + 1..].trim()))
}

fn ensure_same(tag: &str, alias: &str) -> Result<()> {
    if tag != alias {
        bail!("typedef of `{tag}` names it `{alias}`");
    }
    Ok(())
}

fn parse_field(declaration: &Declaration) -> Result<Field> {
    let code = declaration.code.as_str();
    let (name, ty) = if code.contains("(*") {
        let (name, signature) = parse_function_pointer(code)?;
        (name, FieldType::Callback(signature))
    } else {
        let (ty, name) = split_name(code)?;
        (name, FieldType::Value(ty))
    };
    Ok(Field {
        doc: declaration.doc.clone(),
        name,
        ty,
    })
}

/// `R (*name)(parameters)`
fn parse_function_pointer(code: &str) -> Result<(String, Signature)> {
    let (returns, rest) = code.split_once("(*").context("expected `(*`")?;
    let (name, rest) = rest.split_once(')').context("expected `)`")?;
    let parameters = rest
        .trim()
        .strip_prefix('(')
        .and_then(|p| p.strip_suffix(')'))
        .context("expected parameters")?;
    Ok((name.trim().to_owned(), signature(returns, parameters)?))
}

/// `R name(parameters)`
fn parse_function(code: &str) -> Result<(String, Signature)> {
    let open = code.find('(').context("expected `(`")?;
    let parameters = code[open..]
        .strip_prefix('(')
        .and_then(|p| p.strip_suffix(')'))
        .context("expected parameters")?;
    let (returns, name) = split_name(&code[..open])?;
    Ok((
        name,
        Signature {
            returns,
            parameters: parameters_of(parameters)?,
        },
    ))
}

fn signature(returns: &str, parameters: &str) -> Result<Signature> {
    Ok(Signature {
        returns: CType::parse(returns)?,
        parameters: parameters_of(parameters)?,
    })
}

fn parameters_of(list: &str) -> Result<Vec<(String, CType)>> {
    let list = list.trim();
    if list.is_empty() || list == "void" {
        return Ok(Vec::new());
    }
    list.split(',')
        .map(|parameter| split_name(parameter).map(|(ty, name)| (name, ty)))
        .collect()
}

/// `type name` into the type and a Rust-safe name.
fn split_name(text: &str) -> Result<(CType, String)> {
    let text = text.trim();
    let at = text.rfind([' ', '*']).context("expected a type and a name")?;
    let name = text[at + 1..].trim();
    let name = match name {
        "self" | "type" | "ref" | "fn" | "move" | "match" | "loop" | "box" => format!("{name}_"),
        _ => name.to_owned(),
    };
    Ok((CType::parse(&text[..=at])?, name))
}

fn render(items: &[Item]) -> String {
    let defined_structs: Vec<&str> = items
        .iter()
        .filter_map(|item| match &item.kind {
            Kind::Struct(name, _) => Some(name.as_str()),
            _ => None,
        })
        .collect();

    let mut types = String::new();
    let mut functions = String::new();
    for item in items {
        match &item.kind {
            Kind::Opaque(name) if defined_structs.contains(&name.as_str()) => {}
            Kind::Opaque(name) => {
                doc(&mut types, &item.doc, "");
                writeln!(
                    types,
                    "#[repr(C)]\npub struct {name} {{\n    _data: [u8; 0],\n    \
                     _marker: PhantomData<(*mut u8, PhantomPinned)>,\n}}\n"
                )
                .unwrap();
            }
            Kind::Struct(name, fields) => {
                doc(&mut types, &item.doc, "");
                writeln!(types, "#[repr(C)]\n#[derive(Debug, Clone, Copy)]\npub struct {name} {{").unwrap();
                for field in fields {
                    doc(&mut types, &field.doc, "    ");
                    let ty = match &field.ty {
                        FieldType::Value(ty) => ty.rust(),
                        FieldType::Callback(signature) => function_pointer(signature),
                    };
                    writeln!(types, "    pub {}: {ty},", field.name).unwrap();
                }
                writeln!(types, "}}\n").unwrap();
            }
            Kind::Alias(name, ty) => {
                doc(&mut types, &item.doc, "");
                writeln!(types, "pub type {name} = {};\n", ty.rust()).unwrap();
            }
            Kind::Enum(name, variants) => {
                doc(&mut types, &item.doc, "");
                writeln!(types, "pub type {name} = c_int;").unwrap();
                for (variant, value) in variants {
                    writeln!(types, "pub const {variant}: {name} = {value};").unwrap();
                }
                types.push('\n');
            }
            Kind::FunctionPointer(name, signature) => {
                doc(&mut types, &item.doc, "");
                writeln!(types, "pub type {name} = {};\n", function_pointer(signature)).unwrap();
            }
            Kind::Function(name, signature) => {
                doc(&mut functions, &item.doc, "    ");
                let parameters = parameters(signature);
                let returns = returns(signature);
                let line = format!("    pub fn {name}({}){returns};", parameters.join(", "));
                if line.len() <= 120 {
                    writeln!(functions, "{line}").unwrap();
                } else {
                    writeln!(functions, "    pub fn {name}(").unwrap();
                    for parameter in parameters {
                        writeln!(functions, "        {parameter},").unwrap();
                    }
                    writeln!(functions, "    ){returns};").unwrap();
                }
            }
        }
    }

    format!(
        "// @generated by `cargo xtask bindgen` from the headers in `include/`. Do not edit.\n\n\
         use core::ffi::{{c_char, c_int, c_void}};\n\
         use core::marker::{{PhantomData, PhantomPinned}};\n\n\
         {types}\
         cronet_api! {{\n{functions}}}\n"
    )
}

fn parameters(signature: &Signature) -> Vec<String> {
    signature
        .parameters
        .iter()
        .map(|(name, ty)| format!("{name}: {}", ty.rust()))
        .collect()
}

fn returns(signature: &Signature) -> String {
    if signature.returns.is_void() {
        String::new()
    } else {
        format!(" -> {}", signature.returns.rust())
    }
}

fn function_pointer(signature: &Signature) -> String {
    format!(
        "Option<unsafe extern \"C\" fn({}){}>",
        parameters(signature).join(", "),
        returns(signature)
    )
}

fn doc(out: &mut String, lines: &[String], indent: &str) {
    for line in lines {
        if line.is_empty() {
            writeln!(out, "{indent}///").unwrap();
        } else {
            writeln!(out, "{indent}/// {line}").unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(source: &str) -> Vec<Item> {
        split(&strip_preprocessor(source))
            .iter()
            .filter_map(|d| parse(d).unwrap())
            .collect()
    }

    #[test]
    fn function_with_doc() {
        let parsed = items(
            "///////\n// Group.\n\n// Creates one.\nCRONET_EXPORT\nCronet_BufferPtr Cronet_Buffer_Create(void);\n",
        );
        let [
            Item {
                doc,
                kind: Kind::Function(name, signature),
            },
        ] = &parsed[..]
        else {
            panic!("{parsed:?}")
        };
        assert_eq!(doc, &["Creates one."]);
        assert_eq!(name, "Cronet_Buffer_Create");
        assert_eq!(signature.returns.rust(), "Cronet_BufferPtr");
        assert!(signature.parameters.is_empty());
    }

    #[test]
    fn pointers_and_const() {
        let parsed = items("GRPC_SUPPORT_EXPORT int f(const bidirectional_stream_header_array* headers, char* out);");
        let [
            Item {
                kind: Kind::Function(_, signature),
                ..
            },
        ] = &parsed[..]
        else {
            panic!()
        };
        assert_eq!(
            parameters(signature),
            ["headers: *const bidirectional_stream_header_array", "out: *mut c_char"]
        );
        assert_eq!(signature.returns.rust(), "c_int");
    }

    #[test]
    fn struct_with_callbacks() {
        let parsed = items(
            "typedef struct cb {\n  /* Ready.\n   */\n  void (*on_ready)(bidirectional_stream* stream);\n  \
             void* annotation;\n} cb;",
        );
        let [
            Item {
                kind: Kind::Struct(name, fields),
                ..
            },
        ] = &parsed[..]
        else {
            panic!("{parsed:?}")
        };
        assert_eq!(name, "cb");
        assert_eq!(fields[0].doc, ["Ready."]);
        assert!(matches!(&fields[0].ty, FieldType::Callback(s) if s.parameters.len() == 1));
        assert!(matches!(&fields[1].ty, FieldType::Value(t) if t.rust() == "*mut c_void"));
    }

    #[test]
    fn typedefs() {
        let parsed = items(
            "typedef const char* Cronet_String;\ntypedef struct Cronet_Buffer Cronet_Buffer;\n\
             typedef struct Cronet_Buffer* Cronet_BufferPtr;\ntypedef enum E { E_A = 0, E_B = -1, } E;\n\
             typedef intptr_t (*Dial)(void* context, const char* address, uint16_t port);",
        );
        assert!(matches!(&parsed[0].kind, Kind::Alias(n, t) if n == "Cronet_String" && t.rust() == "*const c_char"));
        assert!(matches!(&parsed[1].kind, Kind::Opaque(n) if n == "Cronet_Buffer"));
        assert!(matches!(&parsed[2].kind, Kind::Alias(_, t) if t.rust() == "*mut Cronet_Buffer"));
        assert!(matches!(&parsed[3].kind, Kind::Enum(_, v) if v[1] == ("E_B".to_owned(), -1)));
        assert!(matches!(&parsed[4].kind, Kind::FunctionPointer(n, s) if n == "Dial" && s.returns.rust() == "isize"));
    }

    #[test]
    fn cplusplus_guard_is_dropped() {
        let parsed = items(
            "#ifdef __cplusplus\nextern \"C\" {\n#endif\nCRONET_EXPORT void f(void);\n#ifdef __cplusplus\n}\n#endif\n",
        );
        assert_eq!(parsed.len(), 1);
    }
}
