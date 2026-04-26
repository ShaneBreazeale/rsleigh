//! WebAssembly decompiler — parse .wasm binaries and emit C-like pseudocode.
//!
//! WASM is a stack-based VM, not a register machine, so we can't use the SLEIGH
//! pipeline. Instead, this module directly parses WASM bytecode and reconstructs
//! expressions by simulating the value stack.

use wasmparser::{BlockType, Operator, Parser, Payload, ValType};

/// A discovered WASM function with its name, type, and body offset.
pub struct WasmFunc {
    pub index: u32,
    pub name: String,
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
    pub locals: Vec<ValType>,
    pub body_offset: usize,
    pub body_size: usize,
}

/// Parse a WASM binary and return the list of functions.
pub fn parse_wasm(data: &[u8]) -> Vec<WasmFunc> {
    let mut functions = Vec::new();
    let mut func_types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut import_count: u32 = 0;
    let mut export_names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut code_idx: u32 = 0;

    let parser = Parser::new(0);
    for payload in parser.parse_all(data) {
        let Ok(payload) = payload else { continue };
        match payload {
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    if let Ok(ft) = ty {
                        let params: Vec<ValType> = ft.params().to_vec();
                        let results: Vec<ValType> = ft.results().to_vec();
                        func_types.push((params, results));
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for imp in reader {
                    if let Ok(imp) = imp {
                        if matches!(imp.ty, wasmparser::TypeRef::Func(_)) {
                            import_count += 1;
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for idx in reader {
                    if let Ok(idx) = idx {
                        func_type_indices.push(idx);
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    if let Ok(exp) = exp {
                        if exp.kind == wasmparser::ExternalKind::Func {
                            export_names.insert(exp.index, exp.name.to_string());
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let func_idx = import_count + code_idx;
                let type_idx = func_type_indices
                    .get(code_idx as usize)
                    .copied()
                    .unwrap_or(0) as usize;
                let (params, results) = func_types.get(type_idx).cloned().unwrap_or_default();

                let mut locals = Vec::new();
                if let Ok(local_reader) = body.get_locals_reader() {
                    for local in local_reader {
                        if let Ok((count, ty)) = local {
                            for _ in 0..count {
                                locals.push(ty);
                            }
                        }
                    }
                }

                let name = export_names
                    .get(&func_idx)
                    .cloned()
                    .unwrap_or_else(|| format!("func_{}", func_idx));

                let range = body.range();
                functions.push(WasmFunc {
                    index: func_idx,
                    name,
                    params,
                    results,
                    locals,
                    body_offset: range.start,
                    body_size: range.end - range.start,
                });
                code_idx += 1;
            }
            _ => {}
        }
    }
    functions
}

fn valtype_to_c(ty: ValType) -> &'static str {
    match ty {
        ValType::I32 => "int",
        ValType::I64 => "long",
        ValType::F32 => "float",
        ValType::F64 => "double",
        _ => "void",
    }
}

/// Decompile a single WASM function to C-like pseudocode.
pub fn decompile_wasm_func(data: &[u8], func: &WasmFunc, all_funcs: &[WasmFunc]) -> String {
    let mut out = String::new();

    // Function signature
    let ret_type = func
        .results
        .first()
        .map(|t| valtype_to_c(*t))
        .unwrap_or("void");
    let params_str: Vec<String> = func
        .params
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{} param_{}", valtype_to_c(*t), i))
        .collect();
    out.push_str(&format!("// {}\n", func.name));
    out.push_str(&format!(
        "{} {}({}) {{\n",
        ret_type,
        func.name,
        params_str.join(", ")
    ));

    // Local declarations
    let param_count = func.params.len();
    for (i, ty) in func.locals.iter().enumerate() {
        out.push_str(&format!("    {} local_{};\n", valtype_to_c(*ty), i));
    }
    if !func.locals.is_empty() {
        out.push_str("\n");
    }

    // Decompile body by simulating the value stack
    let body_start = func.body_offset;
    let body_end = func.body_offset + func.body_size;
    if body_end > data.len() {
        out.push_str("    // body out of bounds\n}\n");
        return out;
    }

    let parser = Parser::new(body_start as u64);
    let mut stack: Vec<String> = Vec::new();
    let mut indent = 1usize;

    for payload in parser.parse_all(&data[..body_end]) {
        let Ok(payload) = payload else { continue };
        if let Payload::CodeSectionEntry(body) = payload {
            let Ok(ops_reader) = body.get_operators_reader() else {
                continue;
            };
            for op in ops_reader {
                let Ok(op) = op else { continue };
                let pad = "    ".repeat(indent);
                match op {
                    Operator::LocalGet { local_index } => {
                        let name = if (local_index as usize) < param_count {
                            format!("param_{}", local_index)
                        } else {
                            format!("local_{}", local_index as usize - param_count)
                        };
                        stack.push(name);
                    }
                    Operator::LocalSet { local_index } => {
                        let val = stack.pop().unwrap_or("?".into());
                        let name = if (local_index as usize) < param_count {
                            format!("param_{}", local_index)
                        } else {
                            format!("local_{}", local_index as usize - param_count)
                        };
                        out.push_str(&format!("{}{} = {};\n", pad, name, val));
                    }
                    Operator::LocalTee { local_index } => {
                        let val = stack.last().cloned().unwrap_or("?".into());
                        let name = if (local_index as usize) < param_count {
                            format!("param_{}", local_index)
                        } else {
                            format!("local_{}", local_index as usize - param_count)
                        };
                        out.push_str(&format!("{}{} = {};\n", pad, name, val));
                    }
                    Operator::GlobalGet { global_index } => {
                        stack.push(format!("global_{}", global_index))
                    }
                    Operator::GlobalSet { global_index } => {
                        let val = stack.pop().unwrap_or("?".into());
                        out.push_str(&format!("{}global_{} = {};\n", pad, global_index, val));
                    }
                    Operator::I32Const { value } => stack.push(format!("{}", value)),
                    Operator::I64Const { value } => stack.push(format!("{}L", value)),
                    Operator::F32Const { value } => {
                        stack.push(format!("{}f", f32::from_bits(value.bits())))
                    }
                    Operator::F64Const { value } => {
                        stack.push(format!("{}", f64::from_bits(value.bits())))
                    }
                    // Arithmetic
                    Operator::I32Add | Operator::I64Add => binop(&mut stack, "+"),
                    Operator::I32Sub | Operator::I64Sub => binop(&mut stack, "-"),
                    Operator::I32Mul | Operator::I64Mul => binop(&mut stack, "*"),
                    Operator::I32DivS | Operator::I64DivS => binop(&mut stack, "/"),
                    Operator::I32DivU | Operator::I64DivU => binop(&mut stack, "/ (unsigned)"),
                    Operator::I32RemS | Operator::I64RemS => binop(&mut stack, "%"),
                    Operator::I32RemU | Operator::I64RemU => binop(&mut stack, "% (unsigned)"),
                    // Bitwise
                    Operator::I32And | Operator::I64And => binop(&mut stack, "&"),
                    Operator::I32Or | Operator::I64Or => binop(&mut stack, "|"),
                    Operator::I32Xor | Operator::I64Xor => binop(&mut stack, "^"),
                    Operator::I32Shl | Operator::I64Shl => binop(&mut stack, "<<"),
                    Operator::I32ShrS | Operator::I64ShrS => binop(&mut stack, ">>"),
                    Operator::I32ShrU | Operator::I64ShrU => binop(&mut stack, ">>> "),
                    // Comparison
                    Operator::I32Eqz | Operator::I64Eqz => {
                        let a = stack.pop().unwrap_or("?".into());
                        stack.push(format!("{} == 0", a));
                    }
                    Operator::I32Eq | Operator::I64Eq => binop(&mut stack, "=="),
                    Operator::I32Ne | Operator::I64Ne => binop(&mut stack, "!="),
                    Operator::I32LtS | Operator::I64LtS => binop(&mut stack, "<"),
                    Operator::I32GtS | Operator::I64GtS => binop(&mut stack, ">"),
                    Operator::I32LeS | Operator::I64LeS => binop(&mut stack, "<="),
                    Operator::I32GeS | Operator::I64GeS => binop(&mut stack, ">="),
                    Operator::I32LtU | Operator::I64LtU => binop(&mut stack, "< (unsigned)"),
                    Operator::I32GtU | Operator::I64GtU => binop(&mut stack, "> (unsigned)"),
                    Operator::I32LeU | Operator::I64LeU => binop(&mut stack, "<= (unsigned)"),
                    Operator::I32GeU | Operator::I64GeU => binop(&mut stack, ">= (unsigned)"),
                    // Float ops
                    Operator::F32Add | Operator::F64Add => binop(&mut stack, "+"),
                    Operator::F32Sub | Operator::F64Sub => binop(&mut stack, "-"),
                    Operator::F32Mul | Operator::F64Mul => binop(&mut stack, "*"),
                    Operator::F32Div | Operator::F64Div => binop(&mut stack, "/"),
                    // Memory
                    Operator::I32Load { memarg } => {
                        let addr = stack.pop().unwrap_or("?".into());
                        if memarg.offset > 0 {
                            stack.push(format!("*(int*)({} + {})", addr, memarg.offset));
                        } else {
                            stack.push(format!("*(int*)({})", addr));
                        }
                    }
                    Operator::I64Load { memarg } => {
                        let addr = stack.pop().unwrap_or("?".into());
                        if memarg.offset > 0 {
                            stack.push(format!("*(long*)({} + {})", addr, memarg.offset));
                        } else {
                            stack.push(format!("*(long*)({})", addr));
                        }
                    }
                    Operator::I32Store { memarg } => {
                        let val = stack.pop().unwrap_or("?".into());
                        let addr = stack.pop().unwrap_or("?".into());
                        if memarg.offset > 0 {
                            out.push_str(&format!(
                                "{}*(int*)({} + {}) = {};\n",
                                pad, addr, memarg.offset, val
                            ));
                        } else {
                            out.push_str(&format!("{}*(int*)({}) = {};\n", pad, addr, val));
                        }
                    }
                    Operator::I64Store { memarg } => {
                        let val = stack.pop().unwrap_or("?".into());
                        let addr = stack.pop().unwrap_or("?".into());
                        if memarg.offset > 0 {
                            out.push_str(&format!(
                                "{}*(long*)({} + {}) = {};\n",
                                pad, addr, memarg.offset, val
                            ));
                        } else {
                            out.push_str(&format!("{}*(long*)({}) = {};\n", pad, addr, val));
                        }
                    }
                    Operator::I32Load8S { memarg } | Operator::I32Load8U { memarg } => {
                        let addr = stack.pop().unwrap_or("?".into());
                        let expr = if memarg.offset > 0 {
                            format!("*(byte*)({} + {})", addr, memarg.offset)
                        } else {
                            format!("*(byte*)({})", addr)
                        };
                        stack.push(expr);
                    }
                    Operator::I32Load16S { memarg } | Operator::I32Load16U { memarg } => {
                        let addr = stack.pop().unwrap_or("?".into());
                        let expr = if memarg.offset > 0 {
                            format!("*(short*)({} + {})", addr, memarg.offset)
                        } else {
                            format!("*(short*)({})", addr)
                        };
                        stack.push(expr);
                    }
                    Operator::I32Store8 { memarg } => {
                        let val = stack.pop().unwrap_or("?".into());
                        let addr = stack.pop().unwrap_or("?".into());
                        out.push_str(&format!(
                            "{}*(byte*)({}{}) = {};\n",
                            pad,
                            addr,
                            if memarg.offset > 0 {
                                format!(" + {}", memarg.offset)
                            } else {
                                String::new()
                            },
                            val
                        ));
                    }
                    Operator::I32Store16 { memarg } => {
                        let val = stack.pop().unwrap_or("?".into());
                        let addr = stack.pop().unwrap_or("?".into());
                        out.push_str(&format!(
                            "{}*(short*)({}{}) = {};\n",
                            pad,
                            addr,
                            if memarg.offset > 0 {
                                format!(" + {}", memarg.offset)
                            } else {
                                String::new()
                            },
                            val
                        ));
                    }
                    // Control flow
                    Operator::Block { blockty } => {
                        out.push_str(&format!("{}{{ // block\n", pad));
                        indent += 1;
                    }
                    Operator::Loop { blockty } => {
                        out.push_str(&format!("{}while (1) {{ // loop\n", pad));
                        indent += 1;
                    }
                    Operator::If { blockty } => {
                        let cond = stack.pop().unwrap_or("?".into());
                        out.push_str(&format!("{}if ({}) {{\n", pad, cond));
                        indent += 1;
                    }
                    Operator::Else => {
                        if indent > 1 {
                            indent -= 1;
                        }
                        let pad = "    ".repeat(indent);
                        out.push_str(&format!("{}}} else {{\n", pad));
                        indent += 1;
                    }
                    Operator::End => {
                        if indent > 1 {
                            indent -= 1;
                        }
                        let pad = "    ".repeat(indent);
                        // Don't emit closing brace for the function body end
                        if indent >= 1 {
                            out.push_str(&format!("{}}}\n", pad));
                        }
                    }
                    Operator::Br { relative_depth } => {
                        out.push_str(&format!("{}break; // br {}\n", pad, relative_depth));
                    }
                    Operator::BrIf { relative_depth } => {
                        let cond = stack.pop().unwrap_or("?".into());
                        out.push_str(&format!(
                            "{}if ({}) break; // br_if {}\n",
                            pad, cond, relative_depth
                        ));
                    }
                    Operator::Return => {
                        let val = stack.pop();
                        if let Some(v) = val {
                            out.push_str(&format!("{}return {};\n", pad, v));
                        } else {
                            out.push_str(&format!("{}return;\n", pad));
                        }
                    }
                    Operator::Call { function_index } => {
                        let callee = all_funcs
                            .iter()
                            .find(|f| f.index == function_index)
                            .map(|f| f.name.as_str())
                            .unwrap_or("?");
                        // Get callee's param count from type info
                        let callee_params = all_funcs
                            .iter()
                            .find(|f| f.index == function_index)
                            .map(|f| f.params.len())
                            .unwrap_or(0);
                        let mut args = Vec::new();
                        for _ in 0..callee_params {
                            args.push(stack.pop().unwrap_or("?".into()));
                        }
                        args.reverse();
                        let callee_has_result = all_funcs
                            .iter()
                            .find(|f| f.index == function_index)
                            .map(|f| !f.results.is_empty())
                            .unwrap_or(false);
                        let call_expr = format!("{}({})", callee, args.join(", "));
                        if callee_has_result {
                            stack.push(call_expr);
                        } else {
                            out.push_str(&format!("{}{};\n", pad, call_expr));
                        }
                    }
                    Operator::Drop => {
                        stack.pop();
                    }
                    Operator::Select => {
                        let cond = stack.pop().unwrap_or("?".into());
                        let b = stack.pop().unwrap_or("?".into());
                        let a = stack.pop().unwrap_or("?".into());
                        stack.push(format!("{} ? {} : {}", cond, a, b));
                    }
                    Operator::MemoryGrow { .. } => {
                        let pages = stack.pop().unwrap_or("?".into());
                        stack.push(format!("memory_grow({})", pages));
                    }
                    Operator::MemorySize { .. } => {
                        stack.push("memory_size()".into());
                    }
                    // Conversions
                    Operator::I32WrapI64 => {
                        let v = stack.pop().unwrap_or("?".into());
                        stack.push(format!("(int){}", v));
                    }
                    Operator::I64ExtendI32S => {
                        let v = stack.pop().unwrap_or("?".into());
                        stack.push(format!("(long){}", v));
                    }
                    Operator::I64ExtendI32U => {
                        let v = stack.pop().unwrap_or("?".into());
                        stack.push(format!("(unsigned long){}", v));
                    }
                    Operator::Unreachable => {
                        out.push_str(&format!("{}__builtin_unreachable();\n", pad));
                    }
                    Operator::Nop => {}
                    _ => {
                        // Unknown op — emit as comment
                        // stack.push(format!("/* {:?} */", op));
                    }
                }
            }
        }
    }

    // If there's a value left on the stack and the function returns, emit return
    if !func.results.is_empty() {
        if let Some(val) = stack.pop() {
            let pad = "    ".repeat(1);
            out.push_str(&format!("{}return {};\n", pad, val));
        }
    }

    out.push_str("}\n");
    out
}

fn binop(stack: &mut Vec<String>, op: &str) {
    let b = stack.pop().unwrap_or("?".into());
    let a = stack.pop().unwrap_or("?".into());
    stack.push(format!("{} {} {}", a, op, b));
}
