use proc_macro2::TokenStream;

use quote::{quote, ToTokens};

use crate::disassembly::{
    Assertation, Assignment, Expr, ExprElement, GlobalSet, Op, OpUnary,
    ReadScope, Variable, VariableId,
};

pub fn disassembly_op(x: impl ToTokens, op: &Op, y: impl ToTokens) -> TokenStream {
    match (crate::codegen::DISASSEMBLY_ALLOW_OVERFLOW, op) {
        (true, Op::Add) => quote! {#x.wrapping_add(#y)},
        (true, Op::Sub) => quote! {#x.wrapping_sub(#y)},
        (true, Op::Mul) => quote! {#x.wrapping_mul(#y)},
        (true, Op::Div) => quote! {#x.wrapping_div(#y)},
        (true, Op::Asr) => quote! {
            u32::try_from(#y).ok().and_then(|shr| #x.checked_shr(shr)).unwrap_or(0)
        },
        (true, Op::Lsl) => quote! {
            u32::try_from(#y).ok().and_then(|shl| #x.checked_shl(shl)).unwrap_or(0)
        },
        (false, Op::Add) => quote! {(#x + #y)},
        (false, Op::Sub) => quote! {(#x - #y)},
        (false, Op::Mul) => quote! {(#x * #y)},
        (false, Op::Div) => quote! {(#x / #y)},
        (false, Op::Asr) => quote! {(#x >> #y)},
        (false, Op::Lsl) => quote! {(#x << #y)},
        //bit op, works the same way unsigned/signed, so use unsigned
        (_, Op::And) => quote! {(#x & #y)},
        (_, Op::Or) => quote! {(#x | #y)},
        (_, Op::Xor) => quote! {(#x ^ #y)},
    }
}
pub fn op_unary(op: &OpUnary, x: impl ToTokens) -> TokenStream {
    match op {
        OpUnary::Negation => quote! {(!#x)},
        OpUnary::Negative => quote! {(-#x)},
    }
}
pub trait DisassemblyGenerator {
    fn global_set(&self, global_set: &GlobalSet) -> TokenStream;
    fn value(&self, value: &ReadScope) -> TokenStream;
    fn set_context(
        &self,
        id: &crate::ContextId,
        value: TokenStream,
    ) -> TokenStream;
    fn new_variable(
        &mut self,
        var_id: &VariableId,
        variable: &Variable,
    ) -> TokenStream;
    fn var_name(&self, var: &VariableId) -> TokenStream;
    fn expr(&self, expr: &Expr) -> TokenStream {
        match expr {
            Expr::Value(element) => self.expr_element(element),
            Expr::Op(_span, op, left, right) => {
                let x = self.expr(left);
                let y = self.expr(right);
                disassembly_op(x, op, y)
            }
        }
    }
    fn expr_element(&self, element: &ExprElement) -> TokenStream {
        match element {
            ExprElement::Value { value, location: _ } => self.value(value),
            ExprElement::Op(_span, op, inner) => {
                let x = self.expr(inner);
                op_unary(op, x)
            }
        }
    }
    fn set_variable(
        &self,
        var: &VariableId,
        value: TokenStream,
    ) -> TokenStream {
        let var_name = self.var_name(var);
        quote! { #var_name = #value; }
    }
    fn assignment(&self, ass: &Assignment) -> TokenStream {
        use crate::disassembly::WriteScope::*;
        let value = self.expr(&ass.right);
        match &ass.left {
            Context(context) => self.set_context(context, value),
            Local(variable) => self.set_variable(variable, value),
        }
    }
    fn disassembly(
        &self,
        assertations: &mut dyn Iterator<Item = &Assertation>,
    ) -> TokenStream {
        assertations
            .map(|ass| {
                use crate::disassembly::Assertation::*;
                match ass {
                    GlobalSet(global) => self.global_set(global),
                    Assignment(ass) => self.assignment(ass),
                }
            })
            .collect()
    }
}
