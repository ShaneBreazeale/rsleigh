use std::collections::HashSet;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::{formater::*, Disassembler};

#[derive(Clone, Debug)]
pub struct RegistersEnum {
    pub name: Ident,
    pub registers: Vec<Ident>,
}

impl RegistersEnum {
    pub fn from_all(name: Ident, sleigh: &crate::Sleigh) -> Self {
        Self::from_iterator(name, sleigh.varnodes().iter())
    }

    //enum from only the Registers that can be printed
    #[allow(dead_code)]
    pub fn from_printable(name: Ident, sleigh: &crate::Sleigh) -> Self {
        use crate::display::DisplayElement::*;
        use crate::token::TokenFieldAttach;
        use crate::varnode::ContextAttach;
        let mut vars = HashSet::new();
        let add_varnodes = |vars: &mut HashSet<_>, id| {
            for (_i, var) in sleigh.attach_varnode(id).0.iter() {
                vars.insert(*var);
            }
        };
        for table in sleigh.tables().iter() {
            for constructor in table.constructors().iter() {
                for element in constructor.display.elements() {
                    match element {
                        Varnode(var) => {
                            vars.insert(*var);
                        }
                        Context(context) => {
                            match sleigh.context(*context).attach {
                                ContextAttach::NoAttach(_)
                                | ContextAttach::Literal(_) => {}
                                ContextAttach::Varnode(id) => {
                                    add_varnodes(&mut vars, id)
                                }
                            }
                        }
                        TokenField(token_field) => {
                            match sleigh.token_field(*token_field).attach {
                                TokenFieldAttach::NoAttach(_)
                                | TokenFieldAttach::Literal(_)
                                | TokenFieldAttach::Number(_, _) => {}
                                TokenFieldAttach::Varnode(id) => {
                                    add_varnodes(&mut vars, id)
                                }
                            }
                        }
                        InstStart(_) | InstNext(_) | Disassembly(_)
                        | Table(_) | Literal(_) | Space => {}
                    }
                }
            }
        }
        //TODO: from meaning, with could use the meaning to display
        Self::from_iterator(name, vars.into_iter().map(|id| sleigh.varnode(id)))
    }

    pub fn from_iterator<'a>(
        name: Ident,
        registers: impl Iterator<Item = &'a crate::varnode::Varnode>,
    ) -> Self {
        let registers = registers
            .map(|varnode| format_ident!("{}", from_sleigh(varnode.name())))
            .collect();
        Self { name, registers }
    }
    pub fn name(&self) -> &Ident {
        &self.name
    }
    pub fn registers(
        &self,
    ) -> impl Iterator<Item = (&Ident, crate::VarnodeId)> {
        self.registers
            .iter()
            .enumerate()
            .map(|(i, name)| (name, unsafe { crate::VarnodeId::from_raw(i) }))
    }
    pub fn register(&self, id: crate::VarnodeId) -> &Ident {
        &self.registers[id.to_raw()]
    }
    pub fn to_tokens(
        &self,
        tokens: &mut TokenStream,
        disassembler: &Disassembler,
    ) {
        let name = self.name();
        let elements_names = self.registers.iter();
        let elements_names2 = self.registers.iter();
        let elements_display = self
            .registers()
            .map(|(_name, id)| disassembler.sleigh.varnode(id).name());
        tokens.extend(quote! {
            #[derive(Clone, Copy, Debug)]
            pub enum #name {
                #(#elements_names),*
            }
            impl #name {
                pub fn as_str(&self) -> &'static str {
                    match self {
                        #(Self::#elements_names2 => #elements_display,)*
                    }
                }
            }
            impl core::fmt::Display for #name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{}", self.as_str())
                }
            }
        })
    }
}
