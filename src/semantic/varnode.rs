use std::collections::HashMap;

use crate::meaning::Meaning;
use crate::semantic::{AttachLiteralId, AttachVarnodeId, SpaceId, ValueFmt, VarnodeId};
use crate::{ContextId, FieldBits, NumberNonZeroUnsigned, NumberUnsigned, Span};

use super::inner::Sleigh;

#[derive(Clone, Debug)]
pub struct Bitrange {
    pub location: Span,
    pub bits: FieldBits,
    pub varnode: VarnodeId,
}

// Context is just bitrange with noflow and maybe attach
#[derive(Clone, Debug)]
pub struct Context {
    pub(crate) name: Box<str>,
    pub bitrange: Bitrange,
    pub noflow: bool,
    pub attach: ContextAttach,
}

impl Context {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_signed(&self) -> bool {
        match self.attach {
            ContextAttach::NoAttach(fmt) => fmt.signed,
            ContextAttach::Varnode(_) | ContextAttach::Literal(_) => false,
        }
    }

    pub fn meaning(&self) -> Meaning {
        match self.attach {
            ContextAttach::NoAttach(fmt) => Meaning::NoAttach(fmt),
            ContextAttach::Varnode(id) => Meaning::Varnode(id),
            ContextAttach::Literal(id) => Meaning::Literal(id),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ContextAttach {
    /// No attach, just use the raw value
    NoAttach(ValueFmt),
    /// The value translate into a varnode
    Varnode(AttachVarnodeId),
    /// The value translate into a string for printing
    Literal(AttachLiteralId),
    // NOTE AttachNumber don't make seense, just assign the correct value to
    // the context
}

#[derive(Clone, Debug)]
pub struct Varnode {
    pub(crate) name: Box<str>,
    pub location: Span,
    /// Address of this varnode in the Address Space
    pub address: NumberUnsigned,
    /// Size of the varnode in bytes
    pub len_bytes: NumberNonZeroUnsigned,
    /// AddressSpace this varnode belongs to
    pub space: SpaceId,
}

impl Varnode {
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Create a single and packed type for Context memory and it's mapping to the
/// original memory.
#[derive(Debug, Clone)]
pub struct ContextMemoryMapping {
    pub(crate) mapping: HashMap<ContextId, FieldBits>,
    pub memory_bits: NumberUnsigned,
}

impl ContextMemoryMapping {
    pub(crate) fn map_all(sleigh: &Sleigh) -> Self {
        // 1. get all the contexts, separated by varnode
        let mut context_mapping: HashMap<VarnodeId, Vec<ContextId>> = HashMap::new();
        for (i, context) in sleigh.contexts.iter().enumerate() {
            context_mapping
                .entry(context.bitrange.varnode)
                .or_default()
                .push(ContextId(i));
        }

        // 2. sort all the context by bit start, if same, sort by len
        for contexts in context_mapping.values_mut() {
            contexts.sort_unstable_by(|x, y| {
                let x = &sleigh.context(*x).bitrange.bits;
                let y = &sleigh.context(*y).bitrange.bits;
                match x.start().cmp(&y.start()) {
                    std::cmp::Ordering::Equal => x.len().get().cmp(&y.len().get()),
                    x => x,
                }
            });
        }

        // 3. map all the bits into a single memory block, one varnode after the
        // other, removing empty spaces in between. Overlap is decided against
        // the furthest bit any earlier field of the varnode reaches, not just
        // the previous field: a wide field (x86 `suffix3D=(22,29)`) can be
        // followed by narrower ones it covers, and the next field after them
        // (`instrPhase=(30,30)`) must still land after the wide field's end.
        let mut varnodes: Vec<_> = context_mapping.into_iter().collect();
        varnodes.sort_unstable_by_key(|(varnode_id, _)| varnode_id.0);
        let mut mem_mapping: Vec<(ContextId, FieldBits)> =
            Vec::with_capacity(sleigh.contexts.len());
        let mut memory_bits = 0;
        for (_varnode_id, contexts) in varnodes {
            // (original start, mapped start, original end) of the run of
            // overlapping fields the current field may join
            let mut run: Option<(NumberUnsigned, NumberUnsigned, NumberUnsigned)> = None;
            for current_context_id in contexts.into_iter() {
                let current_context = &sleigh.context(current_context_id).bitrange.bits;
                let start = current_context.start();
                let end = current_context.end().get();
                let new_start = match &mut run {
                    Some((run_start, run_mapped, run_end)) if *run_end > start => {
                        *run_end = (*run_end).max(end);
                        *run_mapped + (start - *run_start)
                    }
                    _ => {
                        run = Some((start, memory_bits, end));
                        memory_bits
                    }
                };
                let new_end = new_start + current_context.len().get();
                memory_bits = memory_bits.max(new_end);
                mem_mapping.push((current_context_id, FieldBits::new(new_start, new_end)));
            }
        }
        Self {
            mapping: mem_mapping.into_iter().collect(),
            memory_bits,
        }
    }
    pub fn context(&self, id: ContextId) -> FieldBits {
        self.mapping.get(&id).unwrap().to_owned()
    }
}
