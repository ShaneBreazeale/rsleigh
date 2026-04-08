use std::env;
use std::path::Path;

fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "slaspec/x86/x86-64.slaspec".to_string());
    let path = Path::new(&path);

    eprintln!("Parsing {}...", path.display());

    let sleigh = sleigh_rs::file_to_sleigh(path).expect("failed to parse slaspec");

    let mut total_constructors = 0usize;
    let mut with_execution = 0usize;
    let instruction_table = sleigh.instruction_table();

    for (i, table) in sleigh.tables().iter().enumerate() {
        let count = table.constructors().len();
        total_constructors += count;
        for constructor in table.constructors() {
            if constructor.execution.is_some() {
                with_execution += 1;
            }
        }
        if sleigh_rs::TableId(i) == instruction_table {
            eprintln!(
                "  Instruction table: {} ({} constructors)",
                table.name(),
                count
            );
        }
    }

    eprintln!("  Total tables: {}", sleigh.tables().len());
    eprintln!("  Total constructors: {}", total_constructors);
    eprintln!("  Constructors with execution: {}", with_execution);
    eprintln!("  Registers: {}", sleigh.varnodes().len());
    eprintln!("  Spaces: {}", sleigh.spaces().len());
    eprintln!("OK");
}
