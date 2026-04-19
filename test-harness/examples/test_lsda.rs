use rsleigh_decompile::eh_frame::parse_eh_frame;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::fs::read("/Users/shane/repos/gc3-sdk/docs/investigation/plm-control-app.elf")?;
    let regions = parse_eh_frame(&bin);
    let mut total = 0;
    for (_, v) in &regions {
        total += v.len();
    }
    println!("functions with try/catch: {}", regions.len());
    println!("total try regions:        {}", total);
    for addr in [0x50840u64, 0x506a0, 0x516f0, 0x50a70, 0x51230, 0x55090].iter() {
        match regions.get(addr) {
            Some(r) => {
                println!("0x{:x}: {} regions:", addr, r.len());
                for tr in r.iter().take(3) {
                    println!("  [0x{:x}..0x{:x}) -> LP 0x{:x}", tr.start, tr.end, tr.landing_pad);
                }
            }
            None => println!("0x{:x}: no regions", addr),
        }
    }
    Ok(())
}
