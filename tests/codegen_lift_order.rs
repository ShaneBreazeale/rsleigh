//! Fresh parses randomize pattern HashMaps; raw lift order must stay stable.
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn repeated_generation_preserves_raw_lift_order() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("rsleigh-lift-order-{}.slaspec", std::process::id())),
    );
    fs::write(
        &fixture.0,
        r#"
define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 r2 ];
define token instr(8) opcode=(0,3) left=(4,5) right=(6,7);
rhs: r1 is right=0 { local value:4 = r1 + 2; export value; }
lhs: r0 is left=0 { local value:4 = r0 + 1; export value; }
:"mix" lhs,rhs is opcode=0 & lhs & rhs { r2 = lhs + rhs; }
"#,
    )
    .unwrap();

    let mut expected = None;
    for _ in 0..24 {
        let generated = rsleigh::codegen::generate_disassembler(&fixture.0)
            .unwrap()
            .to_string();
        // Other generated declarations may differ in cosmetic order. Compare
        // the emitted lift bodies, including operation order and unique offsets.
        let lifts: Vec<_> = generated
            .split("pub fn lift")
            .skip(1)
            .map(|part| part.split("pub fn parse").next().unwrap().to_owned())
            .collect();
        assert!(!lifts.is_empty(), "fixture must exercise generated lifting");
        let parent = lifts
            .iter()
            .find(|body| body.contains("self . lhs . lift"))
            .unwrap();
        assert!(
            parent.find("self . lhs . lift") < parent.find("self . rhs . lift"),
            "subtables must lift in pattern order, not declaration order"
        );
        if let Some(expected) = &expected {
            assert_eq!(&lifts, expected, "raw lift changed after a fresh parse");
        } else {
            expected = Some(lifts);
        }
    }
}
