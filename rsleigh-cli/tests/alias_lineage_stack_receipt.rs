use std::process::Command;

use rsleigh_api::{Architecture, DecodeError, Decoder};

const CHILD_CASE_ENV: &str = "RSLEIGH_G26_SYNTHETIC_CASE";
const WORKER_STACK_BYTES: usize = 256 * 1024 * 1024;

fn run_child(test_name: &str, case: &str) {
    let status = Command::new(std::env::current_exe().expect("test executable must resolve"))
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_CASE_ENV, case)
        .env("RUST_BACKTRACE", "0")
        .status()
        .expect("synthetic decoder child must start");

    assert!(status.success(), "synthetic decoder child did not complete");
}

fn run_worker(case: &'static str, decode: impl FnOnce() + Send + 'static) {
    eprintln!(
        "g26_stack_receipt phase=worker-entry case={case} \
         architecture=x86_64 stack_bytes={WORKER_STACK_BYTES}"
    );

    std::thread::Builder::new()
        .name(format!("g26-{case}-worker"))
        .stack_size(WORKER_STACK_BYTES)
        .spawn(decode)
        .expect("synthetic decoder worker must spawn")
        .join()
        .expect("synthetic decoder worker must return");

    eprintln!(
        "g26_stack_receipt phase=worker-return case={case} \
         architecture=x86_64 stack_bytes={WORKER_STACK_BYTES}"
    );
}

#[test]
fn ordinary_x86_decode_control_256m() {
    if std::env::var(CHILD_CASE_ENV).as_deref() == Ok("ordinary") {
        run_worker("ordinary", || {
            let mut decoder = Decoder::new(Architecture::X86_64);
            let instruction = decoder
                .decode(&[0x48, 0x89, 0xd8], 0x1000)
                .expect("ordinary x86 decode must succeed");
            assert_eq!(instruction.len, 3);
        });
        return;
    }

    run_child("ordinary_x86_decode_control_256m", "ordinary");
}

#[test]
fn ordinary_legacy_prefixed_x86_control_256m() {
    if std::env::var(CHILD_CASE_ENV).as_deref() == Ok("ordinary-prefixed") {
        run_worker("ordinary-prefixed", || {
            let mut decoder = Decoder::new(Architecture::X86_64);
            let instruction = decoder
                .decode(&[0x66, 0x90], 0x1000)
                .expect("ordinary legacy-prefixed x86 decode must succeed");
            assert_eq!(instruction.len, 2);
        });
        return;
    }

    run_child(
        "ordinary_legacy_prefixed_x86_control_256m",
        "ordinary-prefixed",
    );
}

#[test]
fn legacy_prefixed_3dnow_fails_closed_256m() {
    if std::env::var(CHILD_CASE_ENV).as_deref() == Ok("prefixed-3dnow") {
        run_worker("prefixed-3dnow", || {
            let mut decoder = Decoder::new(Architecture::X86_64);
            assert!(matches!(
                decoder.decode(&[0x66, 0x0f, 0x0f, 0xc0, 0x0c], 0x1000),
                Err(DecodeError::UnknownInstruction)
            ));
        });
        return;
    }

    run_child(
        "legacy_prefixed_3dnow_fails_closed_256m",
        "prefixed-3dnow",
    );
}
