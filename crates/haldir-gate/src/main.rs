//! Haldir Gate binary entry point.
//!
//! This experimental binary exposes offline introspection only. It does NOT open
//! any live command transport (the P0 profile is in-process; see LIMITATIONS).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--version") => {
            println!("haldir-gate {}", haldir_gate::VERSION);
            ExitCode::SUCCESS
        }
        Some("--check-config") => {
            let compat = haldir_ncp08::NCP_V0_8_0;
            println!(
                "haldir-gate {} — configuration self-check",
                haldir_gate::VERSION
            );
            println!(
                "  NCP compatibility : {} @ {}",
                compat.ncp_tag, compat.ncp_commit
            );
            println!("  capability profile: {}", compat.capability_profile);
            println!("  assurance profile : assurance-reference-v1 (P0, in-process)");
            println!("  status            : EXPERIMENTAL — not for deployment");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "haldir-gate {}: experimental P0 build. No live command transport is wired \
                 in this profile.\nUsage: haldir-gate [--version | --check-config]",
                haldir_gate::VERSION
            );
            ExitCode::from(2)
        }
    }
}
