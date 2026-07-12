//! Haldir Gate binary entry point.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    eprintln!(
        "haldir-gate {}: runtime entry not yet wired in this scaffold",
        haldir_gate::VERSION
    );
    std::process::ExitCode::from(2)
}
