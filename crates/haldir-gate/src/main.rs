//! Haldir Gate binary entry point.
//!
//! This experimental binary exposes offline introspection only. It does NOT open
//! any live command transport (the P0 profile is in-process; see LIMITATIONS).
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "Usage: haldir-gate [--help | --version | --build-info]";
const HELP: &str = "\
Haldir Gate experimental offline-introspection binary

Usage: haldir-gate [--help | --version | --build-info]

Options:
  -h, --help       Print this help
  -V, --version    Print the binary version
      --build-info Print compiled compatibility and reference-profile metadata

--build-info does not load or validate runtime configuration, deployment
packages, trust policy, filesystem permissions, credentials, ACLs, or routes.
No live command transport is wired into this binary.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    BuildInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliError {
    MissingArgument,
    UnexpectedTrailingArgument,
    UnsupportedArgument,
    CheckConfigUnavailable,
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let argument = args.next().ok_or(CliError::MissingArgument)?;
    let command = match argument.as_os_str() {
        value if value == OsStr::new("-h") || value == OsStr::new("--help") => Command::Help,
        value if value == OsStr::new("-V") || value == OsStr::new("--version") => Command::Version,
        value if value == OsStr::new("--build-info") => Command::BuildInfo,
        value if value == OsStr::new("--check-config") => {
            return Err(CliError::CheckConfigUnavailable);
        }
        _ => return Err(CliError::UnsupportedArgument),
    };

    if args.next().is_some() {
        return Err(CliError::UnexpectedTrailingArgument);
    }

    Ok(command)
}

fn write_build_info(mut output: impl Write) -> io::Result<()> {
    let compatibility = haldir_ncp08::NCP_V0_8_0;
    writeln!(
        output,
        "haldir-gate {} — compiled build information",
        haldir_gate::VERSION
    )?;
    writeln!(
        output,
        "  NCP compatibility    : {} @ {}",
        compatibility.ncp_tag, compatibility.ncp_commit
    )?;
    writeln!(
        output,
        "  capability profile   : {}",
        compatibility.capability_profile
    )?;
    writeln!(
        output,
        "  reference profile    : assurance-reference-v1 (P0, in-process)"
    )?;
    writeln!(
        output,
        "  runtime wiring       : none (offline introspection only)"
    )?;
    writeln!(output, "  configuration check  : NOT PERFORMED")?;
    writeln!(
        output,
        "  status               : EXPERIMENTAL — not for deployment"
    )
}

fn write_cli_error(error: CliError, mut output: impl Write) -> io::Result<()> {
    match error {
        CliError::MissingArgument => writeln!(output, "error: one option is required")?,
        CliError::UnexpectedTrailingArgument => {
            writeln!(output, "error: unexpected trailing argument")?;
        }
        CliError::UnsupportedArgument => {
            writeln!(output, "error: unsupported argument")?;
        }
        CliError::CheckConfigUnavailable => {
            writeln!(
                output,
                "error: --check-config is unavailable; this binary does not validate runtime configuration"
            )?;
            writeln!(
                output,
                "hint: use --build-info for compiled compatibility metadata"
            )?;
        }
    }
    writeln!(output, "{USAGE}")?;
    writeln!(output, "Try 'haldir-gate --help' for more information.")
}

fn run(
    args: impl Iterator<Item = OsString>,
    mut stdout: impl Write,
    stderr: impl Write,
) -> io::Result<ExitCode> {
    match parse_args(args) {
        Ok(Command::Help) => {
            write!(stdout, "{HELP}")?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(Command::Version) => {
            writeln!(stdout, "haldir-gate {}", haldir_gate::VERSION)?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(Command::BuildInfo) => {
            write_build_info(stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            write_cli_error(error, stderr)?;
            Ok(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    let stdout = io::stdout();
    let stderr = io::stderr();
    run(std::env::args_os().skip(1), stdout.lock(), stderr.lock()).unwrap_or(ExitCode::FAILURE)
}
