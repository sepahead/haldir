//! `haldir-ctl` — byte-bounded offline inspection and compatibility verification.
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{Mode, OFlags, open};

use haldir_ncp08::{
    NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES, NCP_V0_8_0, NcpCompatibilityError,
    ValidatedNcpCompatibilityArtifact, validate_ncp_compatibility_artifact,
};

const USAGE: &str =
    "Usage: haldir-ctl [--help | --version | --build-info | verify-ncp-compatibility <FILE>]";
const HELP: &str = "\
Haldir bounded offline inspection and compatibility verification

Usage: haldir-ctl [--help | --version | --build-info | verify-ncp-compatibility <FILE>]

Commands:
  verify-ncp-compatibility <FILE>
      Strictly decode a bounded canonical artifact and exact-match every
      compiled NCP compatibility pin.

Options:
  -h, --help       Print this help
  -V, --version    Print the binary version
      --build-info Print the compiled NCP compatibility identity

Compatibility validation proves only that the supplied artifact bytes match
this binary's compiled pins. It does not prove signed deployment-role origin,
artifact-root trust, running-binary identity, or Gate startup selection.
";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    BuildInfo,
    VerifyNcpCompatibility(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsageError {
    MissingCommand,
    MissingInput,
    UnexpectedTrailingArgument,
    UnsupportedArgument,
}

#[derive(Debug)]
enum VerificationError {
    Open,
    NotRegular,
    TooLarge,
    Read,
    Compatibility(NcpCompatibilityError),
}

impl VerificationError {
    fn reason_code(&self) -> &'static str {
        match self {
            Self::Open => "HALDIR_CTL_INPUT_OPEN_FAILED",
            Self::NotRegular => "HALDIR_CTL_INPUT_NOT_REGULAR",
            Self::TooLarge => "HALDIR_CTL_INPUT_TOO_LARGE",
            Self::Read => "HALDIR_CTL_INPUT_READ_FAILED",
            Self::Compatibility(error) => error.reason_code(),
        }
    }
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let argument = args.next().ok_or(UsageError::MissingCommand)?;
    let command = match argument.as_os_str() {
        value if value == OsStr::new("-h") || value == OsStr::new("--help") => Command::Help,
        value if value == OsStr::new("-V") || value == OsStr::new("--version") => Command::Version,
        value if value == OsStr::new("--build-info") => Command::BuildInfo,
        value if value == OsStr::new("verify-ncp-compatibility") => {
            let path = args.next().ok_or(UsageError::MissingInput)?;
            if args.next().is_some() {
                return Err(UsageError::UnexpectedTrailingArgument);
            }
            return Ok(Command::VerifyNcpCompatibility(PathBuf::from(path)));
        }
        _ => return Err(UsageError::UnsupportedArgument),
    };
    if args.next().is_some() {
        return Err(UsageError::UnexpectedTrailingArgument);
    }
    Ok(command)
}

fn write_build_info(mut output: impl Write) -> io::Result<()> {
    writeln!(
        output,
        "haldir-ctl {} — compiled build information",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(output, "  NCP release          : {}", NCP_V0_8_0.ncp_tag)?;
    writeln!(output, "  NCP commit           : {}", NCP_V0_8_0.ncp_commit)?;
    writeln!(
        output,
        "  wire / contract      : {} / {}",
        NCP_V0_8_0.wire_version, NCP_V0_8_0.contract_hash
    )?;
    writeln!(
        output,
        "  capability profile   : {}",
        NCP_V0_8_0.capability_profile
    )?;
    write!(output, "  compatibility id     : sha256:")?;
    write_hex(&mut output, &NCP_V0_8_0.compatibility_id().value)?;
    writeln!(output)?;
    writeln!(
        output,
        "  status               : EXPERIMENTAL — not for deployment"
    )
}

fn write_hex(mut output: impl Write, bytes: &[u8]) -> io::Result<()> {
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    Ok(())
}

fn verify_file(path: &Path) -> Result<ValidatedNcpCompatibilityArtifact, VerificationError> {
    let mut file = open_input(path)?;
    let metadata = file.metadata().map_err(|_| VerificationError::Read)?;
    if !metadata.file_type().is_file() {
        return Err(VerificationError::NotRegular);
    }
    if metadata.len() > u64::try_from(NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES).unwrap_or(u64::MAX) {
        return Err(VerificationError::TooLarge);
    }

    let mut buffer = [0u8; NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES + 1];
    let mut filled = 0usize;
    loop {
        let destination = buffer
            .get_mut(filled..)
            .ok_or(VerificationError::TooLarge)?;
        if destination.is_empty() {
            return Err(VerificationError::TooLarge);
        }
        match file.read(destination) {
            Ok(0) => break,
            Ok(read) => {
                filled = filled
                    .checked_add(read)
                    .ok_or(VerificationError::TooLarge)?;
                if filled > NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES {
                    return Err(VerificationError::TooLarge);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(VerificationError::Read),
        }
    }
    let bytes = buffer.get(..filled).ok_or(VerificationError::TooLarge)?;
    validate_ncp_compatibility_artifact(bytes).map_err(VerificationError::Compatibility)
}

fn open_input(path: &Path) -> Result<File, VerificationError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|_| VerificationError::Open)?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        File::open(path).map_err(|_| VerificationError::Open)
    }
}

fn write_validation(
    mut output: impl Write,
    validated: &ValidatedNcpCompatibilityArtifact,
) -> io::Result<()> {
    writeln!(
        output,
        "ncp-compatibility: VALID (supplied artifact bytes only)"
    )?;
    writeln!(
        output,
        "  NCP release          : {}",
        validated.artifact().ncp_tag.as_str()
    )?;
    writeln!(
        output,
        "  NCP commit           : {}",
        validated.artifact().ncp_commit.as_str()
    )?;
    writeln!(
        output,
        "  wire / contract      : {} / {}",
        validated.artifact().wire_version.as_str(),
        validated.artifact().contract_hash.as_str()
    )?;
    writeln!(
        output,
        "  capability profile   : {}",
        validated.artifact().capability_profile.as_str()
    )?;
    write!(output, "  compatibility id     : sha256:")?;
    write_hex(&mut output, &validated.compatibility_id().value)?;
    writeln!(output)?;
    writeln!(output, "  deployment provenance: NOT PROVEN")
}

fn write_usage_error(error: UsageError, mut output: impl Write) -> io::Result<()> {
    let message = match error {
        UsageError::MissingCommand => "error: one command or option is required",
        UsageError::MissingInput => "error: verify-ncp-compatibility requires one input file",
        UsageError::UnexpectedTrailingArgument => "error: unexpected trailing argument",
        UsageError::UnsupportedArgument => "error: unsupported argument",
    };
    writeln!(output, "{message}")?;
    writeln!(output, "{USAGE}")?;
    writeln!(output, "Try 'haldir-ctl --help' for more information.")
}

fn run(
    args: impl Iterator<Item = OsString>,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> io::Result<ExitCode> {
    match parse_args(args) {
        Ok(Command::Help) => {
            write!(stdout, "{HELP}")?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(Command::Version) => {
            writeln!(stdout, "haldir-ctl {}", env!("CARGO_PKG_VERSION"))?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(Command::BuildInfo) => {
            write_build_info(stdout)?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(Command::VerifyNcpCompatibility(path)) => match verify_file(&path) {
            Ok(validated) => {
                write_validation(stdout, &validated)?;
                Ok(ExitCode::SUCCESS)
            }
            Err(error) => {
                writeln!(stderr, "error: {}", error.reason_code())?;
                Ok(ExitCode::FAILURE)
            }
        },
        Err(error) => {
            write_usage_error(error, stderr)?;
            Ok(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    let stdout = io::stdout();
    let stderr = io::stderr();
    run(std::env::args_os().skip(1), stdout.lock(), stderr.lock()).unwrap_or(ExitCode::FAILURE)
}
