use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
use std::io;
use std::process::{Command, Output};

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

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl From<Output> for Invocation {
    fn from(output: Output) -> Self {
        Self {
            exit_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}

fn invoke<I, S>(args: I) -> io::Result<Invocation>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_haldir-gate"))
        .args(args)
        .output()
        .map(Invocation::from)
}

fn cli_error(message: &str) -> Vec<u8> {
    format!("{message}\n{USAGE}\nTry 'haldir-gate --help' for more information.\n").into_bytes()
}

#[test]
fn no_arguments_should_fail_with_usage() -> TestResult {
    let actual = invoke::<[&str; 0], &str>([])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error("error: one option is required"),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn help_should_describe_offline_introspection_limits() -> TestResult {
    let actual = invoke(["--help"])?;
    let expected = Invocation {
        exit_code: Some(0),
        stdout: HELP.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn short_help_should_match_long_help() -> TestResult {
    let actual = invoke(["-h"])?;
    let expected = Invocation {
        exit_code: Some(0),
        stdout: HELP.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn version_should_print_only_the_binary_version() -> TestResult {
    let actual = invoke(["--version"])?;
    let expected = Invocation {
        exit_code: Some(0),
        stdout: format!("haldir-gate {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
        stderr: Vec::new(),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn short_version_should_match_long_version() -> TestResult {
    let actual = invoke(["-V"])?;
    let expected = Invocation {
        exit_code: Some(0),
        stdout: format!("haldir-gate {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
        stderr: Vec::new(),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn build_info_should_explicitly_disclaim_configuration_validation() -> TestResult {
    let actual = invoke(["--build-info"])?;
    let expected = Invocation {
        exit_code: Some(0),
        stdout: format!(
            "\
haldir-gate {} — compiled build information
  NCP compatibility    : v0.8.0 @ 2f5bd586d4bb20c90362bb6f5698b7f64057ba4e
  capability profile   : PRE_AUTHORITY_ACL_ONLY
  reference profile    : assurance-reference-v1 (P0, in-process)
  runtime wiring       : none (offline introspection only)
  configuration check  : NOT PERFORMED
  status               : EXPERIMENTAL — not for deployment
",
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes(),
        stderr: Vec::new(),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn check_config_should_fail_with_migration_guidance() -> TestResult {
    let actual = invoke(["--check-config"])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error(
            "error: --check-config is unavailable; this binary does not validate runtime configuration\n\
             hint: use --build-info for compiled compatibility metadata",
        ),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn check_config_with_trailing_argument_should_still_fail_closed() -> TestResult {
    let actual = invoke(["--check-config", "ignored"])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error(
            "error: --check-config is unavailable; this binary does not validate runtime configuration\n\
             hint: use --build-info for compiled compatibility metadata",
        ),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn version_with_trailing_argument_should_fail_closed() -> TestResult {
    let actual = invoke(["--version", "ignored"])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error("error: unexpected trailing argument"),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn build_info_with_trailing_argument_should_fail_closed() -> TestResult {
    let actual = invoke(["--build-info", "ignored"])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error("error: unexpected trailing argument"),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn unknown_argument_should_fail_without_echoing_untrusted_text() -> TestResult {
    let actual = invoke(["--unknown"])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error("error: unsupported argument"),
    };

    assert_eq!(actual, expected);
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_should_fail_without_panicking() -> TestResult {
    use std::os::unix::ffi::OsStringExt;

    let argument = OsString::from_vec(vec![0xff]);
    let actual = invoke([argument])?;
    let expected = Invocation {
        exit_code: Some(2),
        stdout: Vec::new(),
        stderr: cli_error("error: unsupported argument"),
    };

    assert_eq!(actual, expected);
    Ok(())
}
