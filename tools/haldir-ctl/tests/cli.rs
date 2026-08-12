//! Black-box command-line contract tests for `haldir-ctl`.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use haldir_ncp08::{NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES, pinned_ncp_compatibility_artifact_bytes};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestFile(PathBuf);

impl TestFile {
    fn new(bytes: &[u8]) -> io::Result<Self> {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("haldir-ctl-test-{}-{sequence}", std::process::id()));
        fs::write(&path, bytes)?;
        Ok(Self(path))
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

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
    Command::new(env!("CARGO_BIN_EXE_haldir-ctl"))
        .args(args)
        .output()
        .map(Invocation::from)
}

#[test]
fn help_and_version_are_successful_and_explicitly_bounded() -> TestResult {
    let help = invoke(["--help"])?;
    assert_eq!(help.exit_code, Some(0));
    assert!(help.stderr.is_empty());
    let help = String::from_utf8(help.stdout)?;
    assert!(help.contains("bounded canonical artifact"));
    assert!(help.contains("does not prove signed deployment-role origin"));

    let version = invoke(["--version"])?;
    assert_eq!(version.exit_code, Some(0));
    assert_eq!(
        version.stdout,
        format!("haldir-ctl {}\n", env!("CARGO_PKG_VERSION")).into_bytes()
    );
    Ok(())
}

#[test]
fn build_info_reports_the_exact_compiled_identity() -> TestResult {
    let actual = invoke(["--build-info"])?;
    assert_eq!(actual.exit_code, Some(0));
    assert!(actual.stderr.is_empty());
    let stdout = String::from_utf8(actual.stdout)?;
    assert!(stdout.contains("v0.8.0"));
    assert!(stdout.contains("2f5bd586d4bb20c90362bb6f5698b7f64057ba4e"));
    assert!(stdout.contains("17f040a0fc9d06d4b958adfa9267b16689b8aa3b91dab21560c1d655de1c17af"));
    assert!(stdout.contains("EXPERIMENTAL — not for deployment"));
    Ok(())
}

#[test]
fn exact_pinned_artifact_validates_with_a_narrow_scope_statement() -> TestResult {
    let input = TestFile::new(&pinned_ncp_compatibility_artifact_bytes()?)?;
    let actual = invoke([OsStr::new("verify-ncp-compatibility"), input.0.as_os_str()])?;
    assert_eq!(actual.exit_code, Some(0));
    assert!(actual.stderr.is_empty());
    let stdout = String::from_utf8(actual.stdout)?;
    assert!(stdout.contains("VALID (supplied artifact bytes only)"));
    assert!(stdout.contains("deployment provenance: NOT PROVEN"));
    Ok(())
}

#[test]
fn malformed_and_oversized_inputs_fail_closed() -> TestResult {
    let malformed = TestFile::new(b"not canonical cbor")?;
    let malformed_result = invoke([
        OsStr::new("verify-ncp-compatibility"),
        malformed.0.as_os_str(),
    ])?;
    assert_eq!(malformed_result.exit_code, Some(1));
    assert!(malformed_result.stdout.is_empty());
    assert!(String::from_utf8(malformed_result.stderr)?.starts_with("error: DECODE_"));

    let oversized = TestFile::new(&vec![0u8; NCP_COMPATIBILITY_ARTIFACT_MAX_BYTES + 1])?;
    let oversized_result = invoke([
        OsStr::new("verify-ncp-compatibility"),
        oversized.0.as_os_str(),
    ])?;
    assert_eq!(oversized_result.exit_code, Some(1));
    assert_eq!(
        oversized_result.stderr,
        b"error: HALDIR_CTL_INPUT_TOO_LARGE\n"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn compatibility_input_does_not_follow_a_final_symlink() -> TestResult {
    use std::os::unix::fs::symlink;

    let target = TestFile::new(&pinned_ncp_compatibility_artifact_bytes()?)?;
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let link_path = std::env::temp_dir().join(format!(
        "haldir-ctl-symlink-test-{}-{sequence}",
        std::process::id()
    ));
    symlink(&target.0, &link_path)?;
    let link = TestFile(link_path);

    let actual = invoke([OsStr::new("verify-ncp-compatibility"), link.0.as_os_str()])?;

    assert_eq!(actual.exit_code, Some(1));
    assert!(actual.stdout.is_empty());
    assert_eq!(actual.stderr, b"error: HALDIR_CTL_INPUT_OPEN_FAILED\n");
    Ok(())
}

#[test]
fn usage_errors_never_echo_untrusted_arguments() -> TestResult {
    for arguments in [vec!["--unknown-secret"], vec!["verify-ncp-compatibility"]] {
        let actual = invoke(arguments)?;
        assert_eq!(actual.exit_code, Some(2));
        assert!(actual.stdout.is_empty());
        assert!(!String::from_utf8(actual.stderr)?.contains("unknown-secret"));
    }
    Ok(())
}
