//! OpenExisting-only development target for concrete live Gate bind and shutdown.
//!
//! Usage:
//! `live_gate_dev_bind_shutdown <fixture-root> <strict-client-config> <result-json>`
//!
//! The fixture must first be created by `live_gate_dev_fixture_provision`. This
//! target performs caller-local activation for the fresh boot, opens one strict
//! Zenoh session, binds the real aggregate, and immediately invokes explicit local
//! shutdown. It processes no intent and invokes no command publication. A failed
//! attempt that reaches journal open can consume one of the disposable fixture's
//! 32 segment slots; discard and reprovision an exhausted or uncertain fixture.
//! Result JSON must be a new path outside the fixture. Post-lock failures attempt
//! to publish a bounded failure result with local cleanup classification.

#![forbid(unsafe_code)]

use std::process::ExitCode;

#[path = "live_gate_dev_support/mod.rs"]
mod support;

fn main() -> ExitCode {
    let args = match support::parse_bind_args(std::env::args_os()) {
        Ok(args) => args,
        Err(error) => return report_failure(error),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(_) => {
            return report_failure(support::SmokeError::runtime_creation());
        }
    };
    match runtime.block_on(support::bind_and_shutdown(args)) {
        Ok(()) => {
            println!(
                "haldir-live-gate-bind: OK DEVELOPMENT_ONLY NOT_FOR_PRODUCTION zero_intents_processed zero_commands_published"
            );
            ExitCode::SUCCESS
        }
        Err(error) => report_failure(error),
    }
}

fn report_failure(error: support::SmokeError) -> ExitCode {
    eprintln!(
        "haldir-live-gate-bind: FAIL stage={} durable_effects_may_have_committed={} cleanup_classification={} DEVELOPMENT_ONLY NOT_FOR_PRODUCTION",
        error.stage(),
        error.durable_effects_may_have_committed(),
        error.cleanup_classification()
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::Value;

    use super::support;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestFixture {
        root: PathBuf,
        provision_result: PathBuf,
        external_paths: Vec<PathBuf>,
    }

    impl TestFixture {
        fn external_path(&mut self, label: &str) -> PathBuf {
            let path = temporary_path(label);
            self.external_paths.push(path.clone());
            path
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
            let _ = std::fs::remove_file(&self.provision_result);
            for path in &self.external_paths {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "haldir-live-gate-dev-bind-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn provisioned_fixture(label: &str) -> Option<TestFixture> {
        let root = temporary_path(label);
        let provision_result = temporary_path(&format!("{label}-provision-result"));
        let arguments = support::parse_provision_args([
            OsString::from("provision"),
            root.clone().into_os_string(),
            provision_result.clone().into_os_string(),
        ])
        .ok()?;
        support::provision_fixture(arguments).ok()?;
        Some(TestFixture {
            root,
            provision_result,
            external_paths: Vec::new(),
        })
    }

    fn invoke_bind(
        root: &Path,
        zenoh_config: &Path,
        result: &Path,
    ) -> Option<Result<(), support::SmokeError>> {
        let arguments = support::parse_bind_args([
            OsString::from("bind"),
            root.as_os_str().to_owned(),
            zenoh_config.as_os_str().to_owned(),
            result.as_os_str().to_owned(),
        ])
        .ok()?;
        let runtime = tokio::runtime::Builder::new_current_thread().build().ok()?;
        Some(runtime.block_on(support::bind_and_shutdown(arguments)))
    }

    fn durable_fingerprint(root: &Path) -> Option<Vec<(PathBuf, Vec<u8>)>> {
        let mut fingerprint = Vec::new();
        for directory_name in ["state", "publication-journal"] {
            let directory = root.join(directory_name);
            for entry in std::fs::read_dir(directory).ok()? {
                let entry = entry.ok()?;
                let metadata = entry.metadata().ok()?;
                if metadata.is_file() {
                    fingerprint.push((
                        PathBuf::from(directory_name).join(entry.file_name()),
                        std::fs::read(entry.path()).ok()?,
                    ));
                }
            }
        }
        fingerprint.sort_by(|left, right| left.0.cmp(&right.0));
        Some(fingerprint)
    }

    fn remove_journal_segments(root: &Path) -> Option<usize> {
        let journal = root.join("publication-journal");
        let mut removed = 0_usize;
        for entry in std::fs::read_dir(journal).ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("segment-") {
                std::fs::remove_file(entry.path()).ok()?;
                removed = removed.saturating_add(1);
            }
        }
        Some(removed)
    }

    fn read_json(path: &Path) -> Option<Value> {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn is_failure_at(run: &Result<(), support::SmokeError>, stage: &str) -> bool {
        matches!(run, Err(error) if error.stage() == stage)
    }

    #[test]
    fn missing_journal_segment_is_rejected_without_durable_mutation() -> Result<(), &'static str> {
        let mut fixture =
            provisioned_fixture("missing-segment").ok_or("fixture provisioning failed")?;
        let removed =
            remove_journal_segments(&fixture.root).ok_or("journal segment removal failed")?;
        if removed == 0 {
            return Err("provisioned fixture contained no journal segment");
        }
        let before = durable_fingerprint(&fixture.root).ok_or("fixture fingerprint failed")?;
        let config = fixture.external_path("missing-segment-config");
        let result = fixture.external_path("missing-segment-result");

        let run = invoke_bind(&fixture.root, &config, &result).ok_or("runtime creation failed")?;
        let after = durable_fingerprint(&fixture.root).ok_or("fixture refingerprint failed")?;

        assert!(
            is_failure_at(&run, "journal-preflight") && before == after && !result.exists(),
            "malformed fixture must fail preflight without changing durable state or writing output"
        );
        Ok(())
    }

    #[test]
    fn result_path_inside_fixture_is_rejected_without_durable_mutation() -> Result<(), &'static str>
    {
        let mut fixture =
            provisioned_fixture("result-alias").ok_or("fixture provisioning failed")?;
        let before = durable_fingerprint(&fixture.root).ok_or("fixture fingerprint failed")?;
        let config = fixture.external_path("result-alias-config");
        let result = fixture.root.join("publication-journal/result.json");

        let run = invoke_bind(&fixture.root, &config, &result).ok_or("runtime creation failed")?;
        let after = durable_fingerprint(&fixture.root).ok_or("fixture refingerprint failed")?;

        assert!(
            is_failure_at(&run, "result-alias") && before == after && !result.exists(),
            "fixture-contained output must be rejected before state or journal mutation"
        );
        Ok(())
    }

    #[test]
    fn held_outer_lock_is_rejected_without_durable_mutation() -> Result<(), &'static str> {
        let mut fixture =
            provisioned_fixture("outer-lock-held").ok_or("fixture provisioning failed")?;
        let before = durable_fingerprint(&fixture.root).ok_or("fixture fingerprint failed")?;
        let config = fixture.external_path("outer-lock-held-config");
        let result = fixture.external_path("outer-lock-held-result");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.root.join(".haldir-live-gate-smoke.lock"))
            .map_err(|_| "outer lock open failed")?;
        lock.try_lock()
            .map_err(|_| "outer lock acquisition failed")?;

        let run = invoke_bind(&fixture.root, &config, &result).ok_or("runtime creation failed")?;
        let after = durable_fingerprint(&fixture.root).ok_or("fixture refingerprint failed")?;
        drop(lock);

        assert!(
            is_failure_at(&run, "outer-lock-held") && before == after && !result.exists(),
            "lock contention must fail before state or journal mutation"
        );
        Ok(())
    }

    #[test]
    fn invalid_zenoh_config_writes_bounded_failure_without_durable_mutation()
    -> Result<(), &'static str> {
        let mut fixture =
            provisioned_fixture("invalid-config").ok_or("fixture provisioning failed")?;
        let config = fixture.external_path("invalid-config-input");
        let result = fixture.external_path("invalid-config-result");
        std::fs::write(&config, b"{not-valid-json").map_err(|_| "config write failed")?;
        let before = durable_fingerprint(&fixture.root).ok_or("fixture fingerprint failed")?;

        let run = invoke_bind(&fixture.root, &config, &result).ok_or("runtime creation failed")?;
        let after = durable_fingerprint(&fixture.root).ok_or("fixture refingerprint failed")?;
        let result_length = std::fs::metadata(&result)
            .map_err(|_| "failure result metadata failed")?
            .len();
        let failure = read_json(&result).ok_or("failure result parse failed")?;
        let recorded_stage = failure.pointer("/failure/stage").and_then(Value::as_str);
        let recorded_durable_effects = failure
            .pointer("/failure/durable_effects_may_have_committed")
            .and_then(Value::as_bool);
        let recorded_cleanup = failure
            .pointer("/failure/cleanup_classification")
            .and_then(Value::as_str);
        let recorded_intents = failure
            .pointer("/negative_evidence/intents_processed_by_target")
            .and_then(Value::as_u64);
        let recorded_commands = failure
            .pointer("/negative_evidence/commands_published_by_target")
            .and_then(Value::as_u64);

        assert!(
            is_failure_at(&run, "zenoh-config")
                && before == after
                && result_length <= 2_048
                && failure.get("status").and_then(Value::as_str) == Some("fail")
                && recorded_stage == Some("zenoh-config")
                && recorded_durable_effects == Some(false)
                && recorded_cleanup == Some("not-applicable")
                && recorded_intents == Some(0)
                && recorded_commands == Some(0),
            "invalid config must produce only a bounded, pre-durable failure result"
        );
        Ok(())
    }
}
