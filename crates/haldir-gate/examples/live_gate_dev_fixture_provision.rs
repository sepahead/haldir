//! Offline provisioner for the disposable development live-Gate smoke fixture.
//!
//! Usage:
//! `live_gate_dev_fixture_provision <fixture-root> <result-json>`
//!
//! Provisioning state and journal is intentionally staged rather than atomic. On
//! any failure after state provisioning, remove the entire dedicated fixture root
//! before retrying. This example never opens a network session.

#![forbid(unsafe_code)]

use std::process::ExitCode;

#[path = "live_gate_dev_support/mod.rs"]
mod support;

fn main() -> ExitCode {
    let result =
        support::parse_provision_args(std::env::args_os()).and_then(support::provision_fixture);
    match result {
        Ok(()) => {
            println!("haldir-live-gate-fixture: OK DEVELOPMENT_ONLY NOT_FOR_PRODUCTION");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "haldir-live-gate-fixture: FAIL stage={} durable_effects_may_have_committed={} cleanup_classification={} DEVELOPMENT_ONLY NOT_FOR_PRODUCTION; discard the entire dedicated fixture root after any partial provisioning failure",
                error.stage(),
                error.durable_effects_may_have_committed(),
                error.cleanup_classification()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::support;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> std::path::PathBuf {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "haldir-live-gate-dev-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn argument_parsers_are_exact_and_separate() {
        let provision = support::parse_provision_args([
            OsString::from("provision"),
            OsString::from("fixture"),
            OsString::from("result.json"),
        ]);
        assert!(provision.is_ok());
        let extra = support::parse_provision_args([
            OsString::from("provision"),
            OsString::from("fixture"),
            OsString::from("result.json"),
            OsString::from("unexpected"),
        ]);
        assert!(extra.is_err());
        let bind = support::parse_bind_args([
            OsString::from("bind"),
            OsString::from("fixture"),
            OsString::from("gate.json"),
            OsString::from("result.json"),
        ]);
        assert!(bind.is_ok());
        let missing = support::parse_bind_args([
            OsString::from("bind"),
            OsString::from("fixture"),
            OsString::from("gate.json"),
        ]);
        assert!(missing.is_err());
    }

    #[test]
    fn offline_provisioner_creates_both_backends_and_never_overwrites() {
        let root = temporary_path("provision");
        let first_result = temporary_path("provision-result");
        let second_result = temporary_path("provision-result-second");
        let first = support::parse_provision_args([
            OsString::from("provision"),
            root.clone().into_os_string(),
            first_result.clone().into_os_string(),
        ])
        .and_then(support::provision_fixture);
        assert!(first.is_ok());
        assert!(root.join("state").is_dir());
        assert!(root.join("publication-journal").is_dir());
        assert!(first_result.is_file());
        let result_value = std::fs::read(&first_result)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        assert_eq!(
            result_value
                .as_ref()
                .and_then(|value| value.get("mode"))
                .and_then(serde_json::Value::as_str),
            Some("development-live-fixture-provision-v1")
        );
        assert_eq!(
            result_value
                .as_ref()
                .and_then(|value| value.get("production_claim"))
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );

        let second = support::parse_provision_args([
            OsString::from("provision"),
            root.clone().into_os_string(),
            second_result.clone().into_os_string(),
        ])
        .and_then(support::provision_fixture);
        assert!(second.is_err());
        assert!(!second_result.exists());

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(first_result);
        let _ = std::fs::remove_file(second_result);
    }

    #[test]
    fn live_target_does_not_create_a_missing_fixture() {
        let root = temporary_path("missing-bind-root");
        let config = temporary_path("missing-bind-config");
        let result = temporary_path("missing-bind-result");
        let arguments = support::parse_bind_args([
            OsString::from("bind"),
            root.clone().into_os_string(),
            config.into_os_string(),
            result.clone().into_os_string(),
        ]);
        let run = match arguments {
            Ok(arguments) => match tokio::runtime::Builder::new_current_thread().build() {
                Ok(runtime) => runtime.block_on(support::bind_and_shutdown(arguments)),
                Err(_) => Err(support::SmokeError::runtime_creation()),
            },
            Err(error) => Err(error),
        };
        assert!(run.is_err());
        assert!(!root.exists());
        assert!(!result.exists());
    }
}
