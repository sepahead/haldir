#!/usr/bin/env python3
"""Adversarial tests for the FR-0002 bounded-process repair."""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import importlib.util
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


PARENT_COMMIT = "ab37e9fae7414981628eaa0dad185408f3b9323a"
PARENT_VERIFIER_BYTES = 536_370
PARENT_VERIFIER_SHA256 = (
    "5c9356c08790996ff2a42e8139519b4b930a41473fd7a021a726ac0558c85dce"
)


def _load_verify():
    module_path = Path(__file__).with_name("verify-current-audit.py")
    spec = importlib.util.spec_from_file_location(
        "verify_current_audit_fr_0002", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the current-audit verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_python(verify, root, source, timeout_seconds, stdout_limit, stderr_limit):
    environment = os.environ.copy()
    environment.pop("PYTHONWARNINGS", None)
    return verify._run_bounded(
        [sys.executable, "-c", source],
        cwd=root,
        env=environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        error_prefix="TEST_FR_0002",
        _test_only_allow_uncontained_process=True,
    )


def _fd_count():
    return len(tuple(Path("/dev/fd").iterdir()))


def _wait_for_path(path):
    deadline = time.monotonic() + 2
    for _attempt in range(201):
        if path.exists():
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    raise AssertionError(f"timed out while waiting for {path.name}")


def _kill_if_present(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return


def _pid_is_running(pid):
    proc_root = Path("/proc")
    if proc_root.is_dir():
        try:
            value = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            return False
        except OSError:
            return True
        closing_parenthesis = value.rfind(")")
        if closing_parenthesis < 0:
            return True
        tail = value[closing_parenthesis + 1 :].lstrip()
        return bool(tail) and tail[0] != "Z"
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class FrameworkRecovery2Tests(unittest.TestCase):
    """Prove bounded cleanup, identity retention, and exact byte capture."""

    def test_framework_recovery_2_parent_runner_reproduces_post_reap_signal(
        self,
    ) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        payload = verify._git_file(
            root,
            PARENT_COMMIT,
            "tools/release/verify-current-audit.py",
        )
        self.assertEqual(len(payload), PARENT_VERIFIER_BYTES)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), PARENT_VERIFIER_SHA256)
        with tempfile.TemporaryDirectory() as raw:
            module_path = Path(raw) / "parent-verifier.py"
            module_path.write_bytes(payload)
            spec = importlib.util.spec_from_file_location(
                "verify_current_audit_fr_0002_parent", module_path
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec is not None else None)
            if spec is None or spec.loader is None:
                self.fail("cannot load the exact parent verifier")
            parent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(parent)
            events = []

            class ParentProcess:
                pid = 424_242
                returncode = None

                def poll(self):
                    events.append(("poll", None))
                    return self.returncode

                def wait(self, timeout):
                    events.append(("wait", timeout))
                    self.returncode = 0
                    return 0

                def terminate(self):
                    events.append(("terminate", None))

                def kill(self):
                    events.append(("kill", None))

            def record_killpg(pid, selected_signal):
                self.assertEqual(pid, ParentProcess.pid)
                events.append(("killpg", selected_signal))

            with mock.patch.object(parent.os, "killpg", side_effect=record_killpg):
                parent._stop_bounded_process(
                    ParentProcess(), inherited_pipes_pending=True
                )
            first_wait = next(
                index for index, event in enumerate(events) if event[0] == "wait"
            )
            self.assertIn(("killpg", signal.SIGKILL), events[first_wait + 1 :])
            trace = [
                f"FR-0002-REPRO parent_commit={PARENT_COMMIT}",
                f"FR-0002-REPRO parent_blob_sha256={PARENT_VERIFIER_SHA256}",
            ]
            for index, event in enumerate(events):
                detail = (
                    str(int(event[1]))
                    if isinstance(event[1], signal.Signals)
                    else "none"
                )
                trace.append(
                    f"FR-0002-REPRO event_index={index} "
                    f"event={event[0]} detail={detail}"
                )
            trace.extend(
                (
                    "FR-0002-REPRO post_reap_group_signal_observed=true",
                    "FR-0002-REPRO result=DEFECT_REPRODUCED",
                )
            )
            sys.stdout.write("\n".join(trace) + "\n")

    def test_bounded_runner_config_bounds_are_enforced_before_spawn(self) -> None:
        verify = _load_verify()
        invalid_timeouts = (
            True,
            "1",
            0,
            -1,
            181,
            math.nan,
            math.inf,
            -math.inf,
        )
        with mock.patch.object(verify.subprocess, "Popen") as popen:
            for timeout_seconds in invalid_timeouts:
                with self.subTest(timeout_seconds=timeout_seconds):
                    with self.assertRaisesRegex(
                        verify.CurrentAuditError, "CONFIG_INVALID"
                    ):
                        _run_python(
                            verify,
                            Path.cwd(),
                            "pass",
                            timeout_seconds,
                            0,
                            0,
                        )
            for stdout_limit, stderr_limit in (
                (-1, 0),
                (0, -1),
                (True, 0),
                (0, False),
                (1.0, 0),
                (0, 1.0),
                ("1", 0),
                (0, None),
                (verify.MAX_GIT_BYTES + 1, 0),
                (0, verify.MAX_GIT_BYTES + 1),
            ):
                with self.subTest(stdout_limit=stdout_limit, stderr_limit=stderr_limit):
                    with self.assertRaisesRegex(
                        verify.CurrentAuditError, "CONFIG_INVALID"
                    ):
                        _run_python(
                            verify,
                            Path.cwd(),
                            "pass",
                            1,
                            stdout_limit,
                            stderr_limit,
                        )
            with self.assertRaisesRegex(verify.CurrentAuditError, "CONFIG_INVALID"):
                verify._run_bounded(
                    [],
                    cwd=Path.cwd(),
                    env={},
                    timeout_seconds=1,
                    stdout_limit=0,
                    stderr_limit=0,
                    error_prefix="TEST_FR_0002",
                    _test_only_allow_uncontained_process=True,
                )
        popen.assert_not_called()

    def test_bounded_runner_platform_and_primitives_reject_before_spawn(
        self,
    ) -> None:
        verify = _load_verify()

        class MissingWaitid:
            def __getattr__(self, name):
                if name == "waitid":
                    raise AttributeError(name)
                return getattr(os, name)

        with (
            mock.patch.object(verify.os, "name", "nt"),
            self.assertRaisesRegex(verify.CurrentAuditError, "POSIX_REQUIRED"),
        ):
            _run_python(verify, Path.cwd(), "pass", 1, 0, 0)
        with (
            mock.patch.object(verify, "os", MissingWaitid()),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "IDENTITY_PRIMITIVE_UNAVAILABLE"
            ),
        ):
            _run_python(verify, Path.cwd(), "pass", 1, 0, 0)
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "UNTRUSTED_HOST_EXECUTABLE"
        ):
            verify._run_bounded(
                ["/bin/echo", "x"],
                cwd=Path.cwd(),
                env={},
                timeout_seconds=1,
                stdout_limit=1,
                stderr_limit=0,
                error_prefix="TEST_FR_0002",
            )

    def test_bounded_runner_clean_success_is_exact(self) -> None:
        verify = _load_verify()
        returncode, stdout, stderr = _run_python(
            verify,
            Path.cwd(),
            "import sys;"
            "sys.stdout.buffer.write(b'alpha');"
            "sys.stderr.buffer.write(b'beta')",
            2,
            5,
            4,
        )
        self.assertEqual((returncode, stdout, stderr), (0, b"alpha", b"beta"))

    def test_bounded_runner_observes_exit_with_wnowait(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_001, returncode=None)
        state = verify._BoundedProcessState(process)
        result = mock.Mock(si_pid=process.pid)
        with mock.patch.object(verify.os, "waitid", return_value=result) as waitid:
            self.assertTrue(verify._bounded_process_exited_unreaped(state))
        waitid.assert_called_once_with(
            verify.os.P_PID,
            process.pid,
            verify.os.WEXITED | verify.os.WNOHANG | verify.os.WNOWAIT,
        )
        self.assertTrue(state.identity_reserved)

    def test_bounded_runner_rejects_mismatched_waitid_identity(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_002, returncode=None)
        state = verify._BoundedProcessState(process)
        result = mock.Mock(si_pid=process.pid + 1)
        with (
            mock.patch.object(verify.os, "waitid", return_value=result),
            self.assertRaisesRegex(verify.CurrentAuditError, "EXIT_IDENTITY_MISMATCH"),
        ):
            verify._bounded_process_exited_unreaped(state)
        self.assertFalse(state.identity_reserved)

    def test_bounded_runner_signals_before_wait_and_never_after_reap(self) -> None:
        verify = _load_verify()
        events = []

        class FakeProcess:
            pid = 72_003
            returncode = None

        process = FakeProcess()
        state = verify._BoundedProcessState(process)

        def record_killpg(_pid, selected_signal):
            events.append(("killpg", selected_signal))

        def record_waitpid(_pid, options):
            self.assertEqual(options, os.WNOHANG)
            events.append(("waitpid", None))
            return process.pid, 0

        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", return_value=True
            ),
            mock.patch.object(verify.os, "killpg", side_effect=record_killpg),
            mock.patch.object(verify.os, "waitpid", side_effect=record_waitpid),
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
        ):
            verify._stop_bounded_process(state)
            verify._stop_bounded_process(state)
        self.assertEqual(
            events,
            [
                ("killpg", signal.SIGTERM),
                ("killpg", signal.SIGKILL),
                ("waitpid", None),
            ],
        )
        self.assertFalse(state.identity_reserved)

    def test_bounded_runner_never_signals_reused_unrelated_process_group(
        self,
    ) -> None:
        verify = _load_verify()
        identity_released = False
        signals = []

        class FakeProcess:
            pid = 72_004
            returncode = None

        process = FakeProcess()
        state = verify._BoundedProcessState(process)

        def guarded_killpg(_pid, selected_signal):
            if identity_released:
                self.fail("a process group was signalled after identity release")
            signals.append(selected_signal)

        def release_identity(_pid, _options):
            nonlocal identity_released
            identity_released = True
            return process.pid, 0

        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", return_value=True
            ),
            mock.patch.object(verify.os, "killpg", side_effect=guarded_killpg),
            mock.patch.object(verify.os, "waitpid", side_effect=release_identity),
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
        ):
            verify._stop_bounded_process(state)
            verify._stop_bounded_process(state)
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(identity_released)

    def test_bounded_runner_waitid_eintr_retries_are_bounded(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_005, returncode=None)
        state = verify._BoundedProcessState(process)
        result = mock.Mock(si_pid=process.pid)
        with mock.patch.object(
            verify.os,
            "waitid",
            side_effect=[
                InterruptedError(),
                OSError(errno.EINTR, "interrupted"),
                result,
            ],
        ) as waitid:
            self.assertTrue(verify._bounded_process_exited_unreaped(state))
        self.assertEqual(waitid.call_count, 3)

    def test_bounded_runner_waitid_echild_forbids_later_group_signal(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_006, returncode=None)
        state = verify._BoundedProcessState(process)
        with (
            mock.patch.object(verify.os, "waitid", side_effect=ChildProcessError()),
            mock.patch.object(verify.os, "killpg") as killpg,
        ):
            errors = verify._stop_bounded_process(state)
        self.assertIn("CURRENT_AUDIT_PROCESS_IDENTITY_LOST", errors)
        self.assertFalse(state.identity_reserved)
        killpg.assert_not_called()

    def test_bounded_runner_waitpid_interruption_abandons_authority(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_007, returncode=None)
        state = verify._BoundedProcessState(process)
        state.leader_exited_before_cleanup = True
        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", return_value=True
            ),
            mock.patch.object(verify.os, "killpg") as killpg,
            mock.patch.object(
                verify.os, "waitpid", side_effect=InterruptedError()
            ) as waitpid,
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
        ):
            errors = verify._stop_bounded_process(state)
            second_errors = verify._stop_bounded_process(state)
        self.assertEqual(waitpid.call_count, 1)
        self.assertEqual(killpg.call_count, 2)
        self.assertEqual(errors, second_errors)
        self.assertIn("CURRENT_AUDIT_PROCESS_REAP_INTERRUPTED", errors)
        self.assertTrue(state.reap_started)
        self.assertFalse(state.identity_reserved)

    def test_bounded_runner_post_real_waitpid_interrupt_forbids_signal(self) -> None:
        verify = _load_verify()
        events = []

        class FakeProcess:
            pid = 72_008
            returncode = None

        process = FakeProcess()
        state = verify._BoundedProcessState(process)
        state.leader_exited_before_cleanup = True

        def reaped_then_interrupted(_pid, _options):
            events.append("waitpid")
            raise InterruptedError()

        def record_signal(_pid, selected_signal):
            events.append(f"signal:{int(selected_signal)}")

        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", return_value=True
            ),
            mock.patch.object(verify.os, "killpg", side_effect=record_signal),
            mock.patch.object(
                verify.os, "waitpid", side_effect=reaped_then_interrupted
            ),
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
        ):
            verify._stop_bounded_process(state)
            verify._stop_bounded_process(state)
        wait_index = events.index("waitpid")
        self.assertEqual(
            events[:wait_index],
            [f"signal:{int(signal.SIGTERM)}", f"signal:{int(signal.SIGKILL)}"],
        )
        self.assertFalse(
            any(event.startswith("signal:") for event in events[wait_index + 1 :])
        )

    def test_bounded_runner_reap_timeout_has_no_second_stop_churn(self) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_009, returncode=None)
        state = verify._BoundedProcessState(process)
        state.leader_exited_before_cleanup = True
        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", return_value=True
            ),
            mock.patch.object(verify.os, "killpg") as killpg,
            mock.patch.object(verify.os, "waitpid", return_value=(0, 0)) as waitpid,
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
            mock.patch.object(verify.time, "monotonic", return_value=0.0),
            mock.patch.object(verify.time, "sleep"),
        ):
            first = verify._stop_bounded_process(state)
            second = verify._stop_bounded_process(state)
        self.assertEqual(waitpid.call_count, 51)
        self.assertEqual(killpg.call_count, 2)
        self.assertEqual(first, second)
        self.assertIn("CURRENT_AUDIT_PROCESS_STOP_TIMEOUT", first)
        self.assertIn(
            "CURRENT_AUDIT_SIGNALLING_AUTHORITY_ABANDONED_WITH_LIVE_LEADER",
            first,
        )
        self.assertTrue(state.identity_reserved)
        self.assertTrue(state.reap_started)

    def test_bounded_runner_signal_mask_failures_have_stable_codes(self) -> None:
        verify = _load_verify()

        class FakeProcess:
            pid = 72_010
            returncode = None

        block_state = verify._BoundedProcessState(FakeProcess())
        with (
            mock.patch.object(
                verify.signal,
                "pthread_sigmask",
                side_effect=OSError(errno.EIO, "mask"),
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "SIGNAL_MASK_BLOCK_FAILED"
            ),
        ):
            verify._reap_bounded_process(block_state)
        self.assertFalse(block_state.reap_started)
        self.assertTrue(block_state.identity_reserved)

        restore_state = verify._BoundedProcessState(FakeProcess())
        calls = 0

        def mask_then_fail(_operation, _mask):
            nonlocal calls
            calls += 1
            if calls == 1:
                return set()
            raise OSError(errno.EIO, "restore")

        with (
            mock.patch.object(
                verify.signal, "pthread_sigmask", side_effect=mask_then_fail
            ),
            mock.patch.object(
                verify.os,
                "waitpid",
                return_value=(restore_state.process.pid, 0),
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "SIGNAL_MASK_RESTORE_FAILED"
            ),
        ):
            verify._reap_bounded_process(restore_state)
        self.assertTrue(restore_state.reap_started)
        self.assertFalse(restore_state.identity_reserved)

    def test_bounded_runner_reap_signal_mask_excludes_fault_signals(self) -> None:
        verify = _load_verify()
        blocked = verify._bounded_reap_signal_set()
        for name in (
            "SIGABRT",
            "SIGBUS",
            "SIGFPE",
            "SIGILL",
            "SIGSEGV",
            "SIGSYS",
            "SIGTRAP",
        ):
            selected = getattr(signal, name, None)
            if selected is not None:
                self.assertNotIn(selected, blocked)
        self.assertNotIn(signal.SIGKILL, blocked)
        self.assertNotIn(signal.SIGSTOP, blocked)

    def test_bounded_runner_waitid_eio_still_signals_and_reaps(self) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        real_waitpid = os.waitpid
        captured = []
        events = []

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        def record_signal(pid, selected_signal):
            events.append(f"signal:{int(selected_signal)}")
            return real_killpg(pid, selected_signal)

        def record_waitpid(pid, options):
            events.append("waitpid")
            return real_waitpid(pid, options)

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(
                verify.os,
                "waitid",
                side_effect=OSError(errno.EIO, "waitid"),
            ) as waitid,
            mock.patch.object(verify.os, "killpg", side_effect=record_signal),
            mock.patch.object(verify.os, "waitpid", side_effect=record_waitpid),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "PROCESS_EXIT_CHECK_FAILED"
            ) as raised,
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                2,
                0,
                0,
            )
        self.assertIn(f"signal:{int(signal.SIGTERM)}", events)
        self.assertIn(f"signal:{int(signal.SIGKILL)}", events)
        self.assertIn("waitpid", events)
        self.assertLessEqual(waitid.call_count, 4)
        self.assertIn("CLEANUP=", str(raised.exception))
        self.assertEqual(captured[0].returncode is not None, True)

    def test_bounded_runner_term_eintr_retries_are_bounded(self) -> None:
        verify = _load_verify()
        real_killpg = os.killpg
        calls = []

        def interrupted_term(pid, selected_signal):
            calls.append(selected_signal)
            if selected_signal == signal.SIGTERM and calls.count(signal.SIGTERM) < 3:
                raise InterruptedError()
            return real_killpg(pid, selected_signal)

        with (
            mock.patch.object(verify.os, "killpg", side_effect=interrupted_term),
            self.assertRaisesRegex(verify.CurrentAuditError, "TIMEOUT"),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                0.02,
                0,
                0,
            )
        self.assertEqual(calls.count(signal.SIGTERM), 3)
        self.assertGreaterEqual(calls.count(signal.SIGKILL), 1)

    def test_bounded_runner_kill_eintr_retries_are_bounded(self) -> None:
        verify = _load_verify()
        real_killpg = os.killpg
        calls = []

        def interrupted_kill(pid, selected_signal):
            calls.append(selected_signal)
            if selected_signal == signal.SIGKILL and calls.count(signal.SIGKILL) < 3:
                raise InterruptedError()
            return real_killpg(pid, selected_signal)

        with mock.patch.object(verify.os, "killpg", side_effect=interrupted_kill):
            with self.assertRaises(verify.CurrentAuditError):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import time;time.sleep(30)",
                    0.02,
                    0,
                    0,
                )
        self.assertEqual(calls.count(signal.SIGKILL), 3)

    def test_bounded_runner_persistent_term_failure_reaps_before_error(
        self,
    ) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        captured = []
        signals = []

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        def fail_term(pid, selected_signal):
            signals.append(selected_signal)
            if selected_signal == signal.SIGTERM:
                raise OSError(errno.EIO, "term")
            return real_killpg(pid, selected_signal)

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(verify.os, "killpg", side_effect=fail_term),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "PROCESS_GROUP_SIGNAL_FAILED"
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                0.02,
                0,
                0,
            )
        self.assertIn(signal.SIGKILL, signals)
        self.assertIsNotNone(captured[0].returncode)

    def test_bounded_runner_persistent_kill_failure_reaps_before_error(
        self,
    ) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        captured = []
        signals = []

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        def fail_kill(pid, selected_signal):
            signals.append(selected_signal)
            if selected_signal == signal.SIGKILL:
                raise OSError(errno.EIO, "kill")
            return real_killpg(pid, selected_signal)

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(verify.os, "killpg", side_effect=fail_kill),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "PROCESS_GROUP_SIGNAL_FAILED"
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                0.02,
                0,
                0,
            )
        self.assertIn(signal.SIGTERM, signals)
        self.assertIn(signal.SIGKILL, signals)
        self.assertIsNotNone(captured[0].returncode)

    def test_bounded_runner_arbitrary_base_exception_continues_cleanup(
        self,
    ) -> None:
        verify = _load_verify()
        events = []

        class CleanupInterrupt(BaseException):
            pass

        class FakeProcess:
            pid = 72_011
            returncode = None

        process = FakeProcess()
        state = verify._BoundedProcessState(process)
        observations = 0

        def observe(_state):
            nonlocal observations
            observations += 1
            if observations == 2:
                raise CleanupInterrupt("during grace")
            return observations > 2

        def record_signal(_pid, selected_signal):
            events.append(f"signal:{int(selected_signal)}")

        def record_waitpid(_pid, _options):
            events.append("waitpid")
            return process.pid, 0

        with (
            mock.patch.object(
                verify, "_bounded_process_exited_unreaped", side_effect=observe
            ),
            mock.patch.object(verify.os, "killpg", side_effect=record_signal),
            mock.patch.object(verify.os, "waitpid", side_effect=record_waitpid),
            mock.patch.object(verify.signal, "pthread_sigmask", return_value=set()),
            self.assertRaises(CleanupInterrupt),
        ):
            verify._stop_bounded_process(state)
        self.assertEqual(
            events,
            [
                f"signal:{int(signal.SIGTERM)}",
                f"signal:{int(signal.SIGKILL)}",
                "waitpid",
            ],
        )
        self.assertFalse(state.identity_reserved)

    def test_bounded_runner_cleanup_base_exception_overrides_primary(
        self,
    ) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        captured = []

        class CleanupInterrupt(BaseException):
            pass

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        try:
            with (
                mock.patch.object(
                    verify.subprocess, "Popen", side_effect=start_process
                ),
                mock.patch.object(
                    verify.selectors,
                    "DefaultSelector",
                    side_effect=OSError(errno.EMFILE, "selector"),
                ),
                mock.patch.object(
                    verify,
                    "_stop_bounded_process",
                    side_effect=CleanupInterrupt("cleanup"),
                ),
                self.assertRaises(CleanupInterrupt) as raised,
            ):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import time;time.sleep(30)",
                    1,
                    0,
                    0,
                )
        finally:
            if captured and captured[0].returncode is None:
                try:
                    real_killpg(captured[0].pid, signal.SIGKILL)
                except OSError:
                    pass
                captured[0].wait(timeout=2)
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(any(note.startswith("PRIMARY=") for note in notes))

    def test_bounded_runner_normal_cleanup_exception_keeps_primary_status(
        self,
    ) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        captured = []

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        try:
            with (
                mock.patch.object(
                    verify.subprocess, "Popen", side_effect=start_process
                ),
                mock.patch.object(
                    verify,
                    "_stop_bounded_process",
                    side_effect=OSError(errno.EIO, "cleanup"),
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "TIMEOUT:CLEANUP=CURRENT_AUDIT_CLEANUP_EXCEPTION",
                ),
            ):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import time;time.sleep(30)",
                    0.01,
                    0,
                    0,
                )
        finally:
            if captured and captured[0].returncode is None:
                try:
                    real_killpg(captured[0].pid, signal.SIGKILL)
                except OSError:
                    pass
                captured[0].wait(timeout=2)
                captured[0].stdout.close()
                captured[0].stderr.close()
        self.assertIsNotNone(captured[0].returncode)

    def test_bounded_runner_late_primary_state_is_not_lost_from_base_error(
        self,
    ) -> None:
        verify = _load_verify()
        real_observe = verify._bounded_process_exited_unreaped
        observations = 0

        class EarlyInterrupt(BaseException):
            pass

        def interrupt_then_observe(state):
            nonlocal observations
            observations += 1
            if observations == 1:
                _wait_for_path(child_path)
                raise EarlyInterrupt("early")
            return real_observe(state)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            child_path = root / "escaped.pid"
            child = (
                "import os,time;"
                f"open({str(child_path)!r},'w').write(str(os.getpid()));"
                "time.sleep(30)"
            )
            leader = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}],"
                "start_new_session=True)"
            )
            try:
                with (
                    mock.patch.object(
                        verify,
                        "_bounded_process_exited_unreaped",
                        side_effect=interrupt_then_observe,
                    ),
                    self.assertRaises(EarlyInterrupt) as raised,
                ):
                    _run_python(verify, root, leader, 2, 0, 0)
                _wait_for_path(child_path)
                notes = getattr(raised.exception, "__notes__", ())
                self.assertIn("PRIMARY=ORPHANED_PROCESS_GROUP", notes)
            finally:
                if child_path.exists():
                    _kill_if_present(int(child_path.read_text(encoding="utf-8")))

    def test_bounded_runner_reap_base_exception_retains_prior_context(
        self,
    ) -> None:
        verify = _load_verify()

        class ReapInterrupt(BaseException):
            pass

        process = mock.Mock(pid=72_013, returncode=None)
        state = verify._BoundedProcessState(process)
        with (
            mock.patch.object(
                verify,
                "_bounded_process_exited_unreaped",
                side_effect=[RuntimeError("earlier cleanup"), True, True],
            ),
            mock.patch.object(verify.os, "killpg"),
            mock.patch.object(
                verify,
                "_reap_bounded_process",
                side_effect=ReapInterrupt("reap"),
            ),
            self.assertRaises(ReapInterrupt) as raised,
        ):
            verify._stop_bounded_process(state)
        notes = getattr(raised.exception, "__notes__", ())
        self.assertIn("PRIMARY=earlier cleanup", notes)

    def test_bounded_runner_post_spawn_state_failure_still_cleans_child(
        self,
    ) -> None:
        verify = _load_verify()
        real_state = verify._BoundedProcessState
        real_popen = subprocess.Popen
        captured = []
        state_calls = 0

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        def interrupt_first_state(process):
            nonlocal state_calls
            state_calls += 1
            if state_calls == 1:
                raise KeyboardInterrupt()
            return real_state(process)

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(
                verify,
                "_BoundedProcessState",
                side_effect=interrupt_first_state,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                2,
                0,
                0,
            )
        self.assertEqual(state_calls, 2)
        self.assertIsNotNone(captured[0].returncode)
        self.assertTrue(captured[0].stdout.closed)
        self.assertTrue(captured[0].stderr.closed)

    def test_bounded_runner_popen_base_exception_closes_stdin(self) -> None:
        verify = _load_verify()

        class SpawnInterrupt(BaseException):
            pass

        with tempfile.TemporaryDirectory() as raw:
            stdin_path = Path(raw) / "input"
            stdin_path.write_bytes(b"data")
            real_open = open
            opened = []

            def capture_open(*arguments, **keywords):
                handle = real_open(*arguments, **keywords)
                opened.append(handle)
                return handle

            with (
                mock.patch("builtins.open", side_effect=capture_open),
                mock.patch.object(
                    verify.subprocess,
                    "Popen",
                    side_effect=SpawnInterrupt("spawn"),
                ),
                self.assertRaises(SpawnInterrupt),
            ):
                verify._run_bounded(
                    [sys.executable, "-c", "pass"],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=2,
                    stdout_limit=0,
                    stderr_limit=0,
                    error_prefix="TEST_FR_0002",
                    stdin_path=stdin_path,
                    _test_only_allow_uncontained_process=True,
                )
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].closed)

    def test_bounded_runner_stdin_close_failure_cleans_owned_process(self) -> None:
        verify = _load_verify()
        real_open = open
        real_popen = subprocess.Popen
        captured = []
        wrappers = []

        class CloseOnce:
            def __init__(self, handle):
                self.handle = handle
                self.calls = 0

            def fileno(self):
                return self.handle.fileno()

            def close(self):
                self.calls += 1
                if self.calls == 1:
                    raise OSError(errno.EIO, "close")
                return self.handle.close()

        def wrapped_open(*arguments, **keywords):
            wrapper = CloseOnce(real_open(*arguments, **keywords))
            wrappers.append(wrapper)
            return wrapper

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        with tempfile.TemporaryDirectory() as raw:
            stdin_path = Path(raw) / "input"
            stdin_path.write_bytes(b"data")
            with (
                mock.patch("builtins.open", side_effect=wrapped_open),
                mock.patch.object(
                    verify.subprocess, "Popen", side_effect=start_process
                ),
                self.assertRaisesRegex(verify.CurrentAuditError, "STDIN_CLOSE_FAILED"),
            ):
                verify._run_bounded(
                    [sys.executable, "-c", "import time;time.sleep(30)"],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=2,
                    stdout_limit=0,
                    stderr_limit=0,
                    error_prefix="TEST_FR_0002",
                    stdin_path=stdin_path,
                    _test_only_allow_uncontained_process=True,
                )
        self.assertIsNotNone(captured[0].returncode)
        self.assertGreaterEqual(wrappers[0].calls, 2)
        self.assertTrue(wrappers[0].handle.closed)

    def test_bounded_runner_selector_constructor_failure_cleans_resources(
        self,
    ) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        captured = []

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(
                verify.selectors,
                "DefaultSelector",
                side_effect=OSError(errno.EMFILE, "selector"),
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "SELECTOR_CONSTRUCT_FAILED"
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                2,
                0,
                0,
            )
        self.assertIsNotNone(captured[0].returncode)
        self.assertTrue(captured[0].stdout.closed)
        self.assertTrue(captured[0].stderr.closed)

    def test_bounded_runner_pipe_setup_failures_clean_resources(self) -> None:
        verify = _load_verify()
        real_popen = subprocess.Popen
        real_selector_factory = verify.selectors.DefaultSelector

        for fault in ("set_blocking", "register"):
            captured = []

            def start_process(*arguments, **keywords):
                process = real_popen(*arguments, **keywords)
                captured.append(process)
                return process

            class RegisterFailureSelector:
                def __init__(self):
                    self.selector = real_selector_factory()

                def register(self, *_arguments, **_keywords):
                    raise OSError(errno.EIO, "register")

                def unregister(self, stream):
                    return self.selector.unregister(stream)

                def select(self, timeout):
                    return self.selector.select(timeout)

                def close(self):
                    return self.selector.close()

            patches = [
                mock.patch.object(verify.subprocess, "Popen", side_effect=start_process)
            ]
            if fault == "set_blocking":
                patches.append(
                    mock.patch.object(
                        verify.os,
                        "set_blocking",
                        side_effect=OSError(errno.EIO, "set_blocking"),
                    )
                )
            else:
                patches.append(
                    mock.patch.object(
                        verify.selectors,
                        "DefaultSelector",
                        side_effect=RegisterFailureSelector,
                    )
                )
            with self.subTest(fault=fault):
                with (
                    patches[0],
                    patches[1],
                    self.assertRaisesRegex(
                        verify.CurrentAuditError,
                        "NONBLOCKING_FAILED|REGISTER_FAILED",
                    ),
                ):
                    _run_python(
                        verify,
                        Path.cwd(),
                        "import time;time.sleep(30)",
                        2,
                        0,
                        0,
                    )
                self.assertIsNotNone(captured[0].returncode)
                self.assertTrue(captured[0].stdout.closed)
                self.assertTrue(captured[0].stderr.closed)

    def test_bounded_runner_selector_eintr_retries_are_bounded(self) -> None:
        verify = _load_verify()
        real_selector_factory = verify.selectors.DefaultSelector
        proxies = []

        class InterruptingSelector:
            def __init__(self):
                self.selector = real_selector_factory()
                self.calls = 0
                proxies.append(self)

            def register(self, *arguments, **keywords):
                return self.selector.register(*arguments, **keywords)

            def unregister(self, *arguments, **keywords):
                return self.selector.unregister(*arguments, **keywords)

            def get_map(self):
                return self.selector.get_map()

            def select(self, timeout):
                self.calls += 1
                if self.calls <= 2:
                    raise InterruptedError()
                return self.selector.select(timeout)

            def close(self):
                return self.selector.close()

        with mock.patch.object(
            verify.selectors,
            "DefaultSelector",
            side_effect=InterruptingSelector,
        ):
            result = _run_python(
                verify,
                Path.cwd(),
                "pass",
                2,
                0,
                0,
            )
        self.assertEqual(result, (0, b"", b""))
        self.assertGreaterEqual(proxies[0].calls, 3)

        class PersistentInterruptSelector(InterruptingSelector):
            def select(self, timeout):
                self.calls += 1
                raise InterruptedError()

        proxies.clear()
        with (
            mock.patch.object(
                verify.selectors,
                "DefaultSelector",
                side_effect=PersistentInterruptSelector,
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError, "SELECTOR_SELECT_INTERRUPTED"
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                2,
                0,
                0,
            )
        self.assertLessEqual(proxies[0].calls, 8)

    def test_bounded_runner_read_errors_are_bounded(self) -> None:
        verify = _load_verify()
        real_read = os.read
        real_popen = subprocess.Popen
        calls = 0

        def start_process(*arguments, **keywords):
            with mock.patch.object(verify.os, "read", real_read):
                return real_popen(*arguments, **keywords)

        def finite_interrupt(fd, size):
            nonlocal calls
            calls += 1
            if calls <= 2:
                raise InterruptedError()
            return real_read(fd, size)

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(verify.os, "read", side_effect=finite_interrupt),
        ):
            result = _run_python(
                verify,
                Path.cwd(),
                "import sys;sys.stdout.buffer.write(b'x')",
                2,
                1,
                0,
            )
        self.assertEqual(result[1], b"x")
        self.assertGreaterEqual(calls, 3)

        calls = 0

        def persistent_interrupt(_fd, _size):
            nonlocal calls
            calls += 1
            raise InterruptedError()

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(verify.os, "read", side_effect=persistent_interrupt),
            self.assertRaisesRegex(verify.CurrentAuditError, "STREAM_READ_INTERRUPTED"),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import sys,time;"
                "sys.stdout.buffer.write(b'x');sys.stdout.flush();time.sleep(30)",
                2,
                1,
                0,
            )
        self.assertEqual(calls, 8)

        eio_calls = 0

        def fail_read(_fd, _size):
            nonlocal eio_calls
            eio_calls += 1
            raise OSError(errno.EIO, "read")

        with (
            mock.patch.object(verify.subprocess, "Popen", side_effect=start_process),
            mock.patch.object(
                verify.os,
                "read",
                side_effect=fail_read,
            ),
            self.assertRaisesRegex(verify.CurrentAuditError, "STREAM_READ_FAILED"),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import sys,time;"
                "sys.stdout.buffer.write(b'x');sys.stdout.flush();time.sleep(30)",
                2,
                1,
                0,
            )
        self.assertEqual(eio_calls, 1)

    def test_bounded_runner_resource_close_failures_are_aggregated(self) -> None:
        verify = _load_verify()
        real_selector_factory = verify.selectors.DefaultSelector
        real_popen = subprocess.Popen
        captured = []

        class CloseFailureStream:
            def __init__(self, stream):
                self.stream = stream

            def fileno(self):
                return self.stream.fileno()

            def close(self):
                raise OSError(errno.EIO, "stream close")

        class CleanupFailureSelector:
            def __init__(self):
                self.selector = real_selector_factory()

            def register(self, *arguments, **keywords):
                return self.selector.register(*arguments, **keywords)

            def unregister(self, _stream):
                raise OSError(errno.EIO, "unregister")

            def get_map(self):
                return self.selector.get_map()

            def select(self, timeout):
                return self.selector.select(timeout)

            def close(self):
                self.selector.close()
                raise OSError(errno.EIO, "selector close")

        def start_process(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            process.stdout = CloseFailureStream(process.stdout)
            process.stderr = CloseFailureStream(process.stderr)
            return process

        try:
            with (
                mock.patch.object(
                    verify.subprocess, "Popen", side_effect=start_process
                ),
                mock.patch.object(
                    verify.selectors,
                    "DefaultSelector",
                    side_effect=CleanupFailureSelector,
                ),
                self.assertRaises(verify.CurrentAuditError) as raised,
            ):
                _run_python(
                    verify,
                    Path.cwd(),
                    "pass",
                    2,
                    0,
                    0,
                )
            message = str(raised.exception)
            self.assertIn("SELECTOR_UNREGISTER_FAILED:stdout", message)
            self.assertIn("SELECTOR_UNREGISTER_FAILED:stderr", message)
            self.assertIn("STREAM_CLOSE_FAILED:stdout", message)
            self.assertIn("STREAM_CLOSE_FAILED:stderr", message)
            self.assertIn("SELECTOR_CLOSE_FAILED", message)
        finally:
            if captured:
                captured[0].stdout.stream.close()
                captured[0].stderr.stream.close()

    def test_bounded_runner_zero_limit_and_multibyte_limits_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        self.assertEqual(
            _run_python(verify, Path.cwd(), "pass", 2, 0, 0),
            (0, b"", b""),
        )
        with self.assertRaisesRegex(verify.CurrentAuditError, "OUTPUT_BOUND"):
            _run_python(
                verify,
                Path.cwd(),
                "import sys;sys.stdout.buffer.write(b'x')",
                2,
                0,
                0,
            )
        euro = "€".encode("utf-8")
        result = _run_python(
            verify,
            Path.cwd(),
            f"import sys;sys.stdout.buffer.write({euro!r})",
            2,
            3,
            0,
        )
        self.assertEqual(result[1], euro)
        with self.assertRaisesRegex(verify.CurrentAuditError, "OUTPUT_BOUND"):
            _run_python(
                verify,
                Path.cwd(),
                f"import sys;sys.stdout.buffer.write({euro!r})",
                2,
                2,
                0,
            )

    def test_bounded_runner_dual_stream_pressure_is_exact(self) -> None:
        verify = _load_verify()
        size = 512 * 1024
        result = _run_python(
            verify,
            Path.cwd(),
            "import sys;"
            f"sys.stdout.buffer.write(b'a'*{size});"
            f"sys.stderr.buffer.write(b'b'*{size})",
            5,
            size,
            size,
        )
        self.assertEqual(result[0], 0)
        self.assertEqual(result[1], b"a" * size)
        self.assertEqual(result[2], b"b" * size)

    def test_bounded_runner_error_precedence_retains_cleanup_detail(self) -> None:
        verify = _load_verify()
        with (
            mock.patch.object(
                verify.os,
                "killpg",
                side_effect=PermissionError(errno.EPERM, "permission"),
            ),
            mock.patch.object(verify.sys, "platform", "linux"),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "OUTPUT_BOUND:CLEANUP=.*PROCESS_GROUP_PERMISSION_UNPROVED",
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import sys;sys.stdout.buffer.write(b'x')",
                2,
                0,
                0,
            )

    def test_bounded_runner_darwin_eperm_is_only_an_accepted_residual(
        self,
    ) -> None:
        verify = _load_verify()
        process = mock.Mock(pid=72_012, returncode=None)
        state = verify._BoundedProcessState(process)
        for platform in ("darwin", "linux"):
            for leader_exited in (False, True):
                for pipes_eof in (False, True):
                    state.leader_exited_before_cleanup = leader_exited
                    state.pipes_eof_before_cleanup = pipes_eof
                    expected = bool(
                        platform == "darwin" and leader_exited and pipes_eof
                    )
                    with (
                        self.subTest(
                            platform=platform,
                            leader_exited=leader_exited,
                            pipes_eof=pipes_eof,
                        ),
                        mock.patch.object(verify.sys, "platform", platform),
                    ):
                        self.assertEqual(
                            verify._bounded_darwin_eperm_is_acceptable(state),
                            expected,
                        )

    def test_bounded_runner_eperm_end_to_end_acceptance_is_narrow(
        self,
    ) -> None:
        verify = _load_verify()
        permission_error = PermissionError(errno.EPERM, "permission")
        with (
            mock.patch.object(verify.os, "killpg", side_effect=permission_error),
            mock.patch.object(verify.sys, "platform", "darwin"),
        ):
            self.assertEqual(
                _run_python(verify, Path.cwd(), "pass", 2, 0, 0),
                (0, b"", b""),
            )

        with (
            mock.patch.object(
                verify.os,
                "killpg",
                side_effect=PermissionError(errno.EPERM, "permission"),
            ),
            mock.patch.object(verify.sys, "platform", "linux"),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "PROCESS_GROUP_PERMISSION_UNPROVED",
            ),
        ):
            _run_python(verify, Path.cwd(), "pass", 2, 0, 0)

        real_killpg = os.killpg

        def signal_then_report_eperm(pid, selected_signal):
            try:
                real_killpg(pid, selected_signal)
            except OSError:
                pass
            raise PermissionError(errno.EPERM, "permission")

        with (
            mock.patch.object(
                verify.os, "killpg", side_effect=signal_then_report_eperm
            ),
            mock.patch.object(verify.sys, "platform", "darwin"),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "TIMEOUT:CLEANUP=.*PROCESS_GROUP_PERMISSION_UNPROVED",
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                0.01,
                0,
                0,
            )

    def test_bounded_runner_eperm_with_inherited_pipe_fails_closed(self) -> None:
        verify = _load_verify()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            child_path = root / "escaped.pid"
            child = (
                "import os,time;"
                f"open({str(child_path)!r},'w').write(str(os.getpid()));"
                "time.sleep(30)"
            )
            leader = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}],"
                "start_new_session=True)"
            )
            try:
                with (
                    mock.patch.object(
                        verify.os,
                        "killpg",
                        side_effect=PermissionError(errno.EPERM, "permission"),
                    ),
                    mock.patch.object(verify.sys, "platform", "darwin"),
                    self.assertRaisesRegex(
                        verify.CurrentAuditError,
                        "ORPHANED_PROCESS_GROUP.*PROCESS_GROUP_PERMISSION_UNPROVED",
                    ),
                ):
                    _run_python(verify, root, leader, 2, 0, 0)
                _wait_for_path(child_path)
                escaped_pid = int(child_path.read_text(encoding="utf-8"))
                os.kill(escaped_pid, 0)
            finally:
                if child_path.exists():
                    _kill_if_present(int(child_path.read_text(encoding="utf-8")))

    def test_bounded_runner_same_group_descendant_is_killed_before_reap(
        self,
    ) -> None:
        verify = _load_verify()
        short_leader = (
            "import subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c',"
            "'import time;time.sleep(0.2)'])"
        )
        self.assertEqual(
            _run_python(verify, Path.cwd(), short_leader, 2, 0, 0),
            (0, b"", b""),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            child_path = root / "child.pid"
            child = (
                "import os,time;"
                f"open({str(child_path)!r},'w').write(str(os.getpid()));"
                "time.sleep(30)"
            )
            leader = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}])"
            )
            with self.assertRaisesRegex(
                verify.CurrentAuditError, "ORPHANED_PROCESS_GROUP"
            ):
                _run_python(verify, root, leader, 2, 0, 0)
            _wait_for_path(child_path)
            child_pid = int(child_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if not _pid_is_running(child_pid):
                    break
                time.sleep(0.01)
            else:
                self.fail("same-group descendant survived cleanup")

    def test_bounded_runner_setsid_escape_fails_without_reused_signal(
        self,
    ) -> None:
        verify = _load_verify()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            leader_path = root / "leader.pid"
            child_path = root / "child.pid"
            child = (
                "import os,time;"
                f"open({str(child_path)!r},'w').write(str(os.getpid()));"
                "time.sleep(30)"
            )
            leader = (
                "import os,subprocess,sys;"
                f"open({str(leader_path)!r},'w').write(str(os.getpid()));"
                f"subprocess.Popen([sys.executable,'-c',{child!r}],"
                "start_new_session=True)"
            )
            signalled_groups = []
            real_killpg = os.killpg

            def record_signal(pid, selected_signal):
                signalled_groups.append(pid)
                return real_killpg(pid, selected_signal)

            try:
                with (
                    mock.patch.object(verify.os, "killpg", side_effect=record_signal),
                    self.assertRaisesRegex(
                        verify.CurrentAuditError, "ORPHANED_PROCESS_GROUP"
                    ),
                ):
                    _run_python(verify, root, leader, 2, 0, 0)
                _wait_for_path(leader_path)
                _wait_for_path(child_path)
                leader_pid = int(leader_path.read_text(encoding="utf-8"))
                child_pid = int(child_path.read_text(encoding="utf-8"))
                self.assertEqual(set(signalled_groups), {leader_pid})
                os.kill(child_pid, 0)
            finally:
                if child_path.exists():
                    _kill_if_present(int(child_path.read_text(encoding="utf-8")))

    def test_bounded_runner_interrupt_signals_before_wait(self) -> None:
        verify = _load_verify()
        real_killpg = os.killpg
        real_waitpid = os.waitpid
        events = []

        def record_signal(pid, selected_signal):
            events.append(f"signal:{int(selected_signal)}")
            return real_killpg(pid, selected_signal)

        def record_waitpid(pid, options):
            events.append("waitpid")
            return real_waitpid(pid, options)

        timer = threading.Timer(0.05, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            with (
                mock.patch.object(verify.os, "killpg", side_effect=record_signal),
                mock.patch.object(verify.os, "waitpid", side_effect=record_waitpid),
                self.assertRaises(KeyboardInterrupt),
            ):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import time;time.sleep(30)",
                    10,
                    0,
                    0,
                )
        finally:
            timer.cancel()
            timer.join()
        wait_index = events.index("waitpid")
        self.assertEqual(
            events[:wait_index],
            [f"signal:{int(signal.SIGTERM)}", f"signal:{int(signal.SIGKILL)}"],
        )
        self.assertFalse(
            any(event.startswith("signal:") for event in events[wait_index + 1 :])
        )

    def test_bounded_runner_repeated_modes_preserve_fd_and_thread_counts(
        self,
    ) -> None:
        verify = _load_verify()
        baseline_fds = _fd_count()
        baseline_threads = {thread.ident for thread in threading.enumerate()}
        executed = 0
        for _iteration in range(20):
            self.assertEqual(
                _run_python(verify, Path.cwd(), "pass", 2, 0, 0),
                (0, b"", b""),
            )
            executed += 1
            with self.assertRaisesRegex(verify.CurrentAuditError, "TIMEOUT"):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import time;time.sleep(30)",
                    0.01,
                    0,
                    0,
                )
            executed += 1
            with self.assertRaisesRegex(verify.CurrentAuditError, "OUTPUT_BOUND"):
                _run_python(
                    verify,
                    Path.cwd(),
                    "import sys;sys.stdout.buffer.write(b'x')",
                    2,
                    0,
                    0,
                )
            executed += 1
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                child_path = root / "escaped.pid"
                child = (
                    "import os,time;"
                    f"open({str(child_path)!r},'w').write(str(os.getpid()));"
                    "time.sleep(30)"
                )
                leader = (
                    "import subprocess,sys;"
                    f"subprocess.Popen([sys.executable,'-c',{child!r}],"
                    "start_new_session=True)"
                )
                try:
                    with self.assertRaisesRegex(
                        verify.CurrentAuditError, "ORPHANED_PROCESS_GROUP"
                    ):
                        _run_python(verify, root, leader, 2, 0, 0)
                    _wait_for_path(child_path)
                finally:
                    if child_path.exists():
                        _kill_if_present(int(child_path.read_text(encoding="utf-8")))
            executed += 1
            timer = threading.Timer(0.03, lambda: os.kill(os.getpid(), signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    _run_python(
                        verify,
                        Path.cwd(),
                        "import time;time.sleep(30)",
                        10,
                        0,
                        0,
                    )
            finally:
                timer.cancel()
                timer.join()
            executed += 1
            self.assertEqual(_fd_count(), baseline_fds)
            self.assertEqual(
                {thread.ident for thread in threading.enumerate()},
                baseline_threads,
            )
        self.assertEqual(executed, 100)

    def test_bounded_runner_constructs_no_reader_threads(self) -> None:
        verify = _load_verify()
        with mock.patch.object(threading, "Thread") as thread_constructor:
            result = _run_python(
                verify,
                Path.cwd(),
                "import sys;"
                "sys.stdout.buffer.write(b'a');"
                "sys.stderr.buffer.write(b'b')",
                2,
                1,
                1,
            )
        self.assertEqual(result, (0, b"a", b"b"))
        thread_constructor.assert_not_called()
        self.assertNotIn("threading", verify._run_bounded.__code__.co_names)

    def test_bounded_runner_timeout_and_pipe_errors_keep_precedence(
        self,
    ) -> None:
        verify = _load_verify()
        real_killpg = os.killpg

        def signal_then_report_eperm(pid, selected_signal):
            try:
                real_killpg(pid, selected_signal)
            except OSError:
                pass
            raise PermissionError(errno.EPERM, "permission")

        with (
            mock.patch.object(
                verify.os,
                "killpg",
                side_effect=signal_then_report_eperm,
            ),
            mock.patch.object(verify.sys, "platform", "linux"),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "TIMEOUT:CLEANUP=.*PROCESS_GROUP_PERMISSION_UNPROVED",
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                0.01,
                0,
                0,
            )

        real_selector_factory = verify.selectors.DefaultSelector

        class SelectFailure:
            def __init__(self):
                self.selector = real_selector_factory()

            def register(self, *arguments, **keywords):
                return self.selector.register(*arguments, **keywords)

            def unregister(self, *arguments, **keywords):
                return self.selector.unregister(*arguments, **keywords)

            def get_map(self):
                return self.selector.get_map()

            def select(self, _timeout):
                raise OSError(errno.EIO, "select")

            def close(self):
                return self.selector.close()

        with (
            mock.patch.object(
                verify.selectors,
                "DefaultSelector",
                side_effect=SelectFailure,
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "PIPE_FAILED:CLEANUP=.*SELECTOR_SELECT_FAILED",
            ),
        ):
            _run_python(
                verify,
                Path.cwd(),
                "import time;time.sleep(30)",
                2,
                0,
                0,
            )

    def test_framework_recovery_2_evidence_layout_is_exact(self) -> None:
        verify = _load_verify()
        qualification_paths = [
            path
            for requirement in verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS
            for path in requirement["paths"]
        ]
        activation_paths = [
            path
            for requirement in verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS
            for path in requirement["paths"]
        ]
        self.assertEqual(
            [item["id"] for item in verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS],
            [
                "FR-0002-E01",
                "FR-0002-E02",
                "FR-0002-E03",
                "FR-0002-E04",
                "FR-0002-R01",
                "FR-0002-R02",
            ],
        )
        self.assertEqual(
            [item["id"] for item in verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS],
            ["FR-0002-A01", "FR-0002-A02"],
        )
        self.assertEqual(len(qualification_paths), 12)
        self.assertEqual(len(activation_paths), 6)
        self.assertEqual(len(set(qualification_paths)), 12)
        self.assertEqual(len(set(activation_paths)), 6)
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_STATUSES), 13)
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_2_ACTIVATION_STATUSES), 7)
        self.assertEqual(len(verify.FRAMEWORK_RECOVERY_2_REPAIR_STATUSES), 4)
        self.assertFalse(
            any(
                "path" in requirement
                or len(requirement["paths"]) != len(requirement["max_bytes"])
                for requirement in (
                    *verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS,
                    *verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS,
                )
            )
        )
        self.assertFalse(any("-metadata" in path for path in qualification_paths))
        self.assertFalse(any("-metadata" in path for path in activation_paths))

    def test_framework_recovery_2_gate_order_and_warning_policy_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        expected = verify._framework_recovery_2_expected_gate_payload()
        observed = Path(__file__).with_name("current-audit-gate.sh").read_bytes()
        self.assertEqual(observed, expected)
        lines = observed.decode("utf-8").splitlines()
        commands = [line for line in lines if line.startswith('"$PYTHON3"')]
        self.assertEqual(
            commands,
            [
                '"$PYTHON3" -I tools/release/test_verify_current_audit.py',
                (
                    '"$PYTHON3" -I -W error::ResourceWarning '
                    "tools/release/test_verify_current_audit_fr_0002.py"
                ),
                (
                    '"$PYTHON3" -I '
                    "tools/release/test_current_audit_resource_profile.py"
                ),
                '"$PYTHON3" -I tools/release/verify-current-audit.py',
            ],
        )

    def test_bounded_runner_output_bound_final_write_has_no_spurious_cleanup(
        self,
    ) -> None:
        verify = _load_verify()
        limit = 64 * 1024
        for stream, descriptor in (("stdout", 1), ("stderr", 2)):
            with self.subTest(stream=stream):
                status, stdout, stderr = _run_python(
                    verify,
                    Path.cwd(),
                    (
                        "import os;"
                        f"os.write({descriptor}, b'x' * {limit})"
                    ),
                    2,
                    limit if stream == "stdout" else 0,
                    limit if stream == "stderr" else 0,
                )
                self.assertEqual(status, 0)
                self.assertEqual(
                    len(stdout if stream == "stdout" else stderr), limit
                )
                self.assertFalse(stderr if stream == "stdout" else stdout)
                with self.assertRaises(verify.CurrentAuditError) as raised:
                    _run_python(
                        verify,
                        Path.cwd(),
                        (
                            "import os;"
                            f"os.write({descriptor}, b'x' * {limit + 1})"
                        ),
                        2,
                        limit if stream == "stdout" else 0,
                        limit if stream == "stderr" else 0,
                    )
                self.assertEqual(
                    str(raised.exception), "TEST_FR_0002_OUTPUT_BOUND"
                )

    def test_framework_recovery_2_gate_rejects_missing_duplicate_lines(
        self,
    ) -> None:
        verify = _load_verify()
        prefix = b"supply-chain\t2026-07-23T00:00:00Z "
        fr_count = len(verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS)
        lines = [
            prefix + b"Ran 163 tests in 1.000s",
            prefix + b"OK",
            prefix + f"Ran {fr_count} tests in 2.000s".encode("ascii"),
            prefix + b"OK",
            prefix + b"Ran 26 tests in 3.000s",
            prefix + b"OK",
            prefix + b"verify-current-audit: OK",
        ]
        entry = {"files": [{}, {}, {"path": "retained.log.gz"}]}

        def validate(log):
            with (
                mock.patch.object(verify, "_git_file", return_value=b"compressed"),
                mock.patch.object(
                    verify, "_decompress_unbound_gzip", return_value=log
                ),
                mock.patch.object(
                    verify, "_hosted_step_log_lines", return_value=log
                ),
            ):
                verify._framework_recovery_2_verify_ci_markers(
                    Path("."),
                    "a" * 40,
                    entry,
                    fr_0002_count=fr_count,
                    label="fr2",
                )

        clean = b"\n".join(lines) + b"\n"
        validate(clean)
        mutations = (
            b"\n".join(lines[:-1]) + b"\n",
            clean + lines[0] + b"\n",
            clean + prefix + b"skipped=1\n",
            clean + prefix + b"STOP_TIMEOUT\n",
            clean.replace(prefix + b"OK\n", b"", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_CI_LOG_MARKERS",
                ):
                    validate(mutation)

    def test_framework_recovery_2_hosted_capture_mutations_are_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        paths = tuple(
            verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS[1]["paths"]
        )
        run_id = 12345
        json_fields = (
            "conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,status,"
            "updatedAt,url,workflowName"
        )
        attempt_fields = (
            "attempt,conclusion,createdAt,databaseId,event,headBranch,headSha,jobs,"
            "startedAt,status,updatedAt,url,workflowDatabaseId,workflowName"
        )
        ordinary_raw = f"/private/tmp/{Path(paths[0]).name}.raw"
        ordinary_normalized = f"/private/tmp/{Path(paths[0]).name}.normalized"
        attempt_raw = f"/private/tmp/{Path(paths[1]).name}.raw"
        attempt_normalized = f"/private/tmp/{Path(paths[1]).name}.normalized"
        log_raw = f"/private/tmp/{Path(paths[2]).name}.raw"
        log_decompressed = f"/private/tmp/{Path(paths[2]).name}.decompressed"
        operations = {
            "ordinary_metadata": {
                "raw_path": ordinary_raw,
                "normalized_path": ordinary_normalized,
                "retained_path": paths[0],
                "capture_command": (
                    f"gh run view {run_id} --repo sepahead/haldir --json "
                    f"{json_fields} > {ordinary_raw}"
                ),
                "capture_exit_status": 0,
                "normalize_command": (
                    f"jq -S . {ordinary_raw} > {ordinary_normalized}"
                ),
                "normalize_exit_status": 0,
                "compare_command": f"cmp {ordinary_normalized} {paths[0]}",
                "compare_exit_status": 0,
                "byte_equal": True,
                "started_at_utc": "2026-07-23T00:00:01Z",
                "completed_at_utc": "2026-07-23T00:00:02Z",
            },
            "attempt_metadata": {
                "raw_path": attempt_raw,
                "normalized_path": attempt_normalized,
                "retained_path": paths[1],
                "capture_command": (
                    f"gh run view {run_id} --repo sepahead/haldir --attempt 1 "
                    f"--json {attempt_fields} > {attempt_raw}"
                ),
                "capture_exit_status": 0,
                "normalize_command": (
                    f"jq -S . {attempt_raw} > {attempt_normalized}"
                ),
                "normalize_exit_status": 0,
                "compare_command": f"cmp {attempt_normalized} {paths[1]}",
                "compare_exit_status": 0,
                "byte_equal": True,
                "started_at_utc": "2026-07-23T00:00:03Z",
                "completed_at_utc": "2026-07-23T00:00:04Z",
            },
            "raw_log": {
                "raw_path": log_raw,
                "retained_path": paths[2],
                "decompressed_path": log_decompressed,
                "capture_command": (
                    f"gh run view {run_id} --repo sepahead/haldir --attempt 1 "
                    f"--log > {log_raw}"
                ),
                "capture_exit_status": 0,
                "compression_command": f"gzip -n -9 -c {log_raw} > {paths[2]}",
                "compression_exit_status": 0,
                "decompress_command": (
                    f"gzip -cd {paths[2]} > {log_decompressed}"
                ),
                "decompress_exit_status": 0,
                "compare_command": f"cmp {log_raw} {log_decompressed}",
                "compare_exit_status": 0,
                "byte_equal": True,
                "started_at_utc": "2026-07-23T00:00:05Z",
                "completed_at_utc": "2026-07-23T00:00:06Z",
            },
        }

        def validate(candidate):
            return verify._framework_recovery_2_verify_capture_operations(
                candidate,
                run_id=run_id,
                workflow="ci",
                paths=paths,
                head="a" * 40,
                label="fr2.capture",
                not_before=verify._parse_utc(
                    "2026-07-23T00:00:00Z", "lower"
                ),
                retained_by=verify._parse_utc(
                    "2026-07-23T00:00:07Z", "upper"
                ),
            )

        projection = validate(operations)
        self.assertEqual(
            projection["ordinary_metadata"]["normalize_command"],
            f"jq . {ordinary_raw} > {ordinary_normalized}",
        )
        mutations = []
        candidate = copy.deepcopy(operations)
        candidate["attempt_metadata"]["normalize_command"] = (
            f"jq . {attempt_raw} > {attempt_normalized}"
        )
        mutations.append(candidate)
        candidate = copy.deepcopy(operations)
        candidate["attempt_metadata"]["normalized_path"] = ordinary_normalized
        mutations.append(candidate)
        candidate = copy.deepcopy(operations)
        candidate["attempt_metadata"]["compare_exit_status"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(operations)
        candidate["raw_log"]["compression_command"] = (
            f"gzip -c {log_raw} > {paths[2]}"
        )
        mutations.append(candidate)
        candidate = copy.deepcopy(operations)
        candidate["ordinary_metadata"]["started_at_utc"] = (
            "2026-07-22T23:59:59Z"
        )
        mutations.append(candidate)
        candidate = copy.deepcopy(operations)
        del candidate["ordinary_metadata"]["normalize_exit_status"]
        mutations.append(candidate)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(verify.CurrentAuditError):
                    validate(mutation)

    def test_framework_recovery_2_run_attempt_reuse_is_rejected(self) -> None:
        verify = _load_verify()
        entries = [
            ("repair_ci", "a" * 40, {}),
            ("repair_formal", "b" * 40, {}),
            ("qualification_ci", "c" * 40, {}),
            ("qualification_formal", "d" * 40, {}),
        ]
        with mock.patch.object(
            verify,
            "_framework_recovery_2_run_attempt_identity",
            side_effect=[(1, 1), (2, 1), (3, 1), (4, 1)],
        ):
            verify._framework_recovery_2_verify_run_attempt_uniqueness(
                Path("."), entries
            )
        with (
            mock.patch.object(
                verify,
                "_framework_recovery_2_run_attempt_identity",
                side_effect=[(1, 1), (2, 1), (1, 1), (4, 1)],
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_RUN_ATTEMPT_REUSED",
            ),
        ):
            verify._framework_recovery_2_verify_run_attempt_uniqueness(
                Path("."), entries
            )

    def test_framework_recovery_2_reproduction_binding_is_exact(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        raw_log = b"exact merged stdout and stderr\n"

        def file_record(_repo, commit, path):
            return {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "oid": hashlib.sha1(f"{commit}:{path}".encode()).hexdigest(),
                "sha256": hashlib.sha256(f"{commit}:{path}".encode()).hexdigest(),
                "bytes": len(f"{commit}:{path}"),
                "lines": 1,
            }

        with (
            mock.patch.object(verify, "_git_file", return_value=b"compressed"),
            mock.patch.object(
                verify, "_decompress_unbound_gzip", return_value=raw_log
            ),
            mock.patch.object(
                verify,
                "_commit_regular_file_record",
                side_effect=file_record,
            ),
        ):
            expected = verify._framework_recovery_2_expected_parent_reproduction(
                Path("."),
                repair_commit,
                qualification_commit,
                started_at_utc="2026-07-23T00:00:01Z",
                completed_at_utc="2026-07-23T00:00:02Z",
            )
            evidence_record = {
                "files": [None, expected["raw_log"]["file"]],
                "uncompressed": [None, expected["raw_log"]["uncompressed"]],
            }
            plan = {
                "deterministic_parent_reproduction": {
                    "command": list(
                        verify._framework_recovery_2_parent_reproduction_command()
                    ),
                    "test_id": expected["test_id"],
                }
            }
            with mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[
                    verify._parse_utc("2026-07-23T00:00:00Z", "repair"),
                    verify._parse_utc("2026-07-23T00:00:03Z", "qualification"),
                ],
            ):
                verify._validate_framework_recovery_2_parent_reproduction(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    expected,
                    plan=plan,
                    evidence_record=evidence_record,
                )
            mutations = []
            candidate = copy.deepcopy(expected)
            candidate["observed_events"][-1] = "killpg:SIGKILL"
            mutations.append(candidate)
            candidate = copy.deepcopy(expected)
            candidate["raw_log"]["uncompressed"]["sha256"] = "0" * 64
            mutations.append(candidate)
            candidate = copy.deepcopy(expected)
            candidate["exit_status"] = True
            mutations.append(candidate)
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    with self.assertRaisesRegex(
                        verify.CurrentAuditError,
                        "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_REPRODUCTION_INVALID",
                    ):
                        verify._validate_framework_recovery_2_parent_reproduction(
                            Path("."),
                            repair_commit,
                            qualification_commit,
                            mutation,
                            plan=plan,
                            evidence_record=evidence_record,
                        )

    def test_framework_recovery_2_reproduction_log_is_exact(self) -> None:
        verify = _load_verify()
        transcript = (
            b".\n"
            b"----------------------------------------------------------------------\n"
            b"Ran 1 test in 0.123s\n\n"
            b"OK\n"
            + verify._framework_recovery_2_parent_reproduction_log()
        )
        verify._framework_recovery_2_verify_parent_reproduction_log(transcript)
        mutations = (
            b"prefix\n" + transcript,
            transcript + b"suffix\n",
            transcript.replace(b"\nOK\n", b"\nOK\nUNATTESTED\n", 1),
            transcript.replace(b"Ran 1 test", b"Ran 2 tests", 1),
            transcript.replace(b"result=DEFECT_REPRODUCED", b"result=PASS", 1),
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_REPRODUCTION_LOG",
                ),
            ):
                verify._framework_recovery_2_verify_parent_reproduction_log(
                    mutation
                )

    def test_framework_recovery_2_local_validation_binding_is_exact(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        evidence_record = {
            "files": [
                {"path": "local.json"},
                {"path": "local.log.gz", "sha256": "1" * 64},
            ],
            "uncompressed": [
                None,
                {"sha256": "2" * 64, "bytes": 10, "lines": 1},
            ],
        }
        command_times = [
            ("2026-07-23T00:00:01Z", "2026-07-23T00:00:02Z"),
            ("2026-07-23T00:00:03Z", "2026-07-23T00:00:04Z"),
            ("2026-07-23T00:00:05Z", "2026-07-23T00:00:06Z"),
        ]
        platform = {"operating_system": "Linux", "architecture": "x86_64"}
        versions = {
            "cargo": "cargo 1",
            "docker": "Docker 1",
            "git": "git 1",
            "python": "Python 3",
            "rustc": "rustc 1",
        }
        with mock.patch.object(
            verify, "_commit_metadata", return_value={"tree": "c" * 40}
        ):
            value = verify._framework_recovery_2_expected_local_validation(
                Path("."),
                repair_commit,
                qualification_commit,
                started_at_utc="2026-07-23T00:00:00Z",
                completed_at_utc="2026-07-23T00:00:07Z",
                platform=platform,
                tool_versions=versions,
                command_times=command_times,
                evidence_record=evidence_record,
            )
            with mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[
                    verify._parse_utc("2026-07-22T23:59:59Z", "repair"),
                    verify._parse_utc("2026-07-23T00:00:08Z", "qualification"),
                ],
            ):
                verify._validate_framework_recovery_2_local_document(
                    Path("."),
                    qualification_commit,
                    repair_commit,
                    value,
                    evidence_record=evidence_record,
                )
            mutated = copy.deepcopy(value)
            mutated["commands"][1]["argv"].append("--unrecorded")
            with (
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=[
                        verify._parse_utc(
                            "2026-07-22T23:59:59Z", "repair"
                        ),
                        verify._parse_utc(
                            "2026-07-23T00:00:08Z", "qualification"
                        ),
                    ],
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_LOCAL_COMMANDS",
                ),
            ):
                verify._validate_framework_recovery_2_local_document(
                    Path("."),
                    qualification_commit,
                    repair_commit,
                    mutated,
                    evidence_record=evidence_record,
                )
            out_of_order = copy.deepcopy(value)
            out_of_order["commands"][1]["started_at_utc"] = (
                "2026-07-23T00:00:00Z"
            )
            out_of_order["commands"][1]["completed_at_utc"] = (
                "2026-07-23T00:00:01Z"
            )
            with (
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=[
                        verify._parse_utc(
                            "2026-07-22T23:59:59Z", "repair"
                        ),
                        verify._parse_utc(
                            "2026-07-23T00:00:08Z", "qualification"
                        ),
                    ],
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_LOCAL_COMMANDS",
                ),
            ):
                verify._validate_framework_recovery_2_local_document(
                    Path("."),
                    qualification_commit,
                    repair_commit,
                    out_of_order,
                    evidence_record=evidence_record,
                )

    def test_framework_recovery_2_local_log_order_and_commands_are_exact(
        self,
    ) -> None:
        verify = _load_verify()
        fr_count = len(verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS)
        suite = (
            b"Ran 163 tests in 1.000s\nOK\n"
            + f"Ran {fr_count} tests in 2.000s\n".encode("ascii")
            + b"OK\nRan 26 tests in 3.000s\nOK\n"
            + b"verify-current-audit: OK\n"
        )
        first = (
            b"=== CURRENT_AUDIT_GATE ===\n"
            b"$ tools/release/current-audit-gate.sh\n"
            + suite
        )
        second = (
            b"=== P0R_EXIT_GATE ===\n"
            b"$ tools/p0r-exit-gate.sh\n"
            + suite
            + b"Ran 26 tests in 4.000s\nOK\n"
            + (b"OK\n" * 5)
            + b"P0-R exit gate: 30 passed, 0 failed\n"
        )
        third = (
            b"=== RESOURCE_PROFILE ===\n"
            b"$ python3 -I tools/release/current-audit-resource-profile.py\n"
            b'{\n  "overall_pass": true\n}\n'
        )
        clean = first + second + third

        def validate(candidate):
            with mock.patch.object(
                verify,
                "_framework_recovery_2_validate_local_resource_profile",
            ) as resource_validator:
                verify._framework_recovery_2_verify_local_log(
                    Path("."),
                    "a" * 40,
                    candidate,
                    fr_0002_count=fr_count,
                    resource_started_at_utc="2026-07-23T00:00:00Z",
                    resource_completed_at_utc="2026-07-23T00:00:02Z",
                )
            resource_validator.assert_called_once()

        validate(clean)
        mutations = (
            second + first + third,
            clean.replace(
                b"$ tools/p0r-exit-gate.sh",
                b"$ tools/p0r-exit-gate.sh --unrecorded",
                1,
            ),
            clean + b"=== CURRENT_AUDIT_GATE ===\n"
            b"$ tools/release/current-audit-gate.sh\n",
            clean + b"\nERROR\n",
            clean + b"\nCLEANUP=STOP_TIMEOUT\n",
            clean.replace(b"Ran 26 tests in 3.000s\n", b"", 1),
            clean.replace(
                b"$ tools/release/current-audit-gate.sh\n",
                b"$ tools/release/current-audit-gate.sh\n$ echo injected\n",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_LOCAL_LOG",
                ),
            ):
                validate(mutation)

    def test_framework_recovery_2_local_resource_profile_is_fully_validated(
        self,
    ) -> None:
        verify = _load_verify()
        limits = {
            name: getattr(verify, name)
            for name in (
                "MAX_JSON_BYTES",
                "MAX_JSON_STRING_BYTES",
                "MAX_REQUIREMENTS_BYTES",
                "MAX_COMPRESSED_LOG_BYTES",
                "MAX_LOG_BYTES",
                "MAX_GIT_BYTES",
                "MAX_HYGIENE_TOTAL_BYTES",
                "MAX_REVOCATION_CAUSE_FILE_BYTES",
                "MAX_REVOCATION_CAUSE_TOTAL_BYTES",
                "MAX_PROTOCOL_PATH_BYTES",
                "MAX_VERIFIER_OUTPUT_BYTES",
                "MAX_ZIP_ENTRY_BYTES",
                "MAX_ZIP_TOTAL_BYTES",
            )
        }
        structure = {
            name: getattr(verify, name)
            for name in (
                "MAX_JSON_DEPTH",
                "MAX_JSON_NODES",
                "MAX_JSON_CONTAINER_ENTRIES",
            )
        }
        profile = {
            "generated_at_utc": "2026-07-23T00:00:01Z",
            "overall_pass": True,
            "cases": [{} for _index in range(34)],
            "configuration": {
                "samples_per_case": 3,
                "limits_bytes": limits,
                "json_structure_limits": structure,
            },
        }
        profiler = mock.Mock()
        with (
            mock.patch.object(
                verify,
                "_git_file",
                side_effect=[b"profiler source", b"verifier source"],
            ),
            mock.patch.object(
                verify, "_load_exact_module", return_value=profiler
            ),
        ):
            verify._framework_recovery_2_validate_local_resource_profile(
                Path("."),
                "a" * 40,
                profile,
                generated_not_before=verify._parse_utc(
                    "2026-07-23T00:00:00Z", "before"
                ),
                generated_not_after=verify._parse_utc(
                    "2026-07-23T00:00:02Z", "after"
                ),
            )
        profiler.validate_profile.assert_called_once_with(
            profile, verifier_payload=b"verifier source"
        )
        mutations = []
        candidate = copy.deepcopy(profile)
        candidate["overall_pass"] = False
        mutations.append(candidate)
        candidate = copy.deepcopy(profile)
        candidate["cases"].pop()
        mutations.append(candidate)
        candidate = copy.deepcopy(profile)
        candidate["configuration"]["samples_per_case"] = 2
        mutations.append(candidate)
        candidate = copy.deepcopy(profile)
        candidate["configuration"]["limits_bytes"]["MAX_GIT_BYTES"] += 1
        mutations.append(candidate)
        candidate = copy.deepcopy(profile)
        candidate["configuration"]["json_structure_limits"][
            "MAX_JSON_DEPTH"
        ] += 1
        mutations.append(candidate)
        candidate = copy.deepcopy(profile)
        candidate["generated_at_utc"] = "2026-07-22T23:59:59Z"
        mutations.append(candidate)
        for index, candidate in enumerate(mutations):
            with (
                self.subTest(index=index),
                mock.patch.object(
                    verify,
                    "_git_file",
                    side_effect=[b"profiler source", b"verifier source"],
                ),
                mock.patch.object(
                    verify, "_load_exact_module", return_value=mock.Mock()
                ),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_RESOURCE_PROFILE",
                ),
            ):
                verify._framework_recovery_2_validate_local_resource_profile(
                    Path("."),
                    "a" * 40,
                    candidate,
                    generated_not_before=verify._parse_utc(
                        "2026-07-23T00:00:00Z", "before"
                    ),
                    generated_not_after=verify._parse_utc(
                        "2026-07-23T00:00:02Z", "after"
                    ),
                )

    def test_framework_recovery_2_review_false_provenance_is_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        contracts = verify._framework_recovery_2_review_contracts()
        plan = {
            "code_diff": {"patch_sha256": "1" * 64},
            "source_retention": {"preserved": True},
            "transition_identity": verify._framework_recovery_2_transition_identity(),
            "test_contract": {
                "required_regression_test_ids": sorted(
                    verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS
                )
            },
        }
        narratives = {
            finding_id: {
                "summary": f"Finding {finding_id}.",
                "disposition": f"Resolved {finding_id}.",
            }
            for finding_id in contracts["FR-0002-R01"]
        }
        review = verify._framework_recovery_2_expected_review(
            review_id="FR-0002-R01",
            kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
            repair_commit="a" * 40,
            plan=plan,
            narratives=narratives,
        )
        review["detached_signature"] = {}
        mutations = []
        candidate = copy.deepcopy(review)
        candidate["reviewer"]["human_review_performed"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(review)
        candidate["reviewer"]["provider"] = "unretained-provider"
        mutations.append(candidate)
        candidate = copy.deepcopy(review)
        candidate["final_verdict"] = "GO"
        mutations.append(candidate)
        candidate = copy.deepcopy(review)
        candidate["findings"][0]["severity"] = "NON_BLOCKING"
        mutations.append(candidate)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(verify.CurrentAuditError):
                    verify._validate_framework_recovery_2_review(
                        Path("."),
                        mutation,
                        review_id="FR-0002-R01",
                        kind="INTERNAL_AUTOMATED_DESIGN_REVIEW",
                        repair_commit="a" * 40,
                        plan=plan,
                    )

    def test_framework_recovery_2_review_key_reuse_is_rejected(self) -> None:
        verify = _load_verify()
        source = {"key_fingerprint": "SHA256:source", "public_key": "source"}
        independent = [
            {"key_fingerprint": "SHA256:review-1", "public_key": "review-1"},
            {"key_fingerprint": "SHA256:review-2", "public_key": "review-2"},
        ]
        verify._framework_recovery_2_verify_review_key_separation(
            source, independent
        )
        mutations = (
            [independent[0], copy.deepcopy(independent[0])],
            [
                independent[0],
                {
                    "key_fingerprint": source["key_fingerprint"],
                    "public_key": "other",
                },
            ],
            independent[:1],
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_REVIEW_KEY_SEPARATION",
                ):
                    verify._framework_recovery_2_verify_review_key_separation(
                        source, mutation
                    )

    def test_framework_recovery_2_added_file_old_record_is_null(self) -> None:
        verify = _load_verify()

        def record(_repo, _commit, path):
            return {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "oid": hashlib.sha1(path.encode()).hexdigest(),
                "sha256": hashlib.sha256(path.encode()).hexdigest(),
                "bytes": len(path),
                "lines": 1,
            }

        with (
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=record
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_code_diff",
                return_value={"target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN"},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_test_contract",
                return_value={"fr_0002_count": 1},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_source_retention_manifest",
                return_value={"byte_exact": True},
            ),
        ):
            plan = verify._framework_recovery_2_expected_plan(
                Path("."), "a" * 40, "b" * 40
            )
        records = {
            item["new"]["path"]: item for item in plan["changed_core_files"]
        }
        self.assertIsNone(
            records[verify.FRAMEWORK_RECOVERY_2_TEST_PATH]["old"]
        )
        self.assertEqual(
            records[verify.FRAMEWORK_RECOVERY_2_TEST_PATH]["status"], "A"
        )
        self.assertIsNotNone(
            records["tools/release/verify-current-audit.py"]["old"]
        )

    def test_framework_recovery_2_plan_excludes_self_commit(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40

        def record(_repo, _commit, path):
            return {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "oid": hashlib.sha1(path.encode()).hexdigest(),
                "sha256": hashlib.sha256(path.encode()).hexdigest(),
                "bytes": len(path),
                "lines": 1,
            }

        with (
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=record
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_code_diff",
                return_value={"target": "SIGNED_COMMIT_CONTAINING_THIS_PLAN"},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_test_contract",
                return_value={"fr_0002_count": 1},
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_source_retention_manifest",
                return_value={"byte_exact": True},
            ),
        ):
            plan = verify._framework_recovery_2_expected_plan(
                Path("."), repair_commit, "b" * 40
            )
        self.assertNotIn(
            repair_commit, verify._canonical_json_bytes(plan).decode("utf-8")
        )
        self.assertEqual(
            plan["code_diff"]["target"], "SIGNED_COMMIT_CONTAINING_THIS_PLAN"
        )
        self.assertIsNone(plan["persistent_identifier"])
        self.assertEqual(plan["framework_epoch"], {"prior": 2, "next": 3})

    def test_framework_recovery_2_exact_repair_verifies(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        expected = {
            "schema_version": "1.0.0",
            "assurance_boundary": {
                "historical_protocol_execution_revalidated_under_epoch_3": True
            },
        }
        plan = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-23T00:00:01Z",
            "detached_signature": {"signature": "test"},
        }
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_2_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_2_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        signer = {
            "principal": "release",
            "public_key": "ssh-ed25519 test",
            "key_fingerprint": "SHA256:test",
        }
        attestation = mock.Mock()
        with (
            mock.patch.object(verify, "_commit_metadata", return_value=metadata),
            mock.patch.object(verify, "_verify_named_commit_signature"),
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value=dict(
                    sorted(verify.FRAMEWORK_RECOVERY_2_REPAIR_STATUSES.items())
                ),
            ),
            mock.patch.object(
                verify,
                "_git_tree_entry",
                side_effect=lambda _repo, _commit, path: {
                    "mode": "100755" if path.endswith(".sh") else "100644",
                    "type": "blob",
                    "oid": "same",
                },
            ),
            mock.patch.object(
                verify,
                "_read_commit_json",
                return_value=(
                    plan,
                    verify._canonical_json_bytes(plan, pretty=True),
                ),
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_expected_plan",
                return_value=expected,
            ),
            mock.patch.object(
                verify,
                "_commit_datetime",
                side_effect=[
                    verify._parse_utc("2026-07-23T00:00:00Z", "parent"),
                    verify._parse_utc("2026-07-23T00:00:02Z", "repair"),
                ],
            ),
            mock.patch.object(
                verify, "_source_release_signer", return_value=signer
            ),
            mock.patch.object(
                verify, "_verify_ssh_detached_attestation", attestation
            ),
        ):
            observed = verify._verify_framework_recovery_2_repair(
                Path("."), repair_commit, framework_commit="b" * 40
            )
        self.assertEqual(observed, plan)
        self.assertEqual(
            attestation.call_args.kwargs["namespace"],
            "haldir-framework-recovery-fr-0002-v1",
        )
        self.assertEqual(
            attestation.call_args.kwargs["expected_fingerprint"],
            signer["key_fingerprint"],
        )

    def test_framework_recovery_2_plan_field_mutations_are_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        expected = {
            "schema_version": "1.0.0",
            "assurance_boundary": {
                "historical_protocol_execution_revalidated_under_epoch_3": True
            },
        }
        base = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-23T00:00:01Z",
            "detached_signature": {},
        }
        metadata = {
            "parent": verify.FRAMEWORK_RECOVERY_2_PARENT,
            "subject": verify.FRAMEWORK_RECOVERY_2_SUBJECT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
        }
        mutations = []
        candidate = copy.deepcopy(base)
        candidate["unexpected"] = True
        mutations.append(candidate)
        candidate = copy.deepcopy(base)
        candidate["assurance_boundary"][
            "historical_protocol_execution_revalidated_under_epoch_3"
        ] = False
        mutations.append(candidate)
        candidate = copy.deepcopy(base)
        candidate["created_at_utc"] = "2026-07-23T00:00:03Z"
        mutations.append(candidate)
        for index, candidate in enumerate(mutations):
            with (
                self.subTest(index=index),
                mock.patch.object(
                    verify, "_commit_metadata", return_value=metadata
                ),
                mock.patch.object(verify, "_verify_named_commit_signature"),
                mock.patch.object(
                    verify,
                    "_changed_path_statuses",
                    return_value=dict(
                        sorted(
                            verify.FRAMEWORK_RECOVERY_2_REPAIR_STATUSES.items()
                        )
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_git_tree_entry",
                    side_effect=lambda _repo, _commit, path: {
                        "mode": "100755" if path.endswith(".sh") else "100644",
                        "type": "blob",
                        "oid": "same",
                    },
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        candidate,
                        verify._canonical_json_bytes(candidate, pretty=True),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_expected_plan",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=[
                        verify._parse_utc(
                            "2026-07-23T00:00:00Z", "parent"
                        ),
                        verify._parse_utc(
                            "2026-07-23T00:00:02Z", "repair"
                        ),
                    ],
                ),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._verify_framework_recovery_2_repair(
                    Path("."), "a" * 40, framework_commit="b" * 40
                )

    def test_framework_recovery_2_signature_namespace_is_purpose_separated(
        self,
    ) -> None:
        source = Path(__file__).with_name("verify-current-audit.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        expected = {
            "_verify_framework_recovery_2_repair": (
                "haldir-framework-recovery-fr-0002-v1"
            ),
            "_verify_framework_recovery_2_qualification": (
                "haldir-framework-recovery-fr-0002-qualification-v1"
            ),
            "_verify_framework_recovery_2_activation": (
                "haldir-framework-recovery-fr-0002-activation-v1"
            ),
            "_validate_framework_recovery_2_review": (
                "haldir-framework-recovery-fr-0002-local-integrity-v1"
            ),
        }
        observed = {}
        for name, namespace in expected.items():
            calls = [
                node
                for node in ast.walk(functions[name])
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_verify_ssh_detached_attestation"
            ]
            self.assertEqual(len(calls), 1)
            keyword = next(
                item for item in calls[0].keywords if item.arg == "namespace"
            )
            observed[name] = ast.literal_eval(keyword.value)
            self.assertEqual(observed[name], namespace)
        self.assertEqual(len(set(observed.values())), len(observed))

    def test_framework_recovery_2_source_retention_contract(self) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        parent = verify._git_file(root, PARENT_COMMIT, path)
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()

        def git_file(_repo, commit, selected_path):
            self.assertEqual(selected_path, path)
            return parent if commit == PARENT_COMMIT else target

        with mock.patch.object(verify, "_git_file", side_effect=git_file):
            manifest = verify._framework_recovery_2_source_retention_manifest(
                root, "a" * 40
            )
        self.assertTrue(manifest["protected_residual"]["byte_exact"])
        self.assertEqual(
            manifest["protected_residual"]["parent"]["sha256"],
            manifest["protected_residual"]["target"]["sha256"],
        )
        self.assertEqual(
            set(manifest["allowed_changes"]["modified_definitions"]),
            {
                "_run_bounded",
                "_stop_bounded_process",
                "_verify_forward_protocol_history",
                "_verify_framework_history",
                "_verify_post_activation_gate_retention",
            },
        )
        self.assertEqual(
            manifest["allowed_changes"]["removed_definitions"],
            ["_process_group_exists"],
        )
        self.assertGreater(manifest["preserved_counts"]["definitions"], 190)

    def test_framework_recovery_2_source_retention_mutations_are_rejected(
        self,
    ) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        path = "tools/release/verify-current-audit.py"
        parent = verify._git_file(root, PARENT_COMMIT, path)
        target = Path(__file__).with_name("verify-current-audit.py").read_bytes()
        mutations = (
            target.replace(
                b"def _sha256(payload: bytes) -> str:\n",
                b"def _sha256(payload: bytes) -> str:\n    # preserved drift\n",
                1,
            ),
            target.replace(
                b"\ndef _framework_recovery_2_source_index(",
                b"\n# interstitial drift\n"
                b"def _framework_recovery_2_source_index(",
                1,
            ),
            target.replace(
                b'if __name__ == "__main__":\n',
                b"# main-guard drift\nif __name__ == \"__main__\":\n",
                1,
            ),
            target.replace(
                b"MAX_JSON_BYTES = 256 * 1024\n",
                b"MAX_JSON_BYTES = 128 * 1024\n",
                1,
            ),
            target.replace(
                b"import selectors\n",
                b"import selectors\nimport socket\n",
                1,
            ),
            target.replace(
                b"\ndef _framework_recovery_2_source_index(",
                b"\ndef unauthorized_helper():\n"
                b"    return None\n\n"
                b"def _framework_recovery_2_source_index(",
                1,
            ),
        )
        self.assertTrue(all(candidate != target for candidate in mutations))
        for index, mutation in enumerate(mutations):
            def git_file(_repo, commit, selected_path):
                self.assertEqual(selected_path, path)
                return parent if commit == PARENT_COMMIT else mutation

            with (
                self.subTest(index=index),
                mock.patch.object(verify, "_git_file", side_effect=git_file),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_2_source_retention_manifest(
                    root, "a" * 40
                )

    def test_framework_recovery_2_old_test_suite_is_preserved(self) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        legacy_path = "tools/release/test_verify_current_audit.py"
        parent_legacy = verify._git_file(root, PARENT_COMMIT, legacy_path)
        new_tests = Path(__file__).read_bytes()
        gate = Path(__file__).with_name("current-audit-gate.sh").read_bytes()

        def git_file(_repo, commit, path):
            if path == legacy_path:
                return parent_legacy
            if path == verify.FRAMEWORK_RECOVERY_2_TEST_PATH:
                return new_tests
            if path == "tools/release/current-audit-gate.sh":
                return gate
            self.fail(f"unexpected path {commit}:{path}")

        def record(_repo, commit, path):
            payload = git_file(_repo, commit, path)
            return {
                "path": path,
                "mode": "100755" if path.endswith(".sh") else "100644",
                "type": "blob",
                "oid": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "lines": len(payload.splitlines()),
            }

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=record
            ),
        ):
            contract = verify._framework_recovery_2_test_contract(
                root, "a" * 40
            )
        self.assertEqual(contract["legacy_count"], 163)
        self.assertTrue(contract["legacy_test_bytes_preserved"])
        self.assertEqual(
            contract["fr_0002_count"],
            len(verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS),
        )
        self.assertEqual(
            set(contract["required_regression_test_ids"]),
            verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS,
        )

    def test_framework_recovery_2_test_contract_rejects_legacy_mutation(
        self,
    ) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        legacy_path = "tools/release/test_verify_current_audit.py"
        parent_legacy = verify._git_file(root, PARENT_COMMIT, legacy_path)

        def git_file(_repo, commit, path):
            if path == legacy_path:
                if commit == PARENT_COMMIT:
                    return parent_legacy
                return parent_legacy + b"\n# drift\n"
            self.fail(f"unexpected path {commit}:{path}")

        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_LEGACY_TEST_DRIFT",
            ),
        ):
            verify._framework_recovery_2_test_contract(root, "a" * 40)

    def test_framework_recovery_2_test_contract_rejects_skip_and_loader_bypasses(
        self,
    ) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        legacy_path = "tools/release/test_verify_current_audit.py"
        parent_legacy = verify._git_file(root, PARENT_COMMIT, legacy_path)
        payload = Path(__file__).read_bytes()
        gate = Path(__file__).with_name("current-audit-gate.sh").read_bytes()
        mutations = (
            payload.replace(
                b"    def test_bounded_runner_clean_success_is_exact",
                b"    @unittest.skip('disabled')\n"
                b"    def test_bounded_runner_clean_success_is_exact",
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b"def load_tests(loader, tests, pattern):\n"
                b"    return tests\n\n"
                b'if __name__ == "__main__":',
                1,
            ),
        )
        self.assertTrue(all(candidate != payload for candidate in mutations))
        for index, candidate in enumerate(mutations):
            def git_file(_repo, _commit, path):
                if path == legacy_path:
                    return parent_legacy
                if path == verify.FRAMEWORK_RECOVERY_2_TEST_PATH:
                    return candidate
                if path == "tools/release/current-audit-gate.sh":
                    return gate
                self.fail(f"unexpected path {path}")

            with (
                self.subTest(index=index),
                mock.patch.object(verify, "_git_file", side_effect=git_file),
                self.assertRaises(verify.CurrentAuditError),
            ):
                verify._framework_recovery_2_test_contract(root, "a" * 40)

        candidate = payload.replace(
            b"#!/usr/bin/env python3",
            b"#!/usr/bin/env python4",
            1,
        )

        def git_file(_repo, _commit, path):
            if path == legacy_path:
                return parent_legacy
            if path == verify.FRAMEWORK_RECOVERY_2_TEST_PATH:
                return candidate
            if path == "tools/release/current-audit-gate.sh":
                return gate
            self.fail(f"unexpected path {path}")

        self.assertEqual(len(candidate), len(payload))
        self.assertNotEqual(
            hashlib.sha256(candidate).digest(),
            hashlib.sha256(payload).digest(),
        )
        with (
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_TEST_BYTES_INVALID",
            ),
        ):
            verify._framework_recovery_2_test_contract(root, "a" * 40)

    def test_framework_recovery_2_wrapper_is_epoch_aware(self) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        original_git_file = verify._git_file
        verify._verify_post_activation_gate_retention(
            root,
            PARENT_COMMIT,
            framework_epoch=2,
            compare_worktree=False,
        )

        def epoch_3_file(repo, commit, path):
            if path == "tools/release/current-audit-gate.sh":
                return verify._framework_recovery_2_expected_gate_payload()
            return original_git_file(repo, commit, path)

        with mock.patch.object(
            verify, "_git_file", side_effect=epoch_3_file
        ):
            verify._verify_post_activation_gate_retention(
                root,
                PARENT_COMMIT,
                framework_epoch=3,
                compare_worktree=False,
            )
            verify._verify_post_activation_gate_retention(
                root,
                PARENT_COMMIT,
                compare_worktree=False,
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_POST_ACTIVATION_EPOCH_INVALID",
        ):
            verify._verify_post_activation_gate_retention(
                root,
                PARENT_COMMIT,
                framework_epoch=True,
                compare_worktree=False,
            )

    def test_framework_recovery_2_historical_replay_ignores_live_wrapper(
        self,
    ) -> None:
        verify = _load_verify()
        root = Path(__file__).resolve().parents[2]
        with mock.patch.object(
            verify,
            "_read_repo_relative_bounded",
            side_effect=AssertionError("historical replay read the worktree"),
        ) as reader:
            verify._verify_post_activation_gate_retention(
                root,
                PARENT_COMMIT,
                framework_epoch=2,
                compare_worktree=False,
            )
        reader.assert_not_called()
        with (
            mock.patch.object(
                verify,
                "_read_repo_relative_bounded",
                return_value=b"mutated live worktree",
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_POST_ACTIVATION_GATE_FILE_DRIFT",
            ),
        ):
            verify._verify_post_activation_gate_retention(
                root,
                PARENT_COMMIT,
                framework_epoch=2,
                compare_worktree=True,
            )

    def test_framework_recovery_2_preserved_paths_reject_mutation(self) -> None:
        verify = _load_verify()
        transition = {
            "parent": "a" * 40,
            "required_verified_prefix": 3,
            "statuses": {"plan": "A"},
            "preserved_paths": ["first", "second"],
            "preserved_parent": "b" * 40,
        }

        def same_entry(_repo, _commit, path):
            return {"oid": hashlib.sha1(path.encode()).hexdigest()}

        with mock.patch.object(
            verify, "_git_tree_entry", side_effect=same_entry
        ):
            verify._verify_framework_recovery_transition(
                Path("."),
                "c" * 40,
                "a" * 40,
                {"plan": "A"},
                transition=transition,
                verified_prefix=3,
                inflight=None,
            )

        def changed_entry(_repo, commit, path):
            return {"oid": hashlib.sha1(f"{commit}:{path}".encode()).hexdigest()}

        with (
            mock.patch.object(
                verify, "_git_tree_entry", side_effect=changed_entry
            ),
            self.assertRaisesRegex(
                verify.CurrentAuditError,
                "CURRENT_AUDIT_FRAMEWORK_RECOVERY_STATE_DRIFT",
            ),
        ):
            verify._verify_framework_recovery_transition(
                Path("."),
                "c" * 40,
                "a" * 40,
                {"plan": "A"},
                transition=transition,
                verified_prefix=3,
                inflight=None,
            )

    def test_framework_recovery_2_sequence_requires_verified_prefix_three(
        self,
    ) -> None:
        verify = _load_verify()
        transition = {
            "parent": "a" * 40,
            "required_verified_prefix": 3,
            "statuses": {"plan": "A"},
            "preserved_paths": [],
            "preserved_parent": "b" * 40,
        }
        verify._verify_framework_recovery_transition(
            Path("."),
            "c" * 40,
            "a" * 40,
            {"plan": "A"},
            transition=transition,
            verified_prefix=3,
            inflight=None,
        )
        mutations = (
            {"verified_prefix": 2, "inflight": None},
            {"verified_prefix": 3, "inflight": {"stage": "F"}},
        )
        for index, mutation in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    verify.CurrentAuditError,
                    "CURRENT_AUDIT_FRAMEWORK_RECOVERY_SEQUENCE",
                ),
            ):
                verify._verify_framework_recovery_transition(
                    Path("."),
                    "c" * 40,
                    "a" * 40,
                    {"plan": "A"},
                    transition=transition,
                    **mutation,
                )

    def test_framework_recovery_2_history_requires_contiguous_stages(
        self,
    ) -> None:
        verify = _load_verify()
        chain = [f"{index + 1:040x}" for index in range(22)]
        chain[10] = "dde6512d615f54fac26b2728a05b9c53dca68666"
        chain[11] = verify.FRAMEWORK_RECOVERY_2_PRIOR_QUALIFICATION
        chain[12] = verify.FRAMEWORK_RECOVERY_2_PRIOR_ACTIVATION
        chain[21] = verify.FRAMEWORK_RECOVERY_2_PARENT
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        activation_commit = "c" * 40
        plan = {"plan": True}
        qualification = {"qualification": True}

        def qualify(_repo, _repair, candidate, *, plan):
            if candidate != qualification_commit:
                raise verify.CurrentAuditError("not the qualification")
            self.assertEqual(plan, {"plan": True})
            return qualification

        def activate(
            _repo,
            _repair,
            candidate_qualification,
            candidate_activation,
            *,
            qualification,
        ):
            if (
                candidate_qualification != qualification_commit
                or candidate_activation != activation_commit
                or qualification != {"qualification": True}
            ):
                raise verify.CurrentAuditError("not the activation")
            return {"activation": True}

        with (
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_repair",
                return_value=plan,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_qualification",
                side_effect=qualify,
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_activation",
                side_effect=activate,
            ),
        ):
            pending = verify._verify_framework_recovery_2_history(
                Path("."), [*chain, repair_commit], framework_commit="d" * 40
            )
            qualified = verify._verify_framework_recovery_2_history(
                Path("."),
                [*chain, repair_commit, qualification_commit],
                framework_commit="d" * 40,
            )
            active = verify._verify_framework_recovery_2_history(
                Path("."),
                [
                    *chain,
                    repair_commit,
                    qualification_commit,
                    activation_commit,
                ],
                framework_commit="d" * 40,
            )
            with self.assertRaises(verify.CurrentAuditError):
                verify._verify_framework_recovery_2_history(
                    Path("."),
                    [*chain, repair_commit, "e" * 40, qualification_commit],
                    framework_commit="d" * 40,
                )
        self.assertEqual(pending["state"], "PENDING_QUALIFICATION")
        self.assertEqual(qualified["state"], "QUALIFIED_PENDING_ACTIVATION")
        self.assertEqual(active["state"], "ACTIVE")
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_POSITION",
        ):
            verify._verify_framework_recovery_2_history(
                Path("."),
                [*chain[:20], verify.FRAMEWORK_RECOVERY_2_PARENT, repair_commit],
                framework_commit="d" * 40,
            )

    def test_framework_recovery_2_qualification_validator_is_exact(
        self,
    ) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        plan = {
            "test_contract": {
                "fr_0002_count": len(
                    verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS
                )
            }
        }
        hosted = {}
        for lane, workflow, requirement in (
            (
                "repair_ci",
                "ci",
                verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS[1],
            ),
            (
                "repair_formal",
                "formal",
                verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS[2],
            ),
        ):
            hosted[lane] = {
                "capture_schema": verify.FRAMEWORK_RECOVERY_2_CAPTURE_SCHEMA,
                "workflow": workflow,
                "subject_commit": repair_commit,
                "files": [{"path": path} for path in requirement["paths"]],
                "log_integrity": {"path": requirement["paths"][2]},
                "capture_operations": {
                    "raw_log": {
                        "completed_at_utc": "2026-07-23T00:00:06Z"
                    }
                },
            }
        expected = {"hosted_evidence": hosted, "qualified": True}
        base = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-23T00:00:07Z",
            "detached_signature": {"signature": "qualification"},
        }
        documents = {
            "FR-0002-E01": {
                "completed_at_utc": "2026-07-23T00:00:04Z"
            },
            "FR-0002-E04": {
                "completed_at_utc": "2026-07-23T00:00:05Z",
                "commands": [
                    {},
                    {},
                    {
                        "started_at_utc": "2026-07-23T00:00:04Z",
                        "completed_at_utc": "2026-07-23T00:00:05Z",
                    },
                ],
            },
            "FR-0002-R01": {},
            "FR-0002-R02": {},
        }
        reproduction_log = (
            b".\n"
            b"----------------------------------------------------------------------\n"
            b"Ran 1 test in 0.001s\n\n"
            b"OK\n"
            + verify._framework_recovery_2_parent_reproduction_log()
        )

        def catalog(_repo, _commit, requirement, **_kwargs):
            requirement_id = requirement["id"]
            record = {
                "id": requirement_id,
                "files": [
                    {"path": path, "sha256": "1" * 64}
                    for path in requirement["paths"]
                ],
                "uncompressed": [
                    (
                        {"sha256": "2" * 64, "bytes": 1, "lines": 1}
                        if path.endswith(".log.gz")
                        else None
                    )
                    for path in requirement["paths"]
                ],
            }
            if requirement_id in documents:
                first = verify._canonical_json_bytes(
                    documents[requirement_id], pretty=True
                )
            else:
                first = b"{}\n"
            payloads = [first]
            for path in requirement["paths"][1:]:
                payloads.append(
                    reproduction_log
                    if requirement_id == "FR-0002-E01"
                    and path.endswith(".log.gz")
                    else b"retained payload\n"
                )
            return record, payloads

        metadata_paths = {}
        for index, requirement in enumerate(
            verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_REQUIREMENTS[1:3],
            start=1,
        ):
            metadata_paths[requirement["paths"][0]] = (
                verify._canonical_json_bytes({"databaseId": 100 + index})
            )
            metadata_paths[requirement["paths"][1]] = (
                verify._canonical_json_bytes(
                    {"updatedAt": "2026-07-23T00:00:03Z"}
                )
            )

        def run(
            candidate,
            *,
            statuses=None,
            wrong_mode_path=None,
            commit_signature_error=False,
            detached_signature_error=False,
        ):
            selected_statuses = (
                dict(
                    sorted(
                        verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_STATUSES.items()
                    )
                )
                if statuses is None
                else statuses
            )

            def git_file(_repo, _commit, path):
                return metadata_paths.get(path, b"{}\n")

            def tree_entry(_repo, commit, path):
                return {
                    "mode": (
                        "100755"
                        if commit == qualification_commit
                        and path == wrong_mode_path
                        else "100644"
                    ),
                    "type": "blob",
                    "oid": hashlib.sha1(path.encode()).hexdigest(),
                }

            def named_signature(*_args, **_kwargs):
                if commit_signature_error:
                    raise verify.CurrentAuditError("commit signature")

            def detached_signature(*_args, **_kwargs):
                if detached_signature_error:
                    raise verify.CurrentAuditError("detached signature")

            metadata = {
                "parent": repair_commit,
                "subject": verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_SUBJECT,
                "author_name": "Sepehr Mahmoudian",
                "author_email": "sepmhn@gmail.com",
                "committer_name": "Sepehr Mahmoudian",
                "committer_email": "sepmhn@gmail.com",
            }
            signer = {
                "principal": "release",
                "public_key": "source-key",
                "key_fingerprint": "SHA256:source",
            }
            review_keys = [
                {
                    "public_key": "review-key-1",
                    "key_fingerprint": "SHA256:review-1",
                },
                {
                    "public_key": "review-key-2",
                    "key_fingerprint": "SHA256:review-2",
                },
            ]
            with (
                mock.patch.object(
                    verify, "_commit_metadata", return_value=metadata
                ),
                mock.patch.object(
                    verify,
                    "_verify_named_commit_signature",
                    side_effect=named_signature,
                ),
                mock.patch.object(
                    verify,
                    "_changed_path_statuses",
                    return_value=selected_statuses,
                ),
                mock.patch.object(verify, "_git_file", side_effect=git_file),
                mock.patch.object(
                    verify, "_git_tree_entry", side_effect=tree_entry
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        candidate,
                        verify._canonical_json_bytes(candidate, pretty=True),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=catalog,
                ),
                mock.patch.object(
                    verify,
                    "_validate_framework_recovery_2_parent_reproduction",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_hosted_entry",
                    side_effect=lambda *_args, **kwargs: next(
                        value
                        for value in hosted.values()
                        if value["workflow"] == kwargs["workflow"]
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_verify_capture_operations",
                    return_value={},
                ),
                mock.patch.object(verify, "_verify_hosted_evidence_v2"),
                mock.patch.object(
                    verify, "_framework_recovery_2_verify_ci_markers"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_verify_run_attempt_uniqueness",
                ),
                mock.patch.object(
                    verify, "_validate_framework_recovery_2_local_document"
                ),
                mock.patch.object(
                    verify, "_framework_recovery_2_verify_local_log"
                ),
                mock.patch.object(
                    verify,
                    "_validate_framework_recovery_2_review",
                    side_effect=review_keys,
                ),
                mock.patch.object(
                    verify,
                    "_source_release_signer",
                    return_value=signer,
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_expected_qualification",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo, commit: verify._parse_utc(
                        (
                            "2026-07-23T00:00:00Z"
                            if commit == repair_commit
                            else "2026-07-23T00:00:10Z"
                        ),
                        "commit",
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_verify_ssh_detached_attestation",
                    side_effect=detached_signature,
                ),
            ):
                return verify._verify_framework_recovery_2_qualification(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    plan=plan,
                )

        self.assertEqual(run(base), base)
        early = copy.deepcopy(base)
        early["created_at_utc"] = "2026-07-23T00:00:05Z"
        mutations = (
            (early, {}, "QUALIFICATION_CHRONOLOGY"),
            (
                base,
                {
                    **dict(
                        sorted(
                            verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_STATUSES.items()
                        )
                    ),
                    "extra": "A",
                },
                "DATA_ONLY_DIFF_INVALID",
            ),
        )
        for index, (candidate, options, error) in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(verify.CurrentAuditError, error),
            ):
                run(
                    candidate,
                    statuses=options if options else None,
                )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_MODE",
        ):
            run(
                base,
                wrong_mode_path=verify.FRAMEWORK_RECOVERY_2_QUALIFICATION_PATH,
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "commit signature"
        ):
            run(base, commit_signature_error=True)
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "detached signature"
        ):
            run(base, detached_signature_error=True)

    def test_framework_recovery_2_activation_requires_qualification_checks(
        self,
    ) -> None:
        verify = _load_verify()
        qualification = {
            "evidence_catalog": [{"id": "FR-0002-E01"}],
            "hosted_evidence": {
                "repair_ci": {"lane": "repair_ci"},
                "repair_formal": {"lane": "repair_formal"},
            },
            "review_records": [{"review_id": "FR-0002-R01"}],
            "assurance_boundary": {
                "historical_protocol_execution_revalidated_under_epoch_3": True
            },
        }

        def record(_repo, _commit, path):
            return {"path": path}

        identities = {
            "repair_ci": (1, 1),
            "repair_formal": (2, 1),
            "qualification_ci": (3, 1),
            "qualification_formal": (4, 1),
        }

        def identity(_repo, _commit, _entry, *, label):
            return identities[label]

        activation_hosted = {
            "qualification_ci": {"lane": "qualification_ci"},
            "qualification_formal": {"lane": "qualification_formal"},
        }
        with (
            mock.patch.object(
                verify,
                "_signed_commit_binding",
                side_effect=lambda _repo, child, parent: {
                    "commit": child,
                    "parent": parent,
                },
            ),
            mock.patch.object(
                verify, "_commit_regular_file_record", side_effect=record
            ),
            mock.patch.object(
                verify,
                "_framework_recovery_2_run_attempt_identity",
                side_effect=identity,
            ),
        ):
            activation = verify._framework_recovery_2_expected_activation(
                Path("."),
                "a" * 40,
                "b" * 40,
                "c" * 40,
                qualification=qualification,
                activation_evidence_catalog=[{"id": "FR-0002-A01"}],
                hosted_evidence=activation_hosted,
            )
        self.assertEqual(
            activation["qualification_evidence_records"],
            qualification["evidence_catalog"],
        )
        self.assertEqual(
            activation["review_records"], qualification["review_records"]
        )
        self.assertEqual(
            [item["lane"] for item in activation["all_hosted_run_attempts"]],
            [
                "repair_ci",
                "repair_formal",
                "qualification_ci",
                "qualification_formal",
            ],
        )
        self.assertEqual(
            activation["qualified_qualification"],
            {"commit": "b" * 40, "parent": "a" * 40},
        )

    def test_framework_recovery_2_activation_validator_is_exact(self) -> None:
        verify = _load_verify()
        repair_commit = "a" * 40
        qualification_commit = "b" * 40
        activation_commit = "c" * 40
        hosted = {}
        for lane, workflow, requirement in (
            (
                "qualification_ci",
                "ci",
                verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS[0],
            ),
            (
                "qualification_formal",
                "formal",
                verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS[1],
            ),
        ):
            hosted[lane] = {
                "capture_schema": verify.FRAMEWORK_RECOVERY_2_CAPTURE_SCHEMA,
                "workflow": workflow,
                "subject_commit": qualification_commit,
                "files": [{"path": path} for path in requirement["paths"]],
                "log_integrity": {"path": requirement["paths"][2]},
                "capture_operations": {
                    "raw_log": {
                        "completed_at_utc": "2026-07-23T00:00:06Z"
                    }
                },
            }
        expected = {
            "activation_hosted_evidence": hosted,
            "activated": True,
        }
        base = {
            **copy.deepcopy(expected),
            "created_at_utc": "2026-07-23T00:00:07Z",
            "detached_signature": {"signature": "activation"},
        }
        qualification = {
            "test_contract": {
                "fr_0002_count": len(
                    verify.FRAMEWORK_RECOVERY_2_REQUIRED_TEST_IDS
                )
            },
            "hosted_evidence": {
                "repair_ci": {"lane": "repair_ci"},
                "repair_formal": {"lane": "repair_formal"},
            },
        }
        metadata_paths = {}
        for index, requirement in enumerate(
            verify.FRAMEWORK_RECOVERY_2_ACTIVATION_REQUIREMENTS,
            start=1,
        ):
            metadata_paths[requirement["paths"][0]] = (
                verify._canonical_json_bytes({"databaseId": 200 + index})
            )
            metadata_paths[requirement["paths"][1]] = (
                verify._canonical_json_bytes(
                    {"updatedAt": "2026-07-23T00:00:03Z"}
                )
            )

        def catalog(_repo, _commit, requirement, **_kwargs):
            return (
                {
                    "id": requirement["id"],
                    "files": [
                        {"path": path, "sha256": "1" * 64}
                        for path in requirement["paths"]
                    ],
                    "uncompressed": [
                        (
                            {"sha256": "2" * 64, "bytes": 1, "lines": 1}
                            if path.endswith(".log.gz")
                            else None
                        )
                        for path in requirement["paths"]
                    ],
                },
                [b"{}\n", b"{}\n", b"log\n"],
            )

        def run(
            candidate,
            *,
            statuses=None,
            wrong_mode_path=None,
            commit_signature_error=False,
            detached_signature_error=False,
        ):
            selected_statuses = (
                dict(
                    sorted(
                        verify.FRAMEWORK_RECOVERY_2_ACTIVATION_STATUSES.items()
                    )
                )
                if statuses is None
                else statuses
            )

            def git_file(_repo, _commit, path):
                return metadata_paths.get(path, b"{}\n")

            def tree_entry(_repo, commit, path):
                return {
                    "mode": (
                        "100755"
                        if commit == activation_commit
                        and path == wrong_mode_path
                        else "100644"
                    ),
                    "type": "blob",
                    "oid": hashlib.sha1(path.encode()).hexdigest(),
                }

            def named_signature(*_args, **_kwargs):
                if commit_signature_error:
                    raise verify.CurrentAuditError("commit signature")

            def detached_signature(*_args, **_kwargs):
                if detached_signature_error:
                    raise verify.CurrentAuditError("detached signature")

            metadata = {
                "parent": qualification_commit,
                "subject": verify.FRAMEWORK_RECOVERY_2_ACTIVATION_SUBJECT,
                "author_name": "Sepehr Mahmoudian",
                "author_email": "sepmhn@gmail.com",
                "committer_name": "Sepehr Mahmoudian",
                "committer_email": "sepmhn@gmail.com",
            }
            signer = {
                "principal": "release",
                "public_key": "source-key",
                "key_fingerprint": "SHA256:source",
            }
            with (
                mock.patch.object(
                    verify, "_commit_metadata", return_value=metadata
                ),
                mock.patch.object(
                    verify,
                    "_verify_named_commit_signature",
                    side_effect=named_signature,
                ),
                mock.patch.object(
                    verify,
                    "_changed_path_statuses",
                    return_value=selected_statuses,
                ),
                mock.patch.object(verify, "_git_file", side_effect=git_file),
                mock.patch.object(
                    verify, "_git_tree_entry", side_effect=tree_entry
                ),
                mock.patch.object(
                    verify,
                    "_read_commit_json",
                    return_value=(
                        candidate,
                        verify._canonical_json_bytes(candidate, pretty=True),
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_catalog_record",
                    side_effect=catalog,
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_hosted_entry",
                    side_effect=lambda *_args, **kwargs: next(
                        value
                        for value in hosted.values()
                        if value["workflow"] == kwargs["workflow"]
                    ),
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_verify_capture_operations",
                    return_value={},
                ),
                mock.patch.object(verify, "_verify_hosted_evidence_v2"),
                mock.patch.object(
                    verify, "_framework_recovery_2_verify_ci_markers"
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_verify_run_attempt_uniqueness",
                ),
                mock.patch.object(
                    verify,
                    "_framework_recovery_2_expected_activation",
                    return_value=expected,
                ),
                mock.patch.object(
                    verify,
                    "_commit_datetime",
                    side_effect=lambda _repo, commit: verify._parse_utc(
                        (
                            "2026-07-23T00:00:00Z"
                            if commit == qualification_commit
                            else "2026-07-23T00:00:10Z"
                        ),
                        "commit",
                    ),
                ),
                mock.patch.object(
                    verify, "_source_release_signer", return_value=signer
                ),
                mock.patch.object(
                    verify,
                    "_verify_ssh_detached_attestation",
                    side_effect=detached_signature,
                ),
            ):
                return verify._verify_framework_recovery_2_activation(
                    Path("."),
                    repair_commit,
                    qualification_commit,
                    activation_commit,
                    qualification=qualification,
                )

        self.assertEqual(run(base), base)
        early = copy.deepcopy(base)
        early["created_at_utc"] = "2026-07-23T00:00:05Z"
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "ACTIVATION_CHRONOLOGY"
        ):
            run(early)
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "DATA_ONLY_DIFF_INVALID"
        ):
            run(
                base,
                statuses={
                    **dict(
                        sorted(
                            verify.FRAMEWORK_RECOVERY_2_ACTIVATION_STATUSES.items()
                        )
                    ),
                    "extra": "A",
                },
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError,
            "CURRENT_AUDIT_FRAMEWORK_RECOVERY_2_MODE",
        ):
            run(
                base,
                wrong_mode_path=verify.FRAMEWORK_RECOVERY_2_ACTIVATION_PATH,
            )
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "commit signature"
        ):
            run(base, commit_signature_error=True)
        with self.assertRaisesRegex(
            verify.CurrentAuditError, "detached signature"
        ):
            run(base, detached_signature_error=True)

    def test_framework_recovery_2_frozen_anchor_precedence(self) -> None:
        verify = _load_verify()
        framework_commit = "1" * 40
        first_repair = "2" * 40
        second_repair = "3" * 40
        head = "4" * 40
        chain = [framework_commit, head]
        first = {
            "repair_commit": first_repair,
            "qualification_commit": None,
            "activation_commit": None,
        }
        second = {
            "repair_commit": second_repair,
            "qualification_commit": None,
            "activation_commit": None,
            "plan": {},
        }
        metadata = {
            "parent": verify.IMPLEMENTATION_COMMIT,
            "author_name": "Sepehr Mahmoudian",
            "author_email": "sepmhn@gmail.com",
            "committer_name": "Sepehr Mahmoudian",
            "committer_email": "sepmhn@gmail.com",
            "subject": "release: test",
        }
        anchors = {}
        for path in verify.FRAMEWORK_CORE_FROZEN_PATHS:
            if path in verify.FRAMEWORK_RECOVERY_2_CORE_PATHS:
                anchors[path] = second_repair
            elif path in verify.FRAMEWORK_RECOVERY_CORE_PATHS:
                anchors[path] = first_repair
            else:
                anchors[path] = framework_commit

        def git_command(_repo, *arguments, **_kwargs):
            if arguments[:2] == ("rev-parse", "HEAD"):
                return (head + "\n").encode("ascii")
            if arguments[:3] == (
                "rev-list",
                "--first-parent",
                "--reverse",
            ):
                return ("\n".join(chain) + "\n").encode("ascii")
            self.fail(f"unexpected git command {arguments}")

        def git_file(_repo, commit, path):
            if path == verify.EXPECTED_REQUIREMENTS_LEDGER["path"]:
                return b"same requirements"
            return f"{commit}:{path}".encode("utf-8")

        def tree_entry(_repo, commit, path):
            selected = anchors.get(path, commit) if commit == head else commit
            if path == verify.FRAMEWORK_RECOVERY_PLAN_PATH and commit == head:
                selected = first_repair
            if path == verify.FRAMEWORK_RECOVERY_2_PLAN_PATH and commit == head:
                selected = second_repair
            return {"mode": "100644", "type": "blob", "oid": f"{selected}:{path}"}

        def worktree(_repo, path, _maximum, _label):
            if path == verify.FRAMEWORK_RECOVERY_PLAN_PATH:
                anchor = first_repair
            elif path == verify.FRAMEWORK_RECOVERY_2_PLAN_PATH:
                anchor = second_repair
            else:
                anchor = anchors[path]
            return git_file(_repo, anchor, path)

        with (
            mock.patch.object(verify, "_git", side_effect=git_command),
            mock.patch.object(verify, "_commit_metadata", return_value=metadata),
            mock.patch.object(verify, "_verify_named_commit_signature"),
            mock.patch.object(
                verify,
                "_changed_path_statuses",
                return_value=verify.FRAMEWORK_PATH_STATUSES,
            ),
            mock.patch.object(verify, "_git_file", side_effect=git_file),
            mock.patch.object(
                verify,
                "_commit_file_record",
                return_value=verify.QUALIFICATION_AMENDMENT_RECORD,
            ),
            mock.patch.object(
                verify, "_verify_framework_recovery_history", return_value=first
            ),
            mock.patch.object(
                verify,
                "_verify_framework_recovery_2_history",
                return_value=second,
            ),
            mock.patch.object(verify, "_git_tree_entry", side_effect=tree_entry),
            mock.patch.object(
                verify,
                "_read_repo_relative_bounded",
                side_effect=worktree,
            ),
            mock.patch.object(
                verify, "_verify_post_activation_gate_retention"
            ),
            mock.patch.object(verify, "_verify_cited_test_ids"),
        ):
            verify._verify_framework_history(Path("."))
        self.assertEqual(
            anchors["tools/release/verify-current-audit.py"], second_repair
        )
        self.assertEqual(
            anchors["tools/release/current-audit-gate.sh"], second_repair
        )
        self.assertEqual(
            anchors["tools/release/test_verify_current_audit_fr_0002.py"],
            second_repair,
        )
        self.assertEqual(
            anchors["tools/release/test_verify_current_audit.py"],
            first_repair,
        )

    def test_framework_recovery_2_source_controls_reject_bypasses(self) -> None:
        verify = _load_verify()
        path = str(Path(__file__))
        payload = Path(__file__).read_bytes()

        def validate(candidate):
            tree = verify._framework_recovery_2_validate_test_source(
                candidate, path
            )
            cases = verify._discover_unittest_test_cases(
                candidate, path, strict_runtime=True
            )
            return tree, cases

        tree, cases = validate(payload)
        self.assertIsInstance(tree, ast.Module)
        self.assertEqual(len(cases), len(set(cases)))
        mutations = (
            payload.replace(
                b"    def test_bounded_runner_clean_success_is_exact",
                b"    @unittest.skip('disabled')\n"
                b"    def test_bounded_runner_clean_success_is_exact",
                1,
            ),
            payload.replace(
                b'    """Prove bounded cleanup, identity retention, and exact byte capture."""',
                b'    """Prove bounded cleanup, identity retention, and exact byte capture."""\n'
                b"    def setUp(self):\n"
                b"        self.value = 1",
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b"def load_tests(loader, tests, pattern):\n"
                b"    return tests\n\n"
                b'if __name__ == "__main__":',
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b"setattr(FrameworkRecovery2Tests, 'test_x', lambda self: None)\n\n"
                b'if __name__ == "__main__":',
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b'import socket\n\nif __name__ == "__main__":',
                1,
            ),
            payload.replace(PARENT_COMMIT.encode(), b"0" * 40, 1),
            payload.replace(
                b"class FrameworkRecovery2Tests(unittest.TestCase):",
                b"class FrameworkRecovery2Tests(object):",
                1,
            ),
            payload.replace(
                b"    def test_bounded_runner_clean_success_is_exact",
                b"    async def test_bounded_runner_clean_success_is_exact",
                1,
            ),
            payload.replace(
                b"class FrameworkRecovery2Tests(unittest.TestCase):",
                b"def _load_verify():\n"
                b"    return None\n\n"
                b"class FrameworkRecovery2Tests(unittest.TestCase):",
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b"unittest.TestResult.addFailure = lambda *args: None\n\n"
                b'if __name__ == "__main__":',
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b"FrameworkRecovery2Tests = alias = None\n\n"
                b'if __name__ == "__main__":',
                1,
            ),
            payload.replace(
                b'if __name__ == "__main__":',
                b'__name__ = alias = "disabled"\n\n'
                b'if __name__ == "__main__":',
                1,
            ),
        )
        self.assertTrue(all(mutated != payload for mutated in mutations))
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(verify.CurrentAuditError):
                    validate(mutated)


if __name__ == "__main__":
    unittest.main()
