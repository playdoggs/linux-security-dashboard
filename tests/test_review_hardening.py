"""H05-R1/H16-R1: temporary symlink trees and real pipes; never sudo/exec.

Filesystem ownership is simulated: tests cannot create root-owned files. Real
symlinks/permissions are used, and ancestors of the temporary tree are treated as
protected solely within each metadata patch. No host ownership/settings change.
"""
import codecs
import logging
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication
from test_privileged_hardening import namespace


class IntermediateSymlinkTrust(unittest.TestCase):
    def setUp(self):
        self.ns = namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='dashboard-link-review-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('bin', 'protected', 'intermediate'):
            (self.root / name).mkdir(mode=0o755)
        self.target = self.root / 'protected' / 'tool'
        self.target.write_text('fixture, never executed\n')
        self.target.chmod(0o755)
        self.hop = self.root / 'intermediate' / 'hop'
        self.hop.symlink_to(self.target)
        self.entry = self.root / 'bin' / 'tool'
        self.entry.symlink_to(self.hop)
        self.nonroot = set()

    @contextmanager
    def metadata(self):
        original_stat, original_lstat = Path.stat, Path.lstat
        def decorate(path, info):
            values = list(info)
            values[4] = 12345 if path in self.nonroot else 0
            if path != self.root and self.root not in path.parents:
                # The real /tmp is intentionally untrusted. Model a protected
                # fixture namespace without requiring root/chown or changing it.
                values[0] &= ~0o022
            return os.stat_result(values)
        def fake_stat(path, *args, **kwargs):
            return decorate(path, original_stat(path, *args, **kwargs))
        def fake_lstat(path, *args, **kwargs):
            return decorate(path, original_lstat(path, *args, **kwargs))
        with patch.object(Path, 'stat', fake_stat), patch.object(Path, 'lstat', fake_lstat):
            yield

    def trusted(self, path=None):
        with self.metadata():
            return self.ns['executable_trust'](path or self.entry)[0]

    def test_untrusted_intermediate_directory_owner_is_rejected(self):
        self.nonroot.add(self.hop.parent)
        self.assertFalse(self.trusted())

    def test_group_or_other_writable_intermediate_directory_is_rejected(self):
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.hop.parent.chmod(mode)
                self.assertFalse(self.trusted())

    def test_nonroot_intermediate_symlink_owner_is_rejected(self):
        self.nonroot.add(self.hop)
        self.assertFalse(self.trusted())

    def test_protected_absolute_chain_with_normal_symlink_modes_is_accepted(self):
        self.assertTrue(stat.S_ISLNK(self.hop.lstat().st_mode))
        self.assertEqual(self.hop.lstat().st_mode & 0o777, 0o777)
        self.assertTrue(self.trusted())

    def test_relative_and_usr_merge_style_directory_links_are_accepted(self):
        usr = self.root / 'usr'
        (usr / 'bin').mkdir(parents=True, mode=0o755)
        usr.chmod(0o755)
        (self.root / 'merged-bin').symlink_to('usr/bin', target_is_directory=True)
        (usr / 'bin' / 'tool').symlink_to('../../intermediate/hop')
        self.hop.unlink()
        self.hop.symlink_to('../protected/tool')
        self.assertTrue(self.trusted(self.root / 'merged-bin' / 'tool'))

    def test_untrusted_directory_before_dotdot_is_not_skipped(self):
        self.entry.unlink()
        self.entry.symlink_to('../intermediate/../protected/tool')
        self.hop.parent.chmod(0o777)
        self.assertFalse(self.trusted())

    def test_untrusted_final_target_or_nonexecutable_file_is_rejected(self):
        self.nonroot.add(self.target)
        self.assertFalse(self.trusted())
        self.nonroot.clear()
        self.target.chmod(0o644)
        self.assertFalse(self.trusted())

    def test_broken_and_looping_chains_fail_closed(self):
        self.hop.unlink()
        self.assertFalse(self.trusted())
        self.hop.symlink_to(self.entry)
        self.assertFalse(self.trusted())

    def test_unreadable_link_fails_closed(self):
        with patch.object(os, 'readlink', side_effect=PermissionError('fixture')):
            self.assertFalse(self.trusted())

    def test_raw_link_directory_requirements_on_regular_file_are_rejected(self):
        for suffix in ('/', '/.'):
            with self.subTest(suffix=suffix):
                self.entry.unlink()
                self.entry.symlink_to(str(self.target) + suffix)
                self.assertFalse(self.trusted())

    def test_relative_link_directory_requirements_on_regular_file_are_rejected(self):
        for target in ('../protected/tool/', '../protected/tool/.'):
            with self.subTest(target=target):
                self.entry.unlink()
                self.entry.symlink_to(target)
                self.assertFalse(self.trusted())

    def test_input_directory_requirements_are_not_normalized_away(self):
        for suffix in ('/', '/.'):
            with self.subTest(suffix=suffix):
                self.assertFalse(self.trusted(str(self.target) + suffix))

    def test_directory_markers_before_executable_are_valid(self):
        self.entry.unlink()
        self.entry.symlink_to('../protected/./tool')
        self.assertTrue(self.trusted())

    def test_resolver_rejects_chain_without_falling_back_or_expanding_search(self):
        self.nonroot.add(self.hop.parent)
        trust = self.ns['executable_trust']
        checked = Mock(side_effect=lambda path:trust(self.entry))
        with self.metadata(), patch.dict(self.ns, executable_trust=checked), \
                patch.object(os.path, 'lexists', side_effect=lambda p:p == '/usr/bin/review-fixture') as lookup:
            with self.assertRaisesRegex(ValueError, 'Untrusted'):
                self.ns['resolve_privileged_executable']('review-fixture')
        checked.assert_called_once_with('/usr/bin/review-fixture')
        self.assertEqual([call.args[0] for call in lookup.call_args_list],
                         ['/usr/sbin/review-fixture', '/usr/bin/review-fixture'])


class IncompletePrivilegedOutput(unittest.TestCase):
    FRAGMENT = 'SpecimenPiece'
    PASSWORD = b'SpecimenPieceRemainder'
    PREFIX = b'https://operator:SpecimenPiece'

    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def exercise(self, mode, payload=None, *, sudo=True, returncode=0, cleanup_error=False,
                 stderr_payload=b'', sanitize_error=False):
        ns = namespace()
        ns['codecs'] = codecs
        if sanitize_error:
            sanitize = ns['sanitize_diagnostic']
            calls = 0
            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError(self.PREFIX.decode())
                return sanitize(*args, **kwargs)
            ns['sanitize_diagnostic'] = fail_second
        ns['privileged_invocation'] = lambda *args: (['fixture-never-executed'], {})
        stdout_fd, stdout_write = os.pipe()
        stderr_fd, stderr_write = os.pipe()
        out, err = os.fdopen(stdout_fd, 'rb', buffering=0), os.fdopen(stderr_fd, 'rb', buffering=0)
        self.addCleanup(out.close); self.addCleanup(err.close)
        if stderr_payload:
            os.write(stderr_write, stderr_payload)
        os.close(stderr_write)
        payload = self.PREFIX if payload is None else payload
        os.write(stdout_write, payload)
        if mode not in ('timeout', 'read'):
            os.close(stdout_write)
            stdout_write = None
        proc = SimpleNamespace(stdin=None, stdout=out, stderr=err, wait=Mock(return_value=returncode),
                               poll=Mock(return_value=0), terminate=Mock(), kill=Mock())
        if cleanup_error:
            proc.poll.return_value = None
            if cleanup_error == 'wait':
                proc.wait.side_effect = OSError(self.PREFIX.decode())
            else:
                proc.terminate.side_effect = OSError(self.PREFIX.decode())
        if mode == 'close':
            closed = 0
            def close():
                nonlocal closed
                closed += 1
                out.close()
                if closed > 1:
                    raise OSError(self.PREFIX.decode())
            proc.stdout = SimpleNamespace(fileno=lambda:stdout_fd, close=close)
        worker = ns['StreamingCommandWorker'](['lynis', 'audit', 'system'], sudo=sudo,
                                             password=self.PASSWORD if sudo else None, timeout=.03)
        if mode == 'cap':
            worker.MAX_OUTPUT_BYTES = len(self.PREFIX if payload.startswith(b'https:') else self.FRAGMENT)
        outputs, errors, outcomes = [], [], []
        activity = Mock()
        worker.output_ready.connect(outputs.append)
        worker.output_ready.connect(activity.append)
        worker.error_ready.connect(errors.append)
        worker.error_ready.connect(activity.append)
        worker.finished_ok.connect(lambda: outcomes.append('success'))
        worker.failed.connect(lambda: outcomes.append('failure'))
        real_read = os.read
        reads = 0
        def read(fd, count):
            nonlocal reads
            if mode == 'read' and fd == stdout_fd:
                reads += 1
                if reads > 1:
                    raise OSError(self.PREFIX.decode())
                count = len(self.PREFIX)
            return real_read(fd, count)
        try:
            with patch.object(subprocess, 'Popen', return_value=proc,
                              side_effect=OSError(self.PREFIX.decode()) if mode == 'startup' else None) as start, \
                    patch.object(os, 'read', side_effect=read), patch.object(logging, 'error') as log:
                worker.run()
            self.assertNotIn('shell', start.call_args.kwargs)
            return worker, outputs, errors, outcomes, str(log.call_args_list), str(activity.mock_calls)
        finally:
            if stdout_write is not None:
                os.close(stdout_write)
            out.close(); err.close()

    def assert_withheld(self, result):
        worker, outputs, errors, outcomes, logs, activity = result
        self.assertEqual(outcomes, ['failure'])
        self.assertEqual(worker.full_output, '')
        self.assertEqual(worker._captured, {})
        for destination in (str(outputs), str(errors), logs, activity):
            self.assertNotIn(self.FRAGMENT, destination)
            self.assertNotIn('https://operator:', destination)
        self.assertTrue(any('captured output discarded' in message.lower() for message in errors))

    def test_cap_inside_url_before_at_discards_retained_credentials(self):
        value = self.exercise('cap', self.PREFIX + b'Remainder@example.test/repo')
        self.assert_withheld(value)
        self.assertEqual(value[0].failure_reason, 'output_limit')

    def test_cap_inside_echoed_password_discards_retained_credentials(self):
        self.assert_withheld(self.exercise('cap', self.PASSWORD + b'!'))

    def test_timeout_with_partial_url_discards_retained_credentials(self):
        value = self.exercise('timeout')
        self.assert_withheld(value)
        self.assertEqual(value[0].failure_reason, 'timeout')

    def test_read_error_and_exception_payload_cannot_disclose_fragment(self):
        value = self.exercise('read', self.PREFIX + b'!')
        self.assert_withheld(value)
        self.assertEqual(value[0].failure_reason, 'exception')

    def test_cleanup_exception_payload_cannot_disclose_fragment(self):
        self.assert_withheld(self.exercise('read', self.PREFIX + b'!', cleanup_error=True))

    def test_reaping_exception_payload_cannot_disclose_fragment(self):
        value = self.exercise('read', self.PREFIX + b'!', cleanup_error='wait')
        self.assert_withheld(value)
        self.assertFalse(value[0].direct_child_reaped)

    def test_descriptor_cleanup_failure_discards_even_completed_capture(self):
        self.assert_withheld(self.exercise('close'))

    def test_process_creation_exception_payload_is_not_logged_or_displayed(self):
        self.assert_withheld(self.exercise('startup'))

    def test_successfully_collected_privileged_output_is_preserved_and_redacted(self):
        text = b'Scan evidence\nhttps://operator:SpecimenPieceRemainder@example.test/repo\n'
        worker, outputs, errors, outcomes, logs, activity = self.exercise('complete', text)
        self.assertEqual(outcomes, ['success'])
        self.assertIn('Scan evidence', worker.full_output)
        self.assertIn('example.test/repo', worker.full_output)
        self.assertNotIn(self.FRAGMENT, worker.full_output)
        self.assertIn(worker.full_output, outputs)
        self.assertEqual(errors, [])
        self.assertNotIn(self.FRAGMENT, activity + logs)

    def test_complete_nonzero_exit_preserves_sanitized_evidence(self):
        text = b'Warning evidence\nhttps://operator:SpecimenPieceRemainder@example.test/repo\n'
        worker, outputs, errors, outcomes, logs, activity = self.exercise('complete', text, returncode=2)
        self.assertEqual(outcomes, ['failure'])
        self.assertIn('Warning evidence', worker.full_output)
        self.assertIn('example.test/repo', worker.full_output)
        self.assertNotIn(self.FRAGMENT, str(outputs) + str(errors) + logs + activity)

    def test_nonzero_stderr_fragment_and_final_close_failure_is_withheld(self):
        value = self.exercise('close', b'complete stdout evidence\n', returncode=2,
                              stderr_payload=self.PREFIX + b'\n')
        self.assert_withheld(value)
        self.assertNotIn('complete stdout evidence', str(value[1]))

    def test_ansi_split_known_password_is_redacted_in_both_streams(self):
        split = b'SpecimenPiece\x1b[0mRemainder'
        for code in (0, 2):
            with self.subTest(returncode=code):
                value = self.exercise('complete', b'stdout evidence ' + split + b'\n',
                                      stderr_payload=b'stderr evidence ' + split + b'\n', returncode=code)
                worker, outputs, errors, outcomes, logs, activity = value
                for surface in (worker.full_output, str(outputs), str(errors), logs, activity):
                    self.assertNotIn(self.PASSWORD.decode(), surface)
                    self.assertNotIn(self.FRAGMENT, surface)
                self.assertIn('stdout evidence', worker.full_output)
                self.assertIn('REDACTED', worker.full_output)
                self.assertEqual(worker._captured, {})
                self.assertEqual(outcomes, ['success'] if code == 0 else ['failure'])
                if code:
                    self.assertIn('stderr evidence REDACTED', '\n'.join(errors))

    def test_sanitization_failure_prevents_either_stream_being_released(self):
        value = self.exercise('complete', b'unreleased stdout evidence\n',
                              stderr_payload=b'unreleased stderr evidence\n', sanitize_error=True)
        self.assert_withheld(value)
        self.assertNotIn('unreleased stdout evidence', str(value[1]))
        self.assertNotIn('unreleased stderr evidence', str(value[2]))

    def test_complete_cross_stream_password_is_withheld_in_both_orders(self):
        for code in (0, 2):
            for left, right in ((b'SpecimenPiece', b'Remainder'), (b'Remainder', b'SpecimenPiece')):
                with self.subTest(code=code, left=left):
                    value = self.exercise('complete', left, stderr_payload=right, returncode=code)
                    self.assert_withheld(value)
                    self.assertNotIn('Remainder', str(value[1:]))

    def test_normalized_cross_stream_password_is_withheld(self):
        cases = ((b'SpecimenPiece\x1b[0m', b'Remainder'),
                 (b'Remainder', b'SpecimenPiece\r'),
                 (b'SpecimenPiece\x1b[', b'0mRemainder'),
                 (b'SpecimenPiece\n', b'  Remainder'))
        for left, right in cases:
            with self.subTest(left=left, right=right):
                self.assert_withheld(self.exercise('complete', left, stderr_payload=right, returncode=2))

    def test_redacted_whole_secret_does_not_mask_another_cross_stream_split(self):
        value = self.exercise('complete', self.PASSWORD + b' and SpecimenPiece',
                              stderr_payload=b'Remainder', returncode=2)
        self.assert_withheld(value)

    def test_cross_stream_incomplete_or_failed_cleanup_is_withheld(self):
        for mode, left, right in (('timeout', b'SpecimenPiece', b'Remainder'),
                                  ('close', b'SpecimenPiece', b'Remainder'),
                                  ('read', self.PREFIX + b'!', b'Remainder'),
                                  ('startup', b'SpecimenPiece', b'Remainder')):
            with self.subTest(mode=mode):
                self.assert_withheld(self.exercise(mode, left, stderr_payload=right, returncode=2))

    def test_safe_complete_streams_preserve_evidence_and_outcome(self):
        for code in (0, 2):
            value = self.exercise('complete', b'safe stdout\n', stderr_payload=b'safe stderr\n', returncode=code)
            worker, outputs, errors, outcomes, logs, activity = value
            self.assertEqual(worker.full_output, 'safe stdout\n')
            self.assertIn(worker.full_output, outputs)
            self.assertEqual(outcomes, ['success'] if code == 0 else ['failure'])
            if code:
                self.assertIn('safe stderr', errors)
            self.assertEqual(worker._captured, {})

    def test_nonprivileged_partial_evidence_behaviour_is_unchanged(self):
        worker, outputs, errors, outcomes, logs, activity = self.exercise('timeout', b'partial evidence', sudo=False)
        self.assertEqual(outcomes, ['failure'])
        self.assertEqual(worker.full_output, 'partial evidence')


class FinalSecretRedaction(unittest.TestCase):
    def setUp(self):
        self.clean = namespace()['sanitize_diagnostic']

    def test_ansi_and_control_normalization_precedes_secret_matching(self):
        for split in ('SpecimenPiece\x1b[0mRemainder', 'SpecimenPiece\rRemainder'):
            with self.subTest(split=repr(split)):
                text = self.clean(split, b'SpecimenPieceRemainder')
                self.assertNotIn('SpecimenPieceRemainder', text)
                self.assertNotIn('SpecimenPiece', text)

    def test_late_url_normalization_cannot_reconstruct_known_password(self):
        password = b'https://example.test/repo'
        text = self.clean('HTTPS://example.test/repo', password)
        self.assertNotIn(password.decode(), text)

    def test_late_replacement_cannot_reconstruct_known_password(self):
        password = b'left[private key redacted]right'
        text = self.clean('left-----BEGIN PRIVATE KEY-----opaque-----END PRIVATE KEY-----right', password)
        self.assertNotIn(password.decode(), text)

    def test_overlapping_redaction_marker_fails_closed_without_rewriting_loop(self):
        password = b'leftREDACTEDright'
        text = self.clean('left' * 8 + password.decode() + 'right' * 8, password)
        self.assertNotIn(password.decode(), text)
        self.assertEqual(text, '')


if __name__ == '__main__':
    unittest.main()
