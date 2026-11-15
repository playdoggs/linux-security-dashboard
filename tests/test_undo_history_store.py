"""Stage A storage tests. Temporary SQLite stores only; no GUI or commands."""
import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import datetime
import json
import multiprocessing
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
NS = dict(sqlite3=sqlite3, os=os, stat=stat, uuid=uuid, datetime=datetime,
          Path=Path, json=json, re=re, shlex=shlex, contextmanager=contextmanager,
          PKG_MGR='apt')
NAMES = {'UndoHistoryError', 'UndoHistoryStore', 'UNDO_SERVICE_TARGETS',
         'UNDO_PACKAGE_RE', 'build_undo_argv', 'UNDO_METADATA_FIELDS',
         'MAX_UNDO_LINE_BYTES', 'normalize_undo_record'}
for node in ast.parse(SOURCE.read_text()).body:
    name = node.name if isinstance(node, (ast.ClassDef, ast.FunctionDef)) else None
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
    if name in NAMES:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), NS)
Store, StorageError = NS['UndoHistoryStore'], NS['UndoHistoryError']


def entry(package='example'):
    return dict(schema_version=2, undo=dict(operation='package_install', manager='apt',
                                           package=package), time='same second',
                action='remove example', cmd='historical only', undo_cmd='never execute')


class HistoryStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state'
        self.store = Store(self.path, manager='apt', timeout=0.05)

    def reopen(self):
        return Store(self.path, manager='apt', timeout=0.05)

    def test_protected_creation_and_durability_settings(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.path / Store.DB_NAME).stat().st_mode), 0o600)
        with self.store._connection() as db:
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone(), (3,))
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone(), ('delete',))
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone(), (1,))
            self.assertEqual(db.execute('PRAGMA trusted_schema').fetchone(), (0,))

    def test_creation_closes_private_descriptor_before_database_publication(self):
        original_open, original_link = os.open, os.link
        private_fds = []
        published = []

        def checked_open(name, *args, **kwargs):
            self.assertNotEqual(name, Store.DB_NAME,
                                'Only SQLite may open the published database')
            fd = original_open(name, *args, **kwargs)
            if str(name).startswith('.history-create-'):
                private_fds.append(fd)
            return fd

        def checked_link(source, destination, **kwargs):
            self.assertEqual(destination, Store.DB_NAME)
            self.assertEqual(len(private_fds), 1)
            with self.assertRaises(OSError):
                os.fstat(private_fds[0])
            published.append(destination)
            return original_link(source, destination, **kwargs)

        path = Path(self.temp.name) / 'new-store'
        with patch.object(os, 'open', side_effect=checked_open), \
                patch.object(os, 'link', side_effect=checked_link):
            store = Store(path, manager='apt')
            store.create(entry())
            Store(path, manager='apt').page()
        self.assertEqual(published, [Store.DB_NAME])
        self.assertEqual(list(path.glob('.history-create-*')), [])
        self.assertEqual(stat.S_IMODE((path / Store.DB_NAME).stat().st_mode), 0o600)

    def test_complete_reopen_no_replay_and_audit_retained(self):
        record_id = self.store.create(entry())
        self.assertEqual(str(uuid.UUID(record_id)), record_id)
        claim = self.store.claim(record_id)
        self.assertEqual(claim['argv'], ['apt', 'install', '-y', 'example'])
        self.store.finish(record_id, claim['attempt_id'], 'completed', 'exit_zero')
        reopened = self.reopen()
        self.assertEqual(reopened.get(record_id)['state'], 'completed')
        self.assertEqual(reopened.page(view='actionable'), [])
        self.assertEqual([event['state'] for event in reopened.events(record_id)],
                         ['completed', 'pending', 'available'])
        with self.assertRaises(StorageError):
            reopened.claim(record_id)

    def test_duplicate_contents_have_distinct_ids_and_exact_updates(self):
        first, second = self.store.create(entry()), self.store.create(entry())
        self.assertNotEqual(first, second)
        attempt = self.store.claim(first)
        self.store.finish(first, attempt['attempt_id'], 'failed', 'nonzero_exit')
        self.assertEqual(self.store.get(second)['state'], 'available')
        self.assertEqual(self.store.get(first)['state'], 'failed')
        with self.assertRaises(StorageError):
            self.store.claim(first)

    def test_concurrent_claims_exactly_one_winner(self):
        record_id = self.store.create(entry())
        barrier = threading.Barrier(2)
        def claim():
            store = self.reopen()  # Each call opens its own connection in this thread.
            barrier.wait(timeout=2)
            try:
                return store.claim(record_id)
            except StorageError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: claim(), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.store.events(record_id)), 2)

    def test_connection_close_preserves_other_connection_cross_process_lock(self):
        # A fresh interpreter has no inherited SQLite descriptors or lock state.
        probe = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0.05, isolation_level=None)
try:
    connection.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as error:
    if 'locked' not in str(error):
        raise
    print('LOCKED')
else:
    print('ACQUIRED')
    connection.execute('ROLLBACK')
finally:
    connection.close()
"""
        def writer_status():
            result = subprocess.run(
                [sys.executable, '-B', '-c', probe, str(self.path / Store.DB_NAME)],
                capture_output=True, text=True, check=True, timeout=5)
            return result.stdout.strip()

        with self.store._connection() as first:
            first.execute('BEGIN IMMEDIATE')
            try:
                self.assertEqual(writer_status(), 'LOCKED')
                # Include constructor checks against an already existing store.
                reopened = self.reopen()
                with reopened._connection() as second:
                    second.execute('SELECT count(*) FROM undo_records').fetchone()
                self.assertEqual(writer_status(), 'LOCKED')
            finally:
                first.execute('ROLLBACK')
        self.assertEqual(writer_status(), 'ACQUIRED')

    def test_pending_never_reactivated_by_open_and_unknown_is_terminal(self):
        record_id = self.store.create(entry())
        claim = self.store.claim(record_id)
        reopened = self.reopen()
        self.assertEqual(reopened.get(record_id)['state'], 'pending')
        self.assertEqual(reopened.page(view='actionable'), [])
        # Only an explicit exact-attempt transition marks interruption; opening
        # another instance must not relabel an actively running command.
        reopened.finish(record_id, claim['attempt_id'], 'outcome-unknown', 'interrupted')
        self.assertEqual(self.reopen().get(record_id)['state'], 'outcome-unknown')
        with self.assertRaises(StorageError):
            reopened.claim(record_id)

    def test_failed_and_timeout_outcomes_do_not_reactivate(self):
        for outcome, reason in [('failed', 'missing_executable'), ('failed', 'exception'),
                                ('outcome-unknown', 'timeout'),
                                ('outcome-unknown', 'dispatch_uncertain')]:
            with self.subTest(outcome=outcome, reason=reason):
                record_id = self.store.create(entry())
                claim = self.store.claim(record_id)
                self.store.finish(record_id, claim['attempt_id'], outcome, reason)
                self.assertEqual(self.reopen().get(record_id)['state'], outcome)
                with self.assertRaises(StorageError):
                    self.store.claim(record_id)

    def test_wrong_attempt_and_double_finish_rejected(self):
        record_id = self.store.create(entry())
        claim = self.store.claim(record_id)
        with self.assertRaises(StorageError):
            self.store.finish(record_id, str(uuid.uuid4()), 'completed', 'exit_zero')
        self.assertEqual(self.store.get(record_id)['state'], 'pending')
        self.store.finish(record_id, claim['attempt_id'], 'completed', 'exit_zero')
        with self.assertRaises(StorageError):
            self.store.finish(record_id, claim['attempt_id'], 'failed', 'nonzero_exit')

    def test_failed_event_write_rolls_back_claim_and_creation(self):
        record_id = self.store.create(entry())
        with patch.object(Store, '_event', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(StorageError):
                self.store.claim(record_id)
            with self.assertRaises(StorageError):
                self.store.create(entry('other'))
        self.assertEqual(self.store.get(record_id)['state'], 'available')
        self.assertEqual(len(self.store.page()), 1)
        self.assertEqual(len(self.store.events(record_id)), 1)

    def test_failed_outcome_write_leaves_pending_non_actionable(self):
        record_id = self.store.create(entry())
        claim = self.store.claim(record_id)
        with patch.object(Store, '_event', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(StorageError):
                self.store.finish(record_id, claim['attempt_id'], 'completed', 'exit_zero')
        self.assertEqual(self.reopen().get(record_id)['state'], 'pending')
        self.assertEqual(self.store.page(view='actionable'), [])
        self.assertEqual(len(self.store.events(record_id)), 2)

    def test_commit_failure_does_not_return_a_claim(self):
        record_id = self.store.create(entry())
        @contextmanager
        def fail_commit(db):
            db.execute('BEGIN IMMEDIATE')
            try:
                yield
                raise sqlite3.OperationalError('simulated commit failure')
            finally:
                db.execute('ROLLBACK')
        with patch.object(Store, '_transaction', staticmethod(fail_commit)):
            with self.assertRaises(StorageError):
                self.store.claim(record_id)
        self.assertEqual(self.store.get(record_id)['state'], 'available')

    def test_interrupted_transaction_rolls_back_on_process_death(self):
        record_id = self.store.create(entry())
        def interrupt():
            with self.store._connection() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE undo_records SET state='pending',active_attempt=? WHERE record_id=?",
                           (str(uuid.uuid4()), record_id))
                os._exit(0)  # Deliberately skip rollback/close: only this temp DB is involved.
        process = multiprocessing.get_context('fork').Process(target=interrupt)
        process.start()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join()
            self.fail('Temporary transaction process did not exit')
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(self.reopen().get(record_id)['state'], 'available')
        self.assertEqual(len(self.store.events(record_id)), 1)

    def test_process_exit_after_committed_claim_leaves_pending(self):
        record_id = self.store.create(entry())
        def interrupt():
            self.store.claim(record_id)
            os._exit(0)  # No command is started; committed intent survives.
        process = multiprocessing.get_context('fork').Process(target=interrupt)
        process.start()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join()
            self.fail('Temporary claim process did not exit')
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(self.reopen().get(record_id)['state'], 'pending')
        self.assertEqual(self.store.page(view='actionable'), [])
        self.assertEqual(len(self.store.events(record_id)), 2)

    def test_uncertain_commit_never_returns_an_executable_claim(self):
        record_id = self.store.create(entry())
        @contextmanager
        def uncertain_commit(db):
            db.execute('BEGIN IMMEDIATE')
            yield
            db.execute('COMMIT')
            raise sqlite3.OperationalError('commit succeeded but acknowledgement lost')
        with patch.object(Store, '_transaction', staticmethod(uncertain_commit)):
            with self.assertRaises(StorageError):
                self.store.claim(record_id)
        self.assertEqual(self.reopen().get(record_id)['state'], 'pending')
        with self.assertRaises(StorageError):
            self.store.claim(record_id)

    def test_inaccessible_directory_does_not_fall_back_or_recreate(self):
        with patch.object(Store, '_open_directory', side_effect=PermissionError('denied')):
            with self.assertRaises(StorageError):
                self.store.create(entry())
        self.assertEqual(self.store.page(), [])

    def test_empty_interrupted_initialization_is_not_silently_repaired(self):
        path = Path(self.temp.name) / 'unfinished'
        path.mkdir(mode=0o700)
        db_path = path / Store.DB_NAME
        db_path.touch(mode=0o600)
        with self.assertRaises(StorageError):
            Store(path, manager='apt')
        self.assertEqual(db_path.read_bytes(), b'')

    def test_invalid_finish_and_event_paging(self):
        record_id = self.store.create(entry())
        claim = self.store.claim(record_id)
        for outcome, reason in [('available', 'retry'), ('completed', 'timeout'),
                                ('failed', 'arbitrary log text'), ([], 'exception')]:
            with self.subTest(outcome=outcome, reason=reason), self.assertRaises(StorageError):
                self.store.finish(record_id, claim['attempt_id'], outcome, reason)
        events = self.store.events(record_id, limit=1)
        older = self.store.events(record_id, before_seq=events[-1]['seq'], limit=1)
        self.assertEqual(events[0]['state'], 'pending')
        self.assertEqual(older[0]['state'], 'available')
        with self.assertRaises(StorageError):
            self.store.events(record_id, limit=201)

    def test_schema_prevents_payload_changes_audit_edits_and_reactivation(self):
        record_id = self.store.create(entry())
        for sql in ("UPDATE undo_records SET operation_json='{}'",
                    'DELETE FROM undo_records', 'DELETE FROM undo_events',
                    "UPDATE undo_events SET reason='changed'"):
            with self.subTest(sql=sql), self.assertRaises(StorageError):
                with self.store._connection() as db:
                    db.execute(sql)
        claim = self.store.claim(record_id)
        self.store.finish(record_id, claim['attempt_id'], 'completed', 'exit_zero')
        with self.assertRaises(StorageError):
            with self.store._connection() as db:
                db.execute("UPDATE undo_records SET state='available',active_attempt=NULL")

    def test_sql_injection_identifiers_and_unsupported_operations_rejected(self):
        for record_id in ("' OR 1=1 --", None, [], str(uuid.uuid4()).upper()):
            with self.subTest(record_id=record_id), self.assertRaises(StorageError):
                self.store.claim(record_id)
        for value in ({'undo_cmd': 'sudo arbitrary'}, entry('-option'),
                      dict(schema_version=3, undo={})):
            with self.subTest(value=value), self.assertRaises((ValueError, StorageError)):
                self.store.create(value)
        self.assertEqual(self.store.page(), [])

    def test_unknown_version_and_missing_schema_never_replaced(self):
        db_path = self.path / Store.DB_NAME
        with sqlite3.connect(db_path) as db:
            db.execute('PRAGMA user_version=99')
        before = db_path.read_bytes()
        with self.assertRaises(StorageError):
            self.reopen()
        self.assertEqual(db_path.read_bytes(), before)
        with sqlite3.connect(db_path) as db:
            db.execute('PRAGMA user_version=1')
            db.execute('DROP TRIGGER retain_undo_events')
        before = db_path.read_bytes()
        with self.assertRaises(StorageError):
            self.reopen()
        self.assertEqual(db_path.read_bytes(), before)

    def test_malformed_and_empty_existing_stores_preserved(self):
        for data in (b'not a database', b''):
            with self.subTest(data=data):
                (self.path / Store.DB_NAME).write_bytes(data)
                before = (self.path / Store.DB_NAME).read_bytes()
                with self.assertRaises(StorageError):
                    self.reopen()
                self.assertEqual((self.path / Store.DB_NAME).read_bytes(), before)

    def test_symlinked_database_and_sidecars_rejected_without_touching_target(self):
        for suffix in ('', '-journal', '-wal', '-shm'):
            with self.subTest(suffix=suffix):
                target = Path(self.temp.name) / ('target' + (suffix or '-db'))
                target.write_bytes(b'untouched')
                target.chmod(0o600)
                path = self.path / (Store.DB_NAME + suffix)
                if path.exists():
                    path.unlink()  # Only files created in this test's temp directory.
                path.symlink_to(target)
                with self.assertRaises(StorageError):
                    self.reopen()
                self.assertEqual(target.read_bytes(), b'untouched')
                path.unlink()
                if not suffix:
                    self.store = Store(self.path, manager='apt', timeout=0.05)

    def test_directory_symlink_permissions_types_and_hardlinks_rejected(self):
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(StorageError):
            Store(alias, manager='apt')
        for path, mode in ((self.path, 0o755), (self.path / Store.DB_NAME, 0o644),
                           (self.path / Store.DB_NAME, 0o400)):
            with self.subTest(path=path, mode=mode):
                old_mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(mode)
                try:
                    with self.assertRaises(StorageError):
                        self.reopen()
                finally:
                    path.chmod(old_mode)
        os.link(self.path / Store.DB_NAME, Path(self.temp.name) / 'hardlink')
        with self.assertRaises(StorageError):
            self.reopen()

    def test_owner_mismatch_rejected(self):
        with patch.object(os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(StorageError):
                self.reopen()

    def test_non_regular_database_rejected(self):
        (self.path / Store.DB_NAME).unlink()
        (self.path / Store.DB_NAME).mkdir(mode=0o700)
        with self.assertRaises(StorageError):
            self.reopen()

    def test_lock_timeout_fails_without_claim_or_event(self):
        record_id = self.store.create(entry())
        with self.store._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                with self.assertRaises(StorageError):
                    self.store.claim(record_id)
            finally:
                db.execute('ROLLBACK')
        self.assertEqual(self.store.get(record_id)['state'], 'available')
        self.assertEqual(len(self.store.events(record_id)), 1)

    def test_bounded_paging_and_views_preserve_current_state(self):
        ids = [self.store.create(entry()) for _ in range(205)]
        claim = self.store.claim(ids[-1])
        self.store.finish(ids[-1], claim['attempt_id'], 'completed', 'exit_zero')
        first = self.store.page()
        self.assertEqual(len(first), 200)
        second = self.store.page(before_seq=first[-1]['seq'])
        self.assertEqual(len(second), 5)
        self.assertFalse({r['record_id'] for r in first} & {r['record_id'] for r in second})
        self.assertEqual(len(self.store.page(view='actionable')), 200)
        self.assertNotIn(ids[-1], {r['record_id'] for r in self.store.page(view='actionable')})
        self.assertEqual([r['record_id'] for r in self.store.page(view='history')], [ids[-1]])
        for kwargs in ({'limit': 201}, {'limit': True}, {'before_seq': -1}, {'view': 'arbitrary'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(StorageError):
                self.store.page(**kwargs)

    def test_no_legacy_import_or_automatic_record_recovery(self):
        legacy = Path(self.temp.name) / '.audit-dashboard-undo.log'
        data = b'{"schema_version":2,"undo_cmd":"sudo example"}\n'
        legacy.write_bytes(data)
        self.reopen()
        self.assertEqual(self.store.page(), [])
        self.assertEqual(legacy.read_bytes(), data)
