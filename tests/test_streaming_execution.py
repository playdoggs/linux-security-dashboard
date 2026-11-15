"""Production streaming I/O in isolated interpreters; Python fixtures, never sudo."""
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

TESTS = Path(__file__).resolve().parent
HARNESS = r'''
import sys, subprocess, time, os, selectors, codecs, json, logging
sys.path.insert(0, sys.argv[1])
from test_command_outcomes import NS, CLASSES, load_definition
NS.update(os=os, selectors=selectors, codecs=codecs, time=time)
Worker=load_definition(CLASSES['StreamingCommandWorker'])
fixture, timeout, mode = sys.argv[2], float(sys.argv[3]), sys.argv[4]
original = subprocess.Popen
children=[]
def launch(argv, **kwargs):
    if mode == 'stdin':
        assert argv[:2] == ['sudo', '-S']
        argv=argv[2:]  # Substitute only our Python fixture; NEVER execute sudo.
    assert argv[:3] == [sys.executable, '-B', '-c']
    child=original(argv, **kwargs)
    children.append(child)
    return child
subprocess.Popen=launch
worker=Worker([sys.executable, '-B', '-c', fixture], timeout=timeout,
              sudo=mode=='stdin', password=b'x'*1048576 if mode=='stdin' else None)
events=[]
errors=[]
updates=[0]
worker.finished_ok.connect(lambda: events.append('success'))
worker.failed.connect(lambda: events.append('failure'))
worker.error_ready.connect(errors.append)
worker.output_ready.connect(lambda line: updates.__setitem__(0, updates[0]+1))
if mode == 'readerror':
    original_read=os.read
    def read(fd, size):
        # Allow Popen's internal exec-error pipe read to finish first.
        if children:
            raise OSError('injected output read error')
        return original_read(fd,size)
    os.read=read
start=time.monotonic()
worker.run()
print(json.dumps(dict(events=events, reason=worker.failure_reason, elapsed=time.monotonic()-start,
                     output=worker.full_output, truncated=worker.output_truncated,
                     reaped=worker.direct_child_reaped, errors=errors, updates=updates[0],
                     closed=all(stream is None or stream.closed for p in children
                                for stream in (p.stdin,p.stdout,p.stderr)),
                     retained=sum(len(v) for v in worker._captured.values()))))
'''


class StreamingExecution(unittest.TestCase):
    def run_fixture(self, source, timeout=0.3, mode='normal'):
        result = subprocess.run([sys.executable, '-B', '-c', HARNESS, str(TESTS),
                                 textwrap.dedent(source), str(timeout), mode],
                                capture_output=True, text=True, timeout=6, check=True)
        value = json.loads(result.stdout)
        self.assertEqual(len(value['events']), 1)
        self.assertTrue(value['closed'])
        self.assertEqual(value['retained'], 0)
        self.assertLess(value['elapsed'], timeout + 2)
        return value

    def test_success_partial_line_utf8_and_large_stderr(self):
        value = self.run_fixture("""
            import os
            os.write(2, b'w'*262144)
            os.write(1, 'partial café'.encode())
        """, timeout=2)
        self.assertEqual(value['events'], ['success'])
        self.assertEqual(value['output'], 'partial café')
        self.assertTrue(value['reaped'])
        self.assertFalse(value['truncated'])

    def test_silence_and_unfinished_line_obey_deadline(self):
        for prefix in ('', "os.write(1,b'unfinished');"):
            with self.subTest(prefix=prefix):
                value = self.run_fixture('import os,time; '+prefix+'time.sleep(10)')
                self.assertEqual(value['events'], ['failure'])
                self.assertEqual(value['reason'], 'timeout')
                self.assertTrue(value['reaped'])

    def test_inherited_pipes_do_not_extend_deadline(self):
        value = self.run_fixture("""
            import subprocess,sys
            subprocess.Popen([sys.executable,'-B','-c','import time; time.sleep(0.8)'])
        """)
        self.assertEqual(value['events'], ['failure'])
        self.assertEqual(value['reason'], 'timeout')
        self.assertTrue(value['reaped'])
        self.assertTrue(any('Descendant state is not verified' in x for x in value['errors']))

    def test_ignored_terminate_escalates_only_direct_child(self):
        value = self.run_fixture("""
            import signal,time
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(10)
        """)
        self.assertEqual(value['reason'], 'timeout')
        self.assertTrue(value['reaped'])

    def test_output_limit_is_failure_not_complete_evidence(self):
        for fd in (1, 2):
            with self.subTest(fd=fd):
                value = self.run_fixture(f'import os; os.write({fd}, b"x"*2200000)', timeout=2)
                self.assertEqual(value['events'], ['failure'])
                self.assertEqual(value['reason'], 'output_limit')
                self.assertTrue(value['truncated'])
                self.assertLessEqual(len(value['output'].encode()), 2*1024*1024)
                self.assertTrue(value['reaped'])

    def test_gui_update_queue_has_a_separate_bound(self):
        value = self.run_fixture('import os; os.write(1,b"x\\n"*5000)', timeout=2)
        self.assertEqual(value['events'], ['failure'])
        self.assertEqual(value['reason'], 'output_limit')
        self.assertTrue(value['truncated'])
        self.assertEqual(value['updates'], 4096)

    def test_closed_output_pipes_do_not_skip_process_wait_deadline(self):
        value = self.run_fixture('import os,time; os.close(1); os.close(2); time.sleep(10)')
        self.assertEqual(value['reason'], 'timeout')
        self.assertTrue(value['reaped'])

    def test_blocked_password_input_obeys_same_deadline(self):
        value = self.run_fixture('import time; time.sleep(10)', mode='stdin')
        self.assertEqual(value['reason'], 'timeout')
        self.assertTrue(value['reaped'])

    def test_read_exception_closes_pipes_and_reaps_child(self):
        value = self.run_fixture('import time; print("ready",flush=True); time.sleep(10)', mode='readerror')
        self.assertEqual(value['events'], ['failure'])
        self.assertEqual(value['reason'], 'exception')
        self.assertTrue(value['reaped'])

    def test_nonzero_exit_does_not_become_success(self):
        value = self.run_fixture('import sys; print("partial"); sys.exit(3)')
        self.assertEqual(value['events'], ['failure'])
        self.assertEqual(value['reason'], 'nonzero_exit')


if __name__ == '__main__':
    unittest.main()
