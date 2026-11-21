"""Isolate old AST fixtures from newly shared privileged dispatch.

The adapter never spawns a process. Tests of the production transaction collector
load it explicitly with transaction_stub=False and mock Popen instead.
"""
import ast
import logging
import os
import re
import selectors
import shlex
import stat
import subprocess
import time
import urllib.parse
from pathlib import Path
from unittest.mock import Mock

SOURCE = Path(__file__).resolve().parents[1] / 'linux-security-dashboard.py'
TREE = ast.parse(SOURCE.read_text())
HELPERS = {'normalize_privileged_diagnostic', 'privileged_capture', 'sanitize_diagnostic', 'diagnostic_exception', 'DiagnosticFilter',
           'PRIVILEGED_PATH', 'command_argv', 'resolve_privileged_executable',
           'privileged_invocation', 'package_transaction', 'run_package_transaction',
           'executable_trust'}


def install_helpers(namespace, transaction_stub=True, trusted_stub=True):
    if namespace.get('_privileged_helpers_loaded'):
        return
    namespace['_privileged_helpers_loaded'] = True
    for name, value in dict(logging=logging, os=os, re=re, selectors=selectors,
                            shlex=shlex, stat=stat, subprocess=subprocess, time=time,
                            urllib=__import__('urllib'), Path=Path).items():
        namespace.setdefault(name, value)
    for node in TREE.body:
        name = getattr(node, 'name', None)
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
        if name in HELPERS:
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    if trusted_stub:
        # Old outcome/callback fixtures do not test filesystem trust or require
        # actual host packages. The dedicated hardening suite tests real policy.
        namespace['resolve_privileged_executable'] = lambda name: '/usr/bin/' + name.rsplit('/', 1)[-1]
    if transaction_stub:
        def collect(command, password, progress):
            if not isinstance(namespace['subprocess'].run, Mock):
                raise AssertionError('Unit transaction adapter requires mocked subprocess.run')
            argv, env = namespace['privileged_invocation'](command, password)
            options = dict(capture_output=True, env=env)
            options.update(input=password + b'\n') if password else options.update(stdin=subprocess.DEVNULL)
            result = namespace['subprocess'].run(argv, **options)
            output = (result.stdout or b'') + (result.stderr or b'')
            return dict(code=result.returncode, error=None,
                        output=namespace['sanitize_diagnostic'](output, password))
        namespace['run_package_transaction'] = collect
