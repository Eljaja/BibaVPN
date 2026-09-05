#!/usr/bin/env python3
"""Fault-injection regressions for benchmark cleanup and error reporting."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('local-throughput-bench.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkFailures(unittest.TestCase):
    def test_create_timeout_still_removes_network(self):
        for missing in (False, True):
            with self.subTest(network_missing=missing):
                commands = []

                def injected_run(args, **kwargs):
                    commands.append(args)
                    if args[:3] == ['docker', 'network', 'create']:
                        raise RuntimeError('simulated create timeout')
                    if args[:3] == ['docker', 'network', 'rm'] and missing:
                        return subprocess.CompletedProcess(args, 1, '', f'network {args[3]} not found')
                    return subprocess.CompletedProcess(args, 0, '', '')

                argv = ['bench', '--client', sys.executable, '--server', sys.executable]
                with patch.object(bench.sys, 'argv', argv), patch.object(bench, 'run', injected_run), \
                        patch.object(bench.shutil, 'which', return_value='/unused/tool'):
                    with self.assertRaisesRegex(RuntimeError, '^simulated create timeout$'):
                        bench.main()
                created = next(args[3] for args in commands if args[:3] == ['docker', 'network', 'create'])
                self.assertIn(['docker', 'network', 'rm', created], commands)

    def test_incomplete_transfer_identifies_route(self):
        result = subprocess.CompletedProcess([], 28, '', 'timeout')
        data = {'http_code': 200, 'size_download': 0, 'time_total': 60}
        with self.assertRaisesRegex(RuntimeError, '^direct sample 1: incomplete transfer: rc=28'):
            bench.validate_transfer(result, data, 67108864, context='direct sample 1')


if __name__ == '__main__':
    unittest.main()
