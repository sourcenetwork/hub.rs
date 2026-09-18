"""Recorder failures retain evidence and cannot overwrite an existing run."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class RecorderTests(unittest.TestCase):
    def test_failure_retains_exit_status_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'runner'
            runner.write_text('#!/bin/sh\nprintf "partial measurement\\n"\nprintf "%s" "$RUST_LOG" >&2\nexit 7\n')
            runner.chmod(0o700)
            output = root / 'result'
            checkout = Path(__file__).resolve().parents[2]
            command = [sys.executable, str(Path(__file__).resolve().with_name('record.py')),
                       '--node', str(runner), '--runner', str(runner),
                       '--history', 'rocksdb', '--output', str(output),
                       '--rust-log', 'warn,vera_diagnostics=debug', '1']
            result = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            metadata = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(metadata['exit_code'], 7)
            self.assertEqual(metadata['rust_log'], 'warn,vera_diagnostics=debug')
            self.assertEqual((output / 'stderr.log').read_text(), metadata['rust_log'])
            self.assertEqual((output / 'workload.jsonl').read_text(), 'partial measurement\n')
            repeated = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(json.loads((output / 'manifest.json').read_text()), metadata)


if __name__ == '__main__':
    unittest.main()
