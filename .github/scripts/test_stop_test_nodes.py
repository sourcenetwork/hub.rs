import importlib.util
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "stop_test_nodes", pathlib.Path(__file__).with_name("stop-test-nodes.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProcessSelection(unittest.TestCase):
    def test_only_the_selected_executable_matches(self):
        binary = "/runner/work/hub.rs (test)/target/debug/hubd"
        pattern = module.process_pattern(binary)
        for command in (binary, binary + " --config /tmp/node.toml"):
            self.assertIsNotNone(re.search(pattern, command))
        for command in (
            "/another" + binary,
            binary + "-other",
            binary.replace("hub.rs", "hubXrs"),
            "python3 cleanup.py " + binary,
        ):
            self.assertIsNone(re.search(pattern, command))

    def test_cleanup_leaves_neighboring_process_running(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "hubd"
            neighbor = pathlib.Path(directory) / "hubd-other"
            binary.symlink_to("/bin/sleep")
            neighbor.symlink_to("/bin/sleep")
            selected = subprocess.Popen([str(binary), "30"])
            other = subprocess.Popen([str(neighbor), "30"])
            try:
                subprocess.run([sys.executable, spec.origin, str(binary)], check=True)
                self.assertLess(selected.wait(timeout=5), 0)
                self.assertIsNone(other.poll())
                subprocess.run([sys.executable, spec.origin, str(binary)], check=True)
            finally:
                for process in (selected, other):
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=5)

    def test_rejects_broad_or_relative_paths(self):
        for binary in ("", "hubd", "target/debug/hubd", "/", "/runner/target/debug"):
            with self.assertRaises(ValueError):
                module.process_pattern(binary)


if __name__ == "__main__":
    unittest.main()
