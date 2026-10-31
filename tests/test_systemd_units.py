"""Packaged systemd units must match what the daemons demand."""

from pathlib import Path
import unittest

UNITS = Path(__file__).resolve().parents[1] / "packaging" / "systemd"


class ProxyUnitTests(unittest.TestCase):
    def test_state_dir_mode_is_0700(self):
        # lodeline-proxy rejects a state dir with any group/other bit (state_dir.rs).
        lines = (UNITS / "lodeline-proxy.service").read_text().splitlines()
        self.assertIn("StateDirectoryMode=0700", lines)


if __name__ == "__main__":
    unittest.main()
