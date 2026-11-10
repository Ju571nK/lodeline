"""The rpm uninstall scriptlet removes the shared SELinux module only with the last package."""

import os
import stat
import subprocess
import tempfile
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "lodeline-agent": "lodeline",
    "lodeline-sender": "lodeline-sender",
    "lodeline-server": "lodeline-server",
}
ALL = ["lodeline", "lodeline-sender", "lodeline-server"]


def scriptlet(crate):
    text = (ROOT / "crates" / crate / "Cargo.toml").read_text()
    body = re.search(r'post_uninstall_script = """\\\n(.*?)"""', text, re.S).group(1)
    return body.replace("\\\\", "\\")  # TOML basic string: only \\ is used


def run(crate, arg, rpm_body, with_semodule=True):
    """Run the scriptlet under sh -e; return (exit code, whether semodule -r ran)."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        log = d / "semodule.log"
        stubs = d / "bin"
        stubs.mkdir()

        def stub(name, body):
            p = stubs / name
            p.write_text("#!/bin/sh\n" + body + "\n")
            p.chmod(p.stat().st_mode | stat.S_IXUSR)

        stub("rpm", rpm_body)
        stub("systemctl", "exit 0")
        if with_semodule:
            stub("semodule", f'echo "$@" >> {log}')
        # Only the stubs plus /bin and /usr/bin tools the scriptlet needs, none of them semodule.
        for tool in ("grep", "echo"):
            if (Path("/usr/bin") / tool).exists():
                (stubs / tool).symlink_to(Path("/usr/bin") / tool)
        env = {"PATH": str(stubs)}
        r = subprocess.run(
            ["/bin/sh", "-e", "-c", scriptlet(crate), "sh", arg],
            env=env, capture_output=True, text=True,
        )
        return r.returncode, log.exists() and log.read_text().strip() == "-r lodeline"


def names(*pkgs):
    return "\n".join(f"{p}-0.12.1-1.x86_64" for p in pkgs + ("bash", "glibc")) + "\n"


def listing(*pkgs):
    return f"printf '%s' '{names(*pkgs)}'"


@unittest.skipIf(os.name == "nt", "needs a POSIX sh")
class UninstallScriptletTests(unittest.TestCase):
    def check(self, crate, arg, rpm_body, expect_removed, **kw):
        code, removed = run(crate, arg, rpm_body, **kw)
        self.assertEqual(code, 0, "scriptlet must always exit 0")
        self.assertEqual(removed, expect_removed)

    def test_cases(self):
        for crate, me in PACKAGES.items():
            others = tuple(p for p in ALL if p != me)
            with self.subTest(crate=crate, case="upgrade"):
                self.check(crate, "1", listing(*others), False)
            for n, expect in ((1, False), (2, False), (0, True)):
                with self.subTest(crate=crate, case=f"erase with {n} other(s)"):
                    self.check(crate, "0", listing(*others[:n]), expect)
            with self.subTest(crate=crate, case="rpm -qa fails"):
                self.check(crate, "0", "exit 1", False)
            with self.subTest(crate=crate, case="rpm -qa fails after partial output"):
                self.check(crate, "0", listing() + "; exit 1", False)
            with self.subTest(crate=crate, case="rpm -qa prints nothing"):
                self.check(crate, "0", "exit 0", False)
            with self.subTest(crate=crate, case="no semodule"):
                self.check(crate, "0", listing(), False, with_semodule=False)

    def test_scriptlets_differ_only_in_package_names(self):
        def norm(crate):
            s = scriptlet(crate)
            s = s[s.index("# The three packages") :]
            return s.replace("lodeline-sender|lodeline-server", "X").replace("lodeline|lodeline-server", "X").replace("lodeline|lodeline-sender", "X")

        self.assertEqual(norm("lodeline-agent"), norm("lodeline-sender"))
        self.assertEqual(norm("lodeline-agent"), norm("lodeline-server"))


if __name__ == "__main__":
    unittest.main()
