import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "packaging" / "migrate-from-sigil.sh"


def tree(root):
    return {
        str(p.relative_to(root)): p.read_text()
        for p in sorted(Path(root).rglob("*"))
        if p.is_file() and not str(p).startswith(str(Path(root) / "stub"))
    }


class MigrateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stub = self.root / "stub"
        self.stub.mkdir()
        self.calls = self.root / "stub" / "calls.log"

    def put(self, rel, body="x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def run_script(self, component="agent"):
        env = dict(os.environ, PATH=f"{self.stub}:{os.environ['PATH']}")
        result = subprocess.run(
            ["sh", str(SCRIPT), component, "--root", str(self.root)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stderr

    def stub_command(self, name, body):
        path = self.stub / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{self.calls}"\n{body}\n')
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def test_moves_config_and_state_to_a_fresh_host(self):
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("etc/sigil/client.key", "key")
        self.put("var/lib/sigil/state.db", "db")
        self.put("var/log/sigil/events-1.jsonl", "evt")
        self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "etc/lodeline/policy.yaml": "policy",
                "etc/lodeline/client.key": "key",
                "var/lib/lodeline/state.db": "db",
                "var/log/lodeline/events-1.jsonl": "evt",
            },
        )

    def test_rerun_changes_nothing(self):
        self.put("var/lib/sigil/state.db", "db")
        self.put("etc/sigil/policy.yaml", "policy")
        self.run_script()
        first = tree(self.root)
        self.assertEqual(self.run_script(), "")
        self.assertEqual(tree(self.root), first)

    def test_existing_new_path_with_content_keeps_both_untouched(self):
        self.put("var/lib/sigil/state.db", "old")
        self.put("var/lib/lodeline/state.db", "new")
        self.put("var/lib/lodeline/other.db", "new2")
        before = tree(self.root)
        err = self.run_script()
        self.assertEqual(tree(self.root), before)
        self.assertIn("kept /var/lib/sigil", err)

    def test_new_path_with_only_packaged_examples_still_receives_config(self):
        self.put("etc/lodeline/policy.yaml.example", "new example")
        self.put("etc/sigil/policy.yaml.example", "old example")
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("etc/sigil/.hidden", "hidden")
        self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "etc/lodeline/policy.yaml.example": "new example",
                "etc/lodeline/policy.yaml": "policy",
                "etc/lodeline/.hidden": "hidden",
                "etc/sigil/policy.yaml.example": "old example",
            },
        )

    def test_empty_new_dir_from_tmpfiles_still_receives_state(self):
        (self.root / "var/lib/lodeline").mkdir(parents=True)
        self.put("var/lib/sigil/state.db", "db")
        self.run_script()
        self.assertEqual(tree(self.root), {"var/lib/lodeline/state.db": "db"})
        self.assertFalse((self.root / "var/lib/sigil").exists())

    def test_shared_etc_waits_for_other_old_packages(self):
        self.put("usr/bin/sigil", "old agent")
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("var/lib/sigil-proxy/spool.db", "spool")
        err = self.run_script("proxy")
        self.assertIn("still used by sigil", err)
        self.assertTrue((self.root / "etc/sigil/policy.yaml").exists())
        self.assertTrue((self.root / "var/lib/lodeline-proxy/spool.db").exists())

        (self.root / "usr/bin/sigil").unlink()
        self.run_script("proxy")
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")

    def test_server_moves_its_own_config_dir(self):
        self.put("etc/sigil-server/server.yaml", "cfg")
        self.put("var/lib/sigil-server/signed-policy.json", "signed")
        self.put("var/log/sigil-server/server.log", "log")
        self.run_script("server")
        self.assertEqual(
            tree(self.root),
            {
                "etc/lodeline-server/server.yaml": "cfg",
                "var/lib/lodeline-server/signed-policy.json": "signed",
                "var/log/lodeline-server/server.log": "log",
            },
        )

    def test_old_absolute_paths_in_moved_yaml_are_reported_and_not_edited(self):
        body = "client_cert: /etc/sigil/client.crt\n"
        self.put("etc/sigil/sender.yaml", body)
        err = self.run_script("sender")
        self.assertIn("sender.yaml still names an old /sigil path", err)
        self.assertEqual((self.root / "etc/lodeline/sender.yaml").read_text(), body)

    def test_owner_and_group_follow_the_rename_when_both_accounts_exist(self):
        self.put("etc/passwd", "sigil:x:990:990::/:/bin/false\nlodeline:x:991:991::/:/bin/false\n")
        self.put("etc/group", "sigil:x:990:\nlodeline:x:991:\n")
        self.put("var/lib/sigil/state.db", "db")
        self.stub_command("find", "exit 0")
        self.run_script()
        new = self.root / "var/lib/lodeline"
        self.assertEqual(
            self.calls.read_text().splitlines(),
            [
                f"find {new} -user sigil -exec chown -h lodeline {{}} +",
                f"find {new} -group sigil -exec chgrp -h lodeline {{}} +",
            ],
        )

    def test_unknown_component_is_rejected(self):
        result = subprocess.run(["sh", str(SCRIPT), "signer"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
