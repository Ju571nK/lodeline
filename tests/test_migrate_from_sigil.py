import os
import shutil
import sqlite3
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
        self.accounts = []

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
        self.assertIn("kept in /var/lib/sigil: state.db", err)
        self.assertNotIn("moved /var/lib/sigil", err)

    def test_entries_merge_around_unrelated_new_content(self):
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("etc/lodeline/rule-packs.yaml", "packs")
        err = self.run_script()
        self.assertEqual(
            tree(self.root),
            {"etc/lodeline/policy.yaml": "policy", "etc/lodeline/rule-packs.yaml": "packs"},
        )
        self.assertIn("moved /etc/sigil to /etc/lodeline", err)

    def test_existing_new_entry_is_reported_and_the_rest_still_move(self):
        self.put("etc/sigil/policy.yaml", "old")
        self.put("etc/sigil/client.key", "key")
        self.put("etc/lodeline/policy.yaml", "new")
        err = self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "etc/lodeline/policy.yaml": "new",
                "etc/lodeline/client.key": "key",
                "etc/sigil/policy.yaml": "old",
            },
        )
        self.assertIn("kept in /etc/sigil: policy.yaml", err)
        self.assertNotIn("moved /etc/sigil", err)

    def test_db_at_both_paths_keeps_every_member_of_both(self):
        self.put("var/lib/sigil/state.db", "old db")
        self.put("var/lib/sigil/state.db-wal", "old wal")
        self.put("var/lib/sigil/state.db-shm", "old shm")
        self.put("var/lib/sigil/hook-baseline.json", "baseline")
        self.put("var/lib/lodeline/state.db", "fresh db")
        err = self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "var/lib/sigil/state.db": "old db",
                "var/lib/sigil/state.db-wal": "old wal",
                "var/lib/sigil/state.db-shm": "old shm",
                "var/lib/lodeline/state.db": "fresh db",
                "var/lib/lodeline/hook-baseline.json": "baseline",
            },
        )
        self.assertIn("kept in /var/lib/sigil: state.db.", err)

    def test_rerun_never_pairs_an_old_wal_with_a_db_already_at_the_new_path(self):
        self.put("var/lib/lodeline/state.db", "db")
        self.put("var/lib/sigil/state.db-wal", "wal")
        self.put("var/lib/sigil/hook-baseline.json", "baseline")
        err = self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "var/lib/lodeline/state.db": "db",
                "var/lib/lodeline/hook-baseline.json": "baseline",
                "var/lib/sigil/state.db-wal": "wal",
            },
        )
        self.assertIn("kept in /var/lib/sigil: state.db", err)
        self.assertNotIn("moved /var/lib/sigil", err)

    def test_rerun_after_a_crash_finishes_a_db_whose_wal_arrived_first(self):
        self.put("var/lib/lodeline/state.db-wal", "wal")
        self.put("var/lib/sigil/state.db-shm", "shm")
        self.put("var/lib/sigil/state.db", "db")
        err = self.run_script()
        self.assertEqual(
            tree(self.root),
            {
                "var/lib/lodeline/state.db": "db",
                "var/lib/lodeline/state.db-wal": "wal",
                "var/lib/lodeline/state.db-shm": "shm",
            },
        )
        self.assertIn("moved /var/lib/sigil", err)

    def test_interrupted_merge_then_rerun_keeps_real_sqlite_wal_data(self):
        old = self.root / "var/lib/sigil"
        new = self.root / "var/lib/lodeline"
        old.mkdir(parents=True)
        (new / "occupied").mkdir(parents=True)
        src = self.root / "live.db"
        live = sqlite3.connect(src)
        self.addCleanup(live.close)
        live.executescript(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
            "CREATE TABLE t(v); INSERT INTO t VALUES (1), (2), (3);"
        )
        self.assertGreater(Path(f"{src}-wal").stat().st_size, 0)
        for suffix in ("", "-wal"):
            shutil.copy(f"{src}{suffix}", old / f"state.db{suffix}")
        self.put("var/lib/sigil/hook-baseline.json", "baseline")
        src.rename(self.root / "elsewhere")

        self.stub_command("mv", 'case "$1" in *.db) exit 1 ;; *) exec /bin/mv "$@" ;; esac')
        err = self.run_script()
        self.assertTrue((new / "state.db-wal").exists(), "the wal goes first")
        self.assertTrue((old / "state.db").exists(), "the failed move left the db")
        self.assertIn("kept in /var/lib/sigil: state.db", err)
        self.assertNotIn("moved /var/lib/sigil", err)

        (self.stub / "mv").unlink()
        self.assertIn("moved /var/lib/sigil", self.run_script())
        self.assertFalse(old.exists())
        moved = sqlite3.connect(new / "state.db")
        self.addCleanup(moved.close)
        self.assertEqual(moved.execute("SELECT count(*) FROM t").fetchone(), (3,))
        self.assertEqual(moved.execute("PRAGMA integrity_check").fetchone(), ("ok",))

    def test_symlinked_old_dir_is_reported_and_left_alone(self):
        self.put("data/sigil/state.db", "db")
        (self.root / "var/lib").mkdir(parents=True)
        target = self.root / "data/sigil"
        (self.root / "var/lib/sigil").symlink_to(target)
        (self.root / "var/lib/lodeline").mkdir()
        for _ in range(2):
            err = self.run_script()
            self.assertIn(f"kept /var/lib/sigil: it is a symlink to {target}", err)
            self.assertIn("rmdir /var/lib/lodeline && mv /var/lib/sigil /var/lib/lodeline", err)
            self.assertIn("systemctl enable --now lodeline", err)
        self.assertEqual(os.readlink(self.root / "var/lib/sigil"), str(target))
        self.assertEqual((target / "state.db").read_text(), "db")
        self.assertEqual(list((self.root / "var/lib/lodeline").iterdir()), [])

    def test_manual_symlink_step_then_rerun_repairs_the_target(self):
        self.put("data/sigil/state.db", "db")
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "var/lib/lodeline").symlink_to(self.root / "data/sigil")
        self.accounts = ["sigil", "lodeline"]
        self.write_accounts()
        self.stub_command("find", "exit 0")
        self.assertEqual(self.run_script(), "")
        self.assertIn(f"find {self.root}/var/lib/lodeline/ -user sigil -exec chown -h lodeline {{}} +", self.finds())

    def test_new_path_with_only_packaged_examples_still_receives_config(self):
        self.put("etc/lodeline/policy.yaml.example", "new example")
        self.put("etc/sigil/policy.yaml.example", "old example")
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("etc/sigil/.hidden", "hidden")
        err = self.run_script()
        self.assertIn("moved /etc/sigil to /etc/lodeline", err)
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

    def test_shared_log_dir_waits_like_etc_for_a_running_old_sender(self):
        self.put("usr/bin/sigil-sender", "old sender")
        self.put("var/log/sigil/events-1.jsonl", "evt")
        self.put("var/log/sigil-sender/dead-letter/x", "dead")
        self.put("var/lib/sigil-sender/sender-offset.json", "offset")
        self.assertIn("kept /var/log/sigil: still used by sigil-sender", self.run_script())
        self.assertTrue((self.root / "var/log/sigil/events-1.jsonl").exists())

        (self.root / "usr/bin/sigil-sender").unlink()
        self.run_script("sender")
        self.assertEqual(
            tree(self.root),
            {
                "var/log/lodeline/events-1.jsonl": "evt",
                "var/log/lodeline-sender/dead-letter/x": "dead",
                "var/lib/lodeline-sender/sender-offset.json": "offset",
            },
        )

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

    def test_old_paths_in_config_are_reported_on_every_run_and_not_edited(self):
        body = "client_cert_path: /etc/sigil/client.crt\nagent_control: /var/run/sigil/control.sock\n"
        self.put("etc/sigil/sender.yaml", body)
        self.put("etc/sigil/host-allowlist.json", '{"events": "/var/log/sigil"}')
        self.put("etc/sigil/sender.yaml.example", body)
        for _ in range(2):
            err = self.run_script("sender")
            self.assertIn("/etc/lodeline/sender.yaml still names an old /sigil path", err)
            self.assertIn("/etc/lodeline/host-allowlist.json still names an old /sigil path", err)
            self.assertNotIn(".example", err)
        self.assertEqual((self.root / "etc/lodeline/sender.yaml").read_text(), body)

    def test_old_paths_are_reported_while_etc_sigil_waits(self):
        self.put("usr/bin/sigil-server", "old server")
        self.put("etc/sigil/sender.yaml", "offset_path: /var/lib/sigil-sender/o.json\n")
        err = self.run_script()
        self.assertIn("kept /etc/sigil", err)
        self.assertIn("/etc/sigil/sender.yaml still names an old /sigil path", err)

    def test_upgrade_output_names_the_enable_command_for_that_package(self):
        for component, unit, rel in (
            ("agent", "lodeline", "var/lib/sigil/state.db"),
            ("sender", "lodeline-sender", "var/lib/sigil-sender/o.json"),
            ("server", "lodeline-server", "var/lib/sigil-server/s.json"),
            ("proxy", "lodeline-proxy", "var/lib/sigil-proxy/spool.db"),
        ):
            self.put(rel, "x")
            self.assertTrue(self.run_script(component).rstrip().endswith(f"systemctl enable --now {unit}"))

    def write_accounts(self):
        lines = "".join(f"{a}:x:990:990::/:/bin/false\n" for a in self.accounts)
        self.put("etc/passwd", lines)
        self.put("etc/group", lines)

    def finds(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_owner_and_group_follow_the_rename_when_both_accounts_exist(self):
        self.accounts = ["sigil", "lodeline"]
        self.write_accounts()
        self.put("var/lib/sigil/state.db", "db")
        self.stub_command("find", "exit 0")
        self.run_script()
        new = self.root / "var/lib/lodeline"
        self.assertIn(f"find {new}/ -user sigil -exec chown -h lodeline {{}} +", self.finds())
        self.assertIn(f"find {new}/ -group sigil -exec chgrp -h lodeline {{}} +", self.finds())

    def test_ownership_is_repaired_by_a_rerun_after_a_crash_before_repair(self):
        self.accounts = ["sigil", "lodeline"]
        self.write_accounts()
        self.put("var/lib/lodeline/state.db", "db")
        self.stub_command("find", "exit 0")
        self.assertEqual(self.run_script(), "")
        self.assertIn(f"find {self.root}/var/lib/lodeline/ -user sigil -exec chown -h lodeline {{}} +", self.finds())

    def key_chown(self, old, new):
        return f"find {self.root}/etc/lodeline/ -user {old} -exec chown -h {new} {{}} +"

    def test_proxy_files_in_shared_etc_get_the_new_owner_when_agent_configures_first(self):
        self.put("etc/sigil/proxy/client.key", "key")
        self.stub_command("find", "exit 0")
        self.accounts = ["sigil", "sigil-proxy", "lodeline"]
        self.write_accounts()
        self.run_script("agent")
        self.assertNotIn(self.key_chown("sigil-proxy", "lodeline-proxy"), self.finds())

        self.accounts.append("lodeline-proxy")
        self.write_accounts()
        self.run_script("proxy")
        self.assertIn(self.key_chown("sigil-proxy", "lodeline-proxy"), self.finds())

    def test_agent_files_in_shared_etc_get_the_new_owner_when_proxy_configures_first(self):
        self.put("etc/sigil/client.key", "key")
        self.stub_command("find", "exit 0")
        self.accounts = ["sigil", "sigil-proxy", "lodeline-proxy"]
        self.write_accounts()
        self.run_script("proxy")
        self.assertIn(self.key_chown("sigil-proxy", "lodeline-proxy"), self.finds())
        self.assertNotIn(self.key_chown("sigil", "lodeline"), self.finds())

        self.accounts.append("lodeline")
        self.write_accounts()
        self.run_script("agent")
        self.assertIn(self.key_chown("sigil", "lodeline"), self.finds())

    def test_unknown_component_is_rejected(self):
        result = subprocess.run(["sh", str(SCRIPT), "signer"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
