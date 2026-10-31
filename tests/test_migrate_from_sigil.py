import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "packaging" / "migrate-from-sigil.sh"
SHELL = os.environ.get("MIGRATE_SHELL", "sh")


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

    def spawn(self, *args):
        env = dict(os.environ, PATH=f"{self.stub}:{os.environ['PATH']}")
        return subprocess.run([SHELL, str(SCRIPT), *args], capture_output=True, text=True, env=env)

    def run_script(self, component="agent"):
        result = self.spawn(component, "--root", str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stderr

    def dpkg_has(self, **packages):
        """Package name with `_` for `-`, mapped to a `<dpkg status> <version>` row."""
        self.put("var/lib/dpkg/status", "")
        rows = "".join(f'{name.replace("_", "-")}) echo "{row}" ;; ' for name, row in packages.items())
        self.stub_command("dpkg-query", f'for last; do :; done\ncase "$last" in {rows}*) exit 1 ;; esac')

    def rpm_has(self, **packages):
        (self.root / "var/lib/rpm").mkdir(parents=True, exist_ok=True)
        rows = "".join(f'{name.replace("_", "-")}) echo "{v}" ;; ' for name, v in packages.items())
        self.stub_command(
            "rpm", f'for last; do :; done\ncase "$last" in {rows}*) echo "package $last is not installed"; exit 1 ;; esac'
        )

    def split_filesystems(self):
        self.stub_command(
            "df",
            'case "$2" in */lodeline*) dev=/dev/new ;; *) dev=/dev/old ;; esac\n'
            'echo "Filesystem 512-blocks Used Available Capacity Mounted on"\n'
            'echo "$dev 100 1 99 1% /$dev"',
        )

    def swap_command_from(self, err):
        command = re.search(r"run: (mkdir -p .*?)\. Then rerun", err).group(1)
        return re.sub(r"(?<= )/(?=etc|var)", f"{self.root}/", command)

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
            self.assertIn(
                "mkdir -p /var/lib/lodeline && rm -f /var/lib/lodeline/*.example"
                " && rmdir /var/lib/lodeline && mv /var/lib/sigil /var/lib/lodeline",
                err,
            )
            self.assertIn("systemctl enable --now lodeline", err)
        self.assertEqual(os.readlink(self.root / "var/lib/sigil"), str(target))
        self.assertEqual((target / "state.db").read_text(), "db")
        self.assertEqual(list((self.root / "var/lib/lodeline").iterdir()), [])

    def test_printed_symlink_command_works_on_every_state_of_the_new_dir(self):
        target = self.root / "data/sigil"
        new = self.root / "etc/lodeline"
        for prepare in (lambda: None, lambda: self.put("etc/lodeline/policy.yaml.example"), new.mkdir):
            self.put("data/sigil/policy.yaml", "policy")
            (self.root / "etc").mkdir(exist_ok=True)
            (self.root / "etc/sigil").symlink_to(target)
            prepare()
            command = self.swap_command_from(self.run_script())
            subprocess.run([SHELL, "-c", command], check=True)
            self.assertEqual(os.readlink(new), str(target))
            self.assertEqual((new / "policy.yaml").read_text(), "policy")
            self.assertFalse((self.root / "etc/sigil").is_symlink())
            new.unlink()

    def test_printed_symlink_command_stops_when_the_new_dir_holds_real_data(self):
        self.put("data/sigil/policy.yaml", "old")
        self.put("etc/lodeline/policy.yaml", "new")
        (self.root / "etc/sigil").symlink_to(self.root / "data/sigil")
        command = self.swap_command_from(self.run_script())
        self.assertNotEqual(subprocess.run([SHELL, "-c", command], capture_output=True).returncode, 0)
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "new")
        self.assertTrue((self.root / "etc/sigil").is_symlink())

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

    def test_entries_whose_names_start_with_two_dots_move(self):
        self.put("etc/sigil/..secret", "s")
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("etc/lodeline/rule-packs.yaml", "packs")
        self.assertIn("moved /etc/sigil to /etc/lodeline", self.run_script())
        self.assertEqual((self.root / "etc/lodeline/..secret").read_text(), "s")
        self.assertFalse((self.root / "etc/sigil").exists())

    def test_only_two_dot_entry_still_counts_as_content(self):
        self.put("etc/sigil/..secret", "s")
        self.run_script()
        self.assertEqual(tree(self.root), {"etc/lodeline/..secret": "s"})

    def test_a_kept_name_with_a_space_does_not_hide_a_sibling(self):
        for name in ("a b", "b"):
            self.put(f"etc/sigil/{name}", "old")
            self.put(f"etc/lodeline/{name}", "new")
        self.put("etc/sigil/c", "c")
        err = self.run_script()
        self.assertIn("kept in /etc/sigil: a b, b.", err)
        self.assertEqual((self.root / "etc/lodeline/c").read_text(), "c")

    def test_a_name_that_only_looks_like_a_sidecar_moves(self):
        self.put("var/lib/sigil/x-shm-wal", "1")
        self.put("var/lib/sigil/-wal", "2")
        self.put("var/lib/lodeline/occupied", "new")
        self.assertIn("moved /var/lib/sigil", self.run_script())
        self.assertEqual(
            tree(self.root),
            {"var/lib/lodeline/x-shm-wal": "1", "var/lib/lodeline/-wal": "2", "var/lib/lodeline/occupied": "new"},
        )

    def cross_filesystem_setup(self):
        old = self.root / "var/lib/sigil"
        old.mkdir(parents=True)
        self.put("var/lib/lodeline/occupied", "new")
        self.put("var/lib/sigil/config-dir/nested.json", "nested")
        src = self.root / "live.db"
        live = sqlite3.connect(src)
        self.addCleanup(live.close)
        live.executescript(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
            "CREATE TABLE t(v); INSERT INTO t VALUES (1), (2), (3);"
        )
        for suffix in ("", "-wal"):
            shutil.copy(f"{src}{suffix}", old / f"state.db{suffix}")
        src.rename(self.root / "elsewhere")
        self.split_filesystems()
        return old, self.root / "var/lib/lodeline"

    def test_cross_filesystem_move_lands_each_entry_whole(self):
        old, new = self.cross_filesystem_setup()
        self.assertIn("moved /var/lib/sigil", self.run_script())
        self.assertFalse(old.exists())
        self.assertEqual((new / "config-dir/nested.json").read_text(), "nested")
        self.assertEqual(sorted(p.name for p in new.iterdir() if "tmp" in p.name), [])
        moved = sqlite3.connect(new / "state.db")
        self.addCleanup(moved.close)
        self.assertEqual(moved.execute("SELECT count(*) FROM t").fetchone(), (3,))

    def test_killed_cross_filesystem_copy_never_shows_a_partial_db(self):
        old, new = self.cross_filesystem_setup()
        whole = (old / "state.db").read_bytes()
        self.stub_command(
            "cp", 'case "$2" in *.db) head -c 100 "$2" > "$3"; kill -9 $PPID ;; *) exec /bin/cp "$@" ;; esac'
        )
        killed = self.spawn("agent", "--root", str(self.root))
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertFalse((new / "state.db").exists(), "no partial file under the real name")
        self.assertEqual((new / "state.db.lodeline-migrate-tmp").stat().st_size, 100)
        self.assertEqual((old / "state.db").read_bytes(), whole)

        (self.stub / "cp").unlink()
        self.assertIn("moved /var/lib/sigil", self.run_script())
        self.assertFalse(old.exists())
        self.assertFalse((new / "state.db.lodeline-migrate-tmp").exists())
        moved = sqlite3.connect(new / "state.db")
        self.addCleanup(moved.close)
        self.assertEqual(moved.execute("SELECT count(*) FROM t").fetchone(), (3,))
        self.assertEqual(moved.execute("PRAGMA integrity_check").fetchone(), ("ok",))

    def test_rerun_replaces_a_stale_temporary_directory(self):
        _, new = self.cross_filesystem_setup()
        self.put("var/lib/lodeline/config-dir.lodeline-migrate-tmp/partial", "stale")
        self.run_script()
        self.assertEqual(sorted(p.name for p in (new / "config-dir").iterdir()), ["nested.json"])
        self.assertFalse((new / "config-dir.lodeline-migrate-tmp").exists())

    def test_failed_cross_filesystem_copy_leaves_the_source_and_reports_it(self):
        old, new = self.cross_filesystem_setup()
        self.stub_command("cp", 'case "$2" in *.db) : > "$3"; exit 1 ;; *) exec /bin/cp "$@" ;; esac')
        err = self.run_script()
        self.assertIn("kept in /var/lib/sigil: state.db", err)
        self.assertNotIn("moved /var/lib/sigil", err)
        self.assertTrue((old / "state.db").exists())
        self.assertEqual([p.name for p in new.iterdir() if "state.db." in p.name], [])

    def test_shared_etc_waits_for_other_old_packages(self):
        self.dpkg_has(sigil="installed 0.11.0")
        self.put("etc/sigil/policy.yaml", "policy")
        self.put("var/lib/sigil-proxy/spool.db", "spool")
        err = self.run_script("proxy")
        self.assertIn("still used by sigil", err)
        self.assertTrue((self.root / "etc/sigil/policy.yaml").exists())
        self.assertTrue((self.root / "var/lib/lodeline-proxy/spool.db").exists())

        self.dpkg_has(sigil="config-files 0.11.0")
        self.run_script("proxy")
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")

    def test_shared_log_dir_waits_like_etc_for_a_running_old_sender(self):
        self.rpm_has(sigil_sender="0.11.0")
        self.put("var/log/sigil/events-1.jsonl", "evt")
        self.put("var/log/sigil-sender/dead-letter/x", "dead")
        self.put("var/lib/sigil-sender/sender-offset.json", "offset")
        self.assertIn("kept /var/log/sigil: still used by sigil-sender", self.run_script())
        self.assertTrue((self.root / "var/log/sigil/events-1.jsonl").exists())

        self.rpm_has()
        self.run_script("sender")
        self.assertEqual(
            tree(self.root),
            {
                "var/log/lodeline/events-1.jsonl": "evt",
                "var/log/lodeline-sender/dead-letter/x": "dead",
                "var/lib/lodeline-sender/sender-offset.json": "offset",
            },
        )

    def test_an_unrelated_sigil_binary_with_no_package_holds_nothing_back(self):
        self.dpkg_has()
        self.put("usr/bin/sigil", "NOMARJ/sigil")
        self.put("etc/sigil/policy.yaml", "policy")
        self.run_script()
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")

    def test_the_ebook_editor_package_holds_nothing_back(self):
        for version in ("1.4.3+dfsg-1", "2.4.2+dfsg-1+b2"):
            self.dpkg_has(sigil=f"installed {version}")
            self.put("etc/sigil/policy.yaml", "policy")
            self.put("usr/bin/sigil", "ebook editor")
            self.run_script()
            self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")
            shutil.rmtree(self.root / "etc/lodeline")

        self.rpm_has(sigil="2.8.1")
        self.put("etc/sigil/policy.yaml", "policy")
        (self.root / "var/lib/dpkg/status").unlink()
        self.run_script()
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")

    def test_old_versions_wait_and_the_first_new_version_does_not(self):
        for version, waits in (
            ("0.11.0", True),
            ("0.9.1-1", True),
            ("0.1", True),
            ("0.11.0~rc.1", True),
            ("0.12.0", False),
            ("0.120.0", False),
            ("10.1.0", False),
        ):
            self.dpkg_has(sigil_server=f"unpacked {version}")
            self.put("etc/sigil/policy.yaml", "policy")
            err = self.run_script()
            self.assertEqual("still used by sigil-server" in err, waits, version)
            shutil.rmtree(self.root / "etc/lodeline", ignore_errors=True)

    def test_without_a_package_database_a_binary_keeps_shared_dirs_and_the_note_says_why(self):
        self.put("usr/bin/sigil", "unknown")
        self.put("etc/lodeline/policy.yaml.example", "example")
        self.put("etc/sigil/policy.yaml", "policy")
        err = self.run_script()
        self.assertIn("no package database here", err)
        self.assertTrue((self.root / "etc/sigil/policy.yaml").exists())
        subprocess.run([SHELL, "-c", self.swap_command_from(err)], check=True)
        self.assertEqual((self.root / "etc/lodeline/policy.yaml").read_text(), "policy")

    def test_without_a_package_database_or_a_binary_shared_dirs_move(self):
        self.put("etc/sigil/policy.yaml", "policy")
        self.run_script()
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
        self.dpkg_has(sigil_server="installed 0.11.0")
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

    def test_repair_is_skipped_with_a_note_when_the_new_account_is_missing(self):
        self.accounts = ["sigil"]
        self.write_accounts()
        self.put("var/lib/sigil/state.db", "db")
        self.stub_command("find", "exit 0")
        err = self.run_script()
        self.assertEqual(err.count("skipped repairing ownership from sigil to lodeline"), 2)
        self.assertEqual([c for c in self.finds() if c.startswith("find")], [])

    def test_repair_is_skipped_with_a_note_when_the_old_account_stopped_resolving(self):
        self.accounts = ["lodeline"]
        self.write_accounts()
        self.put("var/lib/sigil/state.db", "db")
        self.assertIn("skipped repairing ownership from sigil to lodeline", self.run_script())

    def test_a_fresh_install_prints_nothing_about_accounts(self):
        self.accounts = ["lodeline"]
        self.write_accounts()
        self.assertEqual(self.run_script(), "")

    def test_accounts_come_from_getent_on_a_real_host_and_from_files_under_root(self):
        self.stub_command("getent", 'case "$2" in sigil) exit 0 ;; *) exit 2 ;; esac')
        err = self.spawn("agent").stderr
        self.assertIn("getent passwd sigil", self.finds())
        self.assertIn("getent group lodeline", self.finds())
        self.assertIn("skipped repairing ownership from sigil to lodeline", err)

        self.calls.unlink()
        self.run_script()
        self.assertFalse(self.calls.exists())

    def test_unknown_component_is_rejected(self):
        result = subprocess.run([SHELL, str(SCRIPT), "signer"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


class PackageRelationsTest(unittest.TestCase):
    def relations(self, crate):
        text = (REPO / "crates" / crate / "Cargo.toml").read_text()
        return re.findall(r"(?m)^(conflicts|replaces|provides|obsoletes) = (.*)$", text)

    def test_old_names_are_bounded_and_the_bare_name_is_not_provided(self):
        for crate, old in (
            ("lodeline-agent", "sigil"),
            ("lodeline-sender", "sigil-sender"),
            ("lodeline-server", "sigil-server"),
            ("lodeline-signer", "sigil-signer"),
            ("lodeline-proxy", "sigil-proxy"),
        ):
            found = self.relations(crate)
            self.assertIn(("conflicts", f'"{old} (<< 0.12)"'), found)
            self.assertIn(("replaces", f'"{old} (<< 0.12)"'), found)
            self.assertIn(("obsoletes", f'{{ "{old}" = "< 0.12" }}'), found)
            provided = [value for field, value in found if field == "provides"]
            self.assertEqual(provided, [] if old == "sigil" else [f'"{old}"', f'{{ "{old}" = "*" }}'])


if __name__ == "__main__":
    unittest.main()
