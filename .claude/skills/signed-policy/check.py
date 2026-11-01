#!/usr/bin/env python3
"""Run the signed-policy formal verification. See SKILL.md.

  check.py            drift check, every model config, every mutant
  check.py --model    model configs only, for use while editing the model
  check.py --drift    drift check only
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

SKILL = Path(__file__).resolve().parent
ROOT = SKILL.parents[2]
SPEC_DIR = SKILL / "spec"
MODULE = "SignedPolicy"
CONFIGS = ["concurrent", "gap", "serial"]

TLC_VERSION = "1.7.4"
TLC_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLC_URL = f"https://github.com/tlaplus/tlaplus/releases/download/v{TLC_VERSION}/tla2tools.jar"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "lodeline-formal"
JAVA_HELP = """No working Java runtime found. TLC needs Java 11 or later.
  macOS:  HOMEBREW_NO_AUTO_UPDATE=1 brew install --ignore-dependencies openjdk@21
  Debian: sudo apt-get install openjdk-21-jre-headless
Or set JAVA_HOME."""

GOOD = '    /\\ e.auth = "good"\n'
EXPIRY = "    /\\ clock < e.until\n"
VERSION = "    /\\ e.v > watermark\n"
WRITE_EFFECT = "/\\ disk' = msg[w]"
BUMP_EFFECT = "/\\ watermark' = msg[w].v"
WRITE_FRAME = "UNCHANGED <<watermark, clock, up, msg, at, notified, live, crashes>>"
BUMP_FRAME = "UNCHANGED <<disk, clock, up, msg, at, notified, live, crashes>>"

# (name, code it stands for, config, property it must break, edits).
# An edit is (old, new), or (a, b, "swap") to exchange two strings.
MUTANTS = [
    ("no signature check", "verify_envelope check 2", "serial", "OnlySignedAccepted", [(GOOD, "")]),
    ("no expiry check", "verify_envelope check 3", "serial", "NoExpiredApplied", [(EXPIRY, "")]),
    ("no version check", "verify_envelope check 4", "serial", "NoRollback", [(VERSION, "")]),
    ("no version check", "verify_envelope check 4", "serial", "WatermarkMonotonic", [(VERSION, "")]),
    (
        "watermark before rename",
        "atomic_write step order",
        "gap",
        "WatermarkNeverAhead",
        [(WRITE_EFFECT, BUMP_EFFECT, "swap"), (WRITE_FRAME, BUMP_FRAME, "swap")],
    ),
    (
        "reload not notified",
        "apply policy_version_tx.send",
        "serial",
        "LiveMatchesDisk",
        [("/\\ notified' = TRUE\n", "/\\ notified' = FALSE\n")],
    ),
]


def fail(message):
    sys.exit(f"check.py: {message}")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tlc_jar():
    jar = CACHE / f"tla2tools-{TLC_VERSION}.jar"
    if not jar.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        print(f"Download TLC {TLC_VERSION} to {jar}", flush=True)
        tmp = jar.with_suffix(".part")
        urllib.request.urlretrieve(TLC_URL, tmp)
        tmp.rename(jar)
    if sha256(jar) != TLC_SHA256:
        fail(f"{jar} does not match the pinned SHA-256. Delete it and retry.")
    return jar


def works(java):
    try:
        return subprocess.run([java, "-version"], capture_output=True).returncode == 0
    except OSError:
        return False


def java_binary():
    candidates = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(str(Path(os.environ["JAVA_HOME"]) / "bin" / "java"))
    if shutil.which("brew"):
        prefix = subprocess.run(
            ["brew", "--prefix", "openjdk@21"], capture_output=True, text=True
        ).stdout.strip()
        if prefix:
            candidates.append(f"{prefix}/bin/java")
    if shutil.which("java"):
        candidates.append(shutil.which("java"))
    for candidate in candidates:
        if works(candidate):
            return candidate
    fail(JAVA_HELP)


def run_tlc(java, jar, spec_text, config_text):
    """Run TLC in a temp directory, so no state or trace file lands in the repo."""
    with tempfile.TemporaryDirectory(prefix="lodeline-formal-") as work:
        work = Path(work)
        (work / f"{MODULE}.tla").write_text(spec_text)
        (work / "run.cfg").write_text(config_text)
        started = time.monotonic()
        proc = subprocess.run(
            [java, "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "auto",
             "-deadlock", "-difftrace", "-metadir", str(work / "states"),
             "-config", "run.cfg", f"{MODULE}.tla"],
            cwd=work, capture_output=True, text=True,
        )
        return proc.stdout + proc.stderr, time.monotonic() - started


def counts(output):
    found = re.search(r"([\d,]+) states generated, ([\d,]+) distinct states found", output)
    return f"{found.group(2)} distinct states" if found else "no state count"


def check_configs(java, jar):
    spec = (SPEC_DIR / f"{MODULE}.tla").read_text()
    ok = True
    for name in CONFIGS:
        output, seconds = run_tlc(java, jar, spec, (SPEC_DIR / f"{name}.cfg").read_text())
        if "Model checking completed. No error has been found." in output:
            print(f"PASS {name}: {counts(output)} in {seconds:.1f}s", flush=True)
        else:
            ok = False
            print(f"FAIL {name}: TLC reported a violation or error\n{output}", flush=True)
    return ok


def replace_once(text, old, new):
    if text.count(old) != 1:
        fail(f"mutant edit must match once, found {text.count(old)}: {old!r}")
    return text.replace(old, new)


def mutate(spec, edits):
    for edit in edits:
        old, new, *swap = edit
        if swap:
            spec = replace_once(spec, old, "@@HOLD@@")
            spec = replace_once(spec, new, old)
            spec = spec.replace("@@HOLD@@", new)
        else:
            spec = replace_once(spec, old, new)
    return spec


def only_property(config_text, prop):
    """Keep the constants. Check one property, so the failure names that property."""
    constants = config_text.split("INVARIANTS")[0]
    keyword = "PROPERTIES" if prop in ("NoRollback", "WatermarkMonotonic") else "INVARIANTS"
    return f"{constants}{keyword}\n    {prop}\n"


def check_mutants(java, jar):
    spec = (SPEC_DIR / f"{MODULE}.tla").read_text()
    ok = True
    for name, code, config, prop, edits in MUTANTS:
        text = only_property((SPEC_DIR / f"{config}.cfg").read_text(), prop)
        output, seconds = run_tlc(java, jar, mutate(spec, edits), text)
        caught = f"Invariant {prop} is violated." in output or f"Action property {prop} is violated." in output
        print(f"{'KILLED' if caught else 'SURVIVED'} {name} ({code}): {prop}, {seconds:.1f}s", flush=True)
        ok = ok and caught
    return ok


def coverage():
    """Read the sync commit and the coverage table from SKILL.md."""
    text = (SKILL / "SKILL.md").read_text()
    sync = re.search(r"^Sync commit: `([0-9a-f]{40})`", text, re.M)
    if not sync:
        fail("SKILL.md has no `Sync commit:` line")
    rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|$", text, re.M)
    if not rows:
        fail("SKILL.md has no coverage rows")
    return sync.group(1), rows


def function_text(source, name):
    """rustfmt puts a function's closing brace at the indent of its `fn`."""
    lines = source.splitlines()
    for start, line in enumerate(lines):
        found = re.match(rf"^(\s*)(pub(\(\w+\))? )?(async )?fn {re.escape(name)}\b", line)
        if found:
            close = found.group(1) + "}"
            for end in range(start, len(lines)):
                if lines[end] == close:
                    return "\n".join(lines[start:end + 1])
    return None


def check_drift():
    sync, rows = coverage()
    ok = True
    for element, path, function in rows:
        old = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{sync}:{path}"], capture_output=True, text=True
        )
        if old.returncode != 0:
            fail(f"cannot read {path} at {sync}: {old.stderr.strip()}")
        current = ROOT / path
        now = function_text(current.read_text(), function) if current.exists() else None
        before = function_text(old.stdout, function)
        if before is None:
            fail(f"{function} is not in {path} at {sync}")
        if now != before:
            ok = False
            print(f"DRIFT {path} {function} changed since the sync commit. Model element: {element}")
    print("Drift check clean." if ok else "Drift found. Follow `Resolve a DRIFT line` in SKILL.md.")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--model", action="store_true")
    parser.add_argument("--drift", action="store_true")
    args = parser.parse_args()
    started = time.monotonic()
    ok = True
    if not args.model:
        ok = check_drift() and ok
    if not args.drift:
        java, jar = java_binary(), tlc_jar()
        ok = check_configs(java, jar) and ok
        if not args.model:
            ok = check_mutants(java, jar) and ok
    print(f"{'OK' if ok else 'FAILED'} in {time.monotonic() - started:.1f}s")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
