"""Build the fixed Linux collector and install it on new or existing hosts.

Builds use a committed source snapshot, so changes in the Fluent Bit working tree
do not affect the installer. The cached binary is checked before each reuse.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REVISION = "3c25db66ce6b47ee118f271dcccc986be8cba2b6"
BINARY_PATH = Path("usr/local/libexec/security-spectrum") / f"fluent-bit-{REVISION[:9]}"
UNIT_PATH = Path("etc/systemd/system/fluent-bit.service")
DROPIN_PATH = Path("etc/systemd/system/fluent-bit.service.d/20-security-spectrum-local.conf")
CMAKE_OPTIONS = [
    "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_STANDARD=11",
    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DFLB_MINIMAL=On",
    "-DFLB_EXAMPLES=Off", "-DFLB_SHARED_LIB=Off",
    "-DFLB_TESTS_RUNTIME=Off", "-DFLB_TESTS_INTERNAL=Off",
    "-DFLB_WASM=Off", "-DFLB_LUAJIT=Off", "-DFLB_TLS=On",
    "-DFLB_IN_TAIL=On", "-DFLB_IN_DUMMY=On",
    "-DFLB_FILTER_ENCRYPT=On", "-DFLB_FILTER_MODIFY=On",
    "-DFLB_OUT_KAFKA=On", "-DFLB_OUT_STDOUT=On", "-DFLB_OUT_NULL=On",
]


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_binary(binary):
    if platform.system() != "Linux":
        raise RuntimeError("The local collector build currently supports Linux")
    binary = Path(binary).expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Collector binary is missing or not executable: {binary}")
    result = subprocess.run([str(binary), "--help"], capture_output=True, text=True, timeout=15)
    required = ("tail", "dummy", "encrypt", "modify", "kafka", "stdout", "null")
    if result.returncode or any(not re.search(r"^\s*" + name + r"\s+", result.stdout, re.MULTILINE)
                                for name in required):
        raise RuntimeError("Collector does not run or lacks required input, filter, or output plugins")
    return binary


def check_source(repo):
    if platform.system() != "Linux":
        raise RuntimeError("The local collector build currently supports Linux")
    if not shutil.which("git"):
        raise RuntimeError("Install Git before preparing the local collector")
    result = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", REVISION + "^{commit}"],
                            capture_output=True)
    if result.returncode:
        raise RuntimeError(f"SS_FLUENT_BIT_SOURCE must point to a Fluent Bit checkout containing {REVISION[:9]}")


def build_collector(repo, cache_root=None):
    repo = Path(repo).expanduser().resolve()
    check_source(repo)
    cache_root = Path(cache_root or os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")).expanduser().resolve()
    base = cache_root / "security-spectrum" / f"fluent-bit-{REVISION[:9]}-{platform.machine()}"
    binary = base / "build/bin/fluent-bit"
    manifest = base / "build.json"
    identity = {"revision": REVISION, "architecture": platform.machine(), "options": CMAKE_OPTIONS}
    if binary.is_file() and manifest.is_file():
        try:
            if json.loads(manifest.read_text()) == {**identity, "sha256": digest(binary)}:
                return validate_binary(binary)
        except (ValueError, OSError, RuntimeError):
            pass
    missing = [name for name in ("cmake", "make", "cc", "c++", "flex", "bison", "tar")
               if not shutil.which(name)]
    if missing:
        raise RuntimeError("Install collector build prerequisites first; missing: " + ", ".join(missing))
    source = base / "source"
    source.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(["git", "-C", str(repo), "archive", REVISION], stdout=subprocess.PIPE)
    try:
        extract = subprocess.run(["tar", "-x", "-C", str(source)], stdin=archive.stdout)
    finally:
        archive.stdout.close()
    if archive.wait() or extract.returncode:
        raise RuntimeError("Could not prepare the committed collector source")
    log_path = base / "build.log"
    print(f"Building fixed collector {REVISION[:9]}; log: {log_path}", file=sys.stderr)
    with log_path.open("w") as log:
        commands = [
            ["cmake", "-S", str(source), "-B", str(base / "build"), *CMAKE_OPTIONS],
            ["cmake", "--build", str(base / "build"), "--target", "fluent-bit-bin",
             "-j", str(min(8, os.cpu_count() or 1))],
        ]
        for command in commands:
            if subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError(f"Collector build failed; inspect {log_path}")
    validate_binary(binary)
    manifest.write_text(json.dumps({**identity, "sha256": digest(binary)}, indent=2) + "\n")
    return binary


def install_collector(binary, root=Path("/")):
    """Write installation files; root may be a staging directory for validation."""
    binary = validate_binary(binary)
    target = root / BINARY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    # Replace atomically: the previous collector may still be running.
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        shutil.copyfile(binary, temporary_path)
        temporary_path.chmod(0o755)
        temporary_path.replace(target)
    finally:
        temporary_path.unlink(missing_ok=True)
    unit = root / UNIT_PATH
    existing = (unit, root / "usr/lib/systemd/system/fluent-bit.service",
                root / "lib/systemd/system/fluent-bit.service")
    if not any(path.exists() for path in existing):
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Unit]\nDescription=Security Spectrum Fluent Bit\nAfter=network.target\n"
                        "[Service]\nType=simple\nRestart=always\nRestartSec=3\n"
                        f"ExecStart=/{BINARY_PATH} -c /etc/fluent-bit/fluent-bit.conf\n"
                        "[Install]\nWantedBy=multi-user.target\n")
        unit.chmod(0o644)
    dropin = root / DROPIN_PATH
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(f"[Service]\nExecStart=\nExecStart=/{BINARY_PATH} -c /etc/fluent-bit/fluent-bit.conf\n")
    dropin.chmod(0o644)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "build"))
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "check":
            check_source(args.source)
        else:
            print(build_collector(args.source))
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
