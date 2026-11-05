#!/usr/bin/env python3
"""Runs only through offline-smoke.sh on an explicitly marked disposable VM.

This is a smoke fixture, not the full failure/WireGuard/release matrix. It never
restores or flushes host networking, scans user files, or deletes prefix matches.
"""

import errno
import fcntl
import glob
import json
import os
import pathlib
import pty
import select
import socket
import struct
import subprocess
import tempfile
import termios
import time


BINARY = "/usr/bin/soteria"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(arguments, *, data=None, environment=None, expected=0):
    result = subprocess.run(arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=120, check=False)
    require(result.returncode == expected, "fixture command failed (status %d, expected %d); review local, synthetic-only stderr: %s" % (result.returncode, expected, result.stderr[-4096:].decode(errors="replace")))
    return result.stdout


def normalize_counters(value):
    if isinstance(value, dict):
        return {key: ({} if key == "counter" else normalize_counters(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [normalize_counters(child) for child in value]
    return value


def network_snapshot():
    snapshot = {}
    for key, args in (
        ("links", ["/usr/bin/ip", "-json", "link", "show"]),
        ("ipv4_routes", ["/usr/bin/ip", "-json", "-4", "route", "show", "table", "all"]),
        ("ipv6_routes", ["/usr/bin/ip", "-json", "-6", "route", "show", "table", "all"]),
        ("firewall", ["/usr/bin/sudo", "-n", "/usr/sbin/nft", "--json", "list", "ruleset"]),
    ):
        snapshot[key] = normalize_counters(json.loads(command(args)))
    snapshot["iptables"] = [line for line in command(["/usr/bin/sudo", "-n", "/usr/sbin/iptables-save"]).decode().splitlines() if not line.startswith("#")]
    snapshot["resolver"] = pathlib.Path("/etc/resolv.conf").read_bytes().hex()
    snapshot["resolver_target"] = os.path.realpath("/etc/resolv.conf")
    for name in ("net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding", "net/ipv6/conf/all/disable_ipv6"):
        snapshot[name] = pathlib.Path("/proc/sys/" + name).read_text()
    return snapshot


def resources():
    units = command(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "soteria-*.service"]).decode().splitlines()
    return {
        "units": sorted(line.strip() for line in units if line.strip()),
        "runtime_names": sorted(glob.glob("/run/soteria-*")),
        "cgroups": sorted(glob.glob("/sys/fs/cgroup/system.slice/soteria-*.service")),
    }


def terminal_probe(config):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 97, 0, 0))

    def acquire_terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    child = subprocess.Popen([BINARY, "shell", "--config", str(config), "--network=offline"], stdin=slave, stdout=slave, stderr=slave, preexec_fn=acquire_terminal, close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + 90

    def read_until(marker):
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.2)
            if readable:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    break
            if marker in output:
                return
            if child.poll() is not None:
                break
        raise AssertionError("PTY fixture did not reach its synthetic marker")

    try:
        os.write(master, b"printf 'SOTERIA_%s_%s\\n' TTY READY; sleep 30\n")
        read_until(b"SOTERIA_TTY_READY")
        time.sleep(0.2)  # allow the foreground sleep to acquire its process group
        os.write(master, b"\x03")
        os.write(master, b"printf 'SOTERIA_%s_%s\\n' TTY RESTORED; stty size; exit 0\n")
        read_until(b"SOTERIA_TTY_RESTORED")
        while child.poll() is None and time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
        require(child.poll() == 0, "interactive shell failed or did not exit within the deadline")
        require(b"33 97" in output, "terminal dimensions did not reach the workload")
        require(termios.tcgetattr(slave) == before, "frontend did not restore its caller terminal")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=20)
        os.close(master)
        os.close(slave)


def main():
    require(os.environ.get("SOTERIA_DISPOSABLE_VM") == "DISPOSABLE_VM_ONLY" and os.geteuid() != 0, "use the VM-guarded shell entrypoint")
    # Direct Python invocation must not bypass the same VM/marker/identity guard.
    wrapper = pathlib.Path(__file__).resolve().with_suffix(".sh")
    command(["/usr/bin/bash", str(wrapper), "--preflight-only"])
    os_release = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            os_release[key] = value.strip('"')
    actual = {("debian", "13"): "debian13-amd64", ("ubuntu", "24.04"): "ubuntu24.04-amd64"}.get((os_release.get("ID", ""), os_release.get("VERSION_ID", "")))
    require(actual == os.environ.get("SOTERIA_VM_TARGET"), "VM distro does not match the selected target")
    before_resources = resources()
    require(not any(before_resources.values()), "fixture requires a fresh VM without previous Soteria resources")
    before_network = network_snapshot()
    version = command([BINARY, "version"]).decode().strip()
    require("commit: " + os.environ["SOTERIA_EXPECTED_COMMIT"] in version, "installed binary does not identify the selected candidate commit")
    manifest = pathlib.Path("/usr/lib/soteria/runtime/.soteria-manifest.json")
    require(manifest.stat().st_size <= 16 * 1024 * 1024, "installed inventory exceeds its bound")
    runtime_digest = json.loads(manifest.read_bytes())["digest"]
    fixture = pathlib.Path(__file__).resolve().with_name("workload-probe.py")
    with tempfile.TemporaryDirectory(prefix="soteria-smoke-", dir="/dev/shm") as temporary:
        work = pathlib.Path(temporary)
        config = work / "fixture-config.json"
        config.write_text('{"version":1}\n')
        run = [BINARY, "run", "--config", str(config), "--network=offline"]
        json.loads(command([BINARY, "doctor", "--json", "--config", str(config)]))
        sentinel = work / "host-sentinel"
        sentinel.write_text("synthetic host sentinel, not a credential\n")
        source = work / "smoke-input.txt"
        source.write_text("public synthetic fixture\n")
        exported = work / "exported"
        exported.mkdir()
        failed_exports = work / "failed-exports"
        failed_exports.mkdir()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as fake_agent:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            fake_agent.bind(str(work / "fake-agent.sock"))
            fake_agent.listen(1)
            ipv6_listener = None
            try:
                ipv6_listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                ipv6_listener.bind(("::1", 0))
                ipv6_listener.listen(1)
            except OSError:
                if ipv6_listener is not None:
                    ipv6_listener.close()
                ipv6_listener = None
            try:
                addresses = json.loads(command(["/usr/bin/ip", "-json", "-4", "address", "show"]))
                expected = {
                    "uid": os.getuid(), "gid": os.getgid(),
                    "host_paths": [str(sentinel), str(work / "fake-agent.sock")],
                    "namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("mnt", "pid", "net", "ipc", "uts")},
                    "loopback_port": listener.getsockname()[1],
                    "ipv6_port": ipv6_listener.getsockname()[1] if ipv6_listener else None,
                    "host_ipv4": [address["local"] for interface in addresses for address in interface.get("addr_info", []) if address["scope"] != "host"],
                }
                environment = dict(os.environ, SOTERIA_SMOKE_SECRET="synthetic-not-a-secret", AWS_SECRET_ACCESS_KEY="synthetic-not-a-secret", SSH_AUTH_SOCK=str(work / "fake-agent.sock"), DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent-synthetic-socket")
                command(run + ["--import", str(fixture), "--import", str(source), "--export", str(exported), "--", "python3", "/work/in/workload-probe.py", json.dumps(expected)], environment=environment)
            finally:
                if ipv6_listener is not None:
                    ipv6_listener.close()
        result = json.loads(exported.joinpath("probe.json").read_text())
        require(result == {"offline_smoke": "passed", "uid": os.getuid(), "gid": os.getgid()}, "exported probe result differs")
        payload = bytes(range(256)) * 32
        output = command(run + ["--", "python3", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], data=payload)
        require(output == payload, "binary pipes/stdin EOF were not preserved")
        command(run + ["--export", str(failed_exports), "--", "bash", "-c", "printf synthetic > /work/out/failed; exit 17"], expected=17)
        require(not list(failed_exports.iterdir()), "failed command exported files")
        command(run + ["--", "python3", "-c", "import os; assert not os.path.exists('/work/out/probe.json')"])
        terminal_probe(config)
    deadline = time.monotonic() + 5
    after_resources = resources()
    while after_resources != before_resources and time.monotonic() < deadline:
        time.sleep(0.2)
        after_resources = resources()
    require(after_resources == before_resources, "unit/cgroup/runtime-directory cleanup is incomplete; destroy the VM, do not prefix-delete resources")
    require(network_snapshot() == before_network, "host network/resolver/sysctl state changed; no restore was attempted")
    print(json.dumps({"fixture": "offline-smoke-v1", "target": actual, "declared_image_sha256": os.environ["SOTERIA_VM_IMAGE_SHA256"], "version": version, "runtime_digest": runtime_digest, "result": "passed", "scope": "offline smoke only, not full release or WireGuard validation"}, sort_keys=True))


if __name__ == "__main__":
    main()
