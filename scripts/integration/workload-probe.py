#!/usr/bin/env python3
"""Synthetic offline fixture, explicitly imported as an ordinary caller file."""

import errno
import json
import os
import pathlib
import socket
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    expected = json.loads(sys.argv[1])
    status = {}
    for line in pathlib.Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        status[key] = value.strip()
    require([int(v) for v in status["Uid"].split()] == [expected["uid"]] * 4, "all UID fields must be the non-root caller")
    require([int(v) for v in status["Gid"].split()] == [expected["gid"]] * 4, "all GID fields must be the caller group")
    require(os.getgroups() == [], "supplementary groups leaked")
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(int(status[name], 16) == 0, name + " is not empty")
    require(status["NoNewPrivs"] == "1", "no_new_privs missing")
    for name in ("SOTERIA_SMOKE_SECRET", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS"):
        require(name not in os.environ, "caller credential/environment variable was forwarded: " + name)
    for name in expected["host_paths"]:
        require(not os.path.exists(name), "host sentinel/socket is visible")
    for name, host_value in expected["namespaces"].items():
        require(os.readlink("/proc/self/ns/" + name) != host_value, "host namespace was retained: " + name)
    for fd in os.listdir("/proc/self/fd"):
        if int(fd) <= 2:
            continue
        try:
            target = os.readlink("/proc/self/fd/" + fd)
        except FileNotFoundError:
            continue  # listdir's own now-closed directory descriptor
        raise AssertionError("unexpected inherited descriptor: " + fd + " -> " + target)
    require(pathlib.Path("/work/in/smoke-input.txt").read_text() == "public synthetic fixture\n", "imported snapshot differs")
    require(os.getcwd() == "/work", "working directory is not /work")
    require(os.environ.get("HOME") == "/home/workspace", "HOME is not the disposable home")

    mounts = []
    for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        mounts.append((fields[4], fields[5].split(","), right.split()[0]))
    for name in ("/work", "/home/workspace", "/tmp", "/run", "/var"):
        candidates = [m for m in mounts if name == m[0] or name.startswith(m[0].rstrip("/") + "/")]
        require(candidates and max(candidates, key=lambda m: len(m[0]))[2] == "tmpfs", name + " is not tmpfs-backed")
        stats = os.statvfs(name)
        require(stats.f_blocks * stats.f_frsize <= 512 * 1024 * 1024, "workspace mount lacks the default size bound")
    root = next((m for m in mounts if m[0] == "/"), None)
    require(root is not None and "ro" in root[1], "runtime root is not a read-only mount")
    try:
        pathlib.Path("/usr/bin/soteria-smoke-write").write_text("must fail")
    except OSError as error:
        require(error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), "unexpected root write error")
    else:
        raise AssertionError("runtime was writable")

    devices = pathlib.Path("/proc/net/dev").read_text().splitlines()[2:]
    require({line.split(":")[0].strip() for line in devices} == {"lo"}, "offline netns contains an external interface")
    tcp_targets = [(socket.AF_INET, "127.0.0.1", expected["loopback_port"])]
    tcp_targets += [(socket.AF_INET, address, 443) for address in ("192.0.2.1", "198.51.100.1", "10.0.0.1", "169.254.169.254")]
    tcp_targets += [(socket.AF_INET, address, expected["loopback_port"]) for address in expected["host_ipv4"]]
    tcp_targets += [(socket.AF_INET6, address, expected["ipv6_port"] or 9) for address in ("::1", "2001:db8::1", "fe80::1%1")]
    for family, address, port in tcp_targets:
        try:
            connection = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            require(family == socket.AF_INET6, "IPv4 socket creation failed unexpectedly")
            continue
        with connection:
            connection.settimeout(0.3)
            try:
                connection.connect((address, port))
            except OSError:
                pass
            else:
                raise AssertionError("offline workload reached a host/external TCP target")
    for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            connection = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            require(family == socket.AF_INET6, "IPv4 UDP socket creation failed")
            continue
        with connection:
            try:
                connection.sendto(b"synthetic offline probe", (address, 53))
            except OSError:
                pass
            else:
                raise AssertionError("offline workload had an external UDP route")
    output = pathlib.Path("/work/out")
    output.mkdir(exist_ok=True)
    output.joinpath("probe.json").write_text(json.dumps({"offline_smoke": "passed", "uid": os.getuid(), "gid": os.getgid()}) + "\n")
    print("synthetic workload probe passed")


if __name__ == "__main__":
    main()
