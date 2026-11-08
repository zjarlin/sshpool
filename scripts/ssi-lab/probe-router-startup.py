#!/usr/bin/env python3
"""在独占 PF24 实验 VM 记录真实 QEMU 启动失败与 KVM_RUN 边界。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time


KERNEL = "7.1.0-rc3-sshpool-gvm-pf24"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-kernel", required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--require-sha256", required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--guest-kernel", type=Path, required=True)
    parser.add_argument("--guest-kernel-sha256", required=True)
    parser.add_argument("--initramfs", type=Path, required=True)
    parser.add_argument("--initramfs-sha256", required=True)
    parser.add_argument("--node", type=int, choices=(0, 1), required=True)
    parser.add_argument("--peers", nargs=2, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    require(args.require_kernel == KERNEL and platform.release() == KERNEL,
            "dedicated PF24 kernel required")
    for path, expected in [(args.qemu, args.require_sha256),
                           (args.guest_kernel, args.guest_kernel_sha256),
                           (args.initramfs, args.initramfs_sha256)]:
        require(digest(path) == expected, f"hash mismatch: {path.name}")
    names = subprocess.check_output(["ps", "-eo", "comm="], text=True).splitlines()
    require(not any(name.strip().startswith(("qemu-system-", "kvm-dsm/", "dsm-conn/"))
                    for name in names), "another experiment is active")
    ports = " or ".join(f"{side} = :{port}" for side in ("sport", "dport")
                        for port in (37710, 37711, 40000, 40001))
    require(not subprocess.check_output(["ss", "-H", "-tan", f"( {ports} )"]).strip(),
            "experiment TCP ports are still occupied")
    args.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = {"schema": 1, "kernel": KERNEL, "node": args.node,
              "qemu_sha256": args.require_sha256,
              "capture_sha256": digest(Path(__file__)),
              "guest_kernel_sha256": args.guest_kernel_sha256,
              "initramfs_sha256": args.initramfs_sha256,
              "forced_cleanup": [], "errors": []}
    trace = args.directory / "ioctl.log"
    command = ["strace", "-f", "-q", "-ttt", "-s", "4096", "-e",
               "trace=ioctl,execve,clone,clone3,exit,exit_group", "-o", str(trace),
               str(args.qemu), "-name", f"sshpool-router-startup-{args.node},debug-threads=on",
               "-machine", "pc,accel=kvm,kernel-irqchip=split",
               "-cpu", "qemu64,-x2apic,+tsc-adjust,enforce",
               "-smp", "4,sockets=2,cores=2,threads=1", "-m", "256",
               "-nodefaults", "-display", "none", "-serial", "stdio",
               "-monitor", "none", "-no-reboot", "-L", str(args.firmware),
               "-kernel", str(args.guest_kernel), "-initrd", str(args.initramfs),
               "-append", "console=ttyS0 rdinit=/init nokaslr panic=10 nox2apic",
               "-local-cpu", f"cpus=2,start={args.node * 2},iplist={' '.join(args.peers)}"]
    result["qemu_arguments"] = command[command.index(str(args.qemu)) + 1:]
    result["qemu_binary"] = str(args.qemu)
    process = None
    result["started_ns"] = time.monotonic_ns()
    try:
        with (args.directory / "stdout.log").open("xb") as stdout, \
                (args.directory / "stderr.log").open("xb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            result["tracer_pid"] = process.pid
            try:
                result["exit"] = process.wait(timeout=35)
                result["exit_observed_ns"] = time.monotonic_ns()
            except subprocess.TimeoutExpired:
                result["errors"].append("process did not exit within 35 seconds")
                raise
    except Exception as error:
        result["errors"].append(str(error))
    finally:
        # 只回收本次创建的进程组；外部强制终止永远作为失败证据保留。
        if process is not None and process.poll() is None:
            for action in (signal.SIGTERM, signal.SIGKILL):
                result["forced_cleanup"].append(action.name)
                os.killpg(process.pid, action)
                try:
                    process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    continue
        if process is not None:
            result["exit"] = process.poll()
        for name in ("stdout", "stderr", "ioctl"):
            path = args.directory / f"{name}.log"
            if path.exists():
                result[name] = path.read_text(errors="replace")
                result[name + "_sha256"] = digest(path)
        result["kvm_run_calls"] = len(re.findall(r"\bioctl\([^\n]*\bKVM_RUN\b", result.get("ioctl", "")))
        result["finished_ns"] = time.monotonic_ns()
        (args.directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ("stdout", "stderr", "ioctl")}), flush=True)
    return int(bool(result["errors"] or result["forced_cleanup"]))


if __name__ == "__main__":
    raise SystemExit(main())
