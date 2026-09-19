#!/usr/bin/env python3
"""
Install/check Python Frida, download the matching Android frida-server, push it
onto a rooted Android device, and start it.

No ChainlessChain CLI, npm workspace, Electron, or native sqlite dependency is
used here. The matching rule is simple: the Python `frida` package version must
match the downloaded frida-server release version.
"""

from __future__ import annotations

import argparse
import importlib
import lzma
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request
from typing import Iterable, List


def adb_args(adb: str, device: str, args: Iterable[str]) -> List[str]:
    out = [adb]
    if device:
        out += ["-s", device]
    out += list(args)
    return out


def run(cmd: List[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if check and proc.returncode != 0:
        output = (proc.stdout or "").strip()
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{output}")
    return proc


def run_adb(adb: str, device: str, *args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return run(adb_args(adb, device, args), check=check, capture=capture)


def print_output(proc: subprocess.CompletedProcess[str]) -> None:
    if proc.stdout:
        print(proc.stdout.rstrip())


def ensure_frida(skip_pip_install: bool) -> object:
    try:
        return importlib.import_module("frida")
    except ImportError:
        if skip_pip_install:
            raise RuntimeError("Python package 'frida' is not installed. Run without --skip-pip-install first.")

    print("Installing/upgrading Python frida package for current user...")
    run([sys.executable, "-m", "pip", "install", "--user", "--upgrade", "frida"])
    importlib.invalidate_caches()
    try:
        return importlib.import_module("frida")
    except ImportError as exc:
        raise RuntimeError("Failed to import Python package 'frida' after pip install") from exc


def detect_arch(abi: str) -> str:
    abi = abi.strip()
    if abi.startswith("arm64"):
        return "android-arm64"
    if abi.startswith("armeabi") or abi.startswith("arm"):
        return "android-arm"
    if abi.startswith("x86_64"):
        return "android-x86_64"
    if abi.startswith("x86"):
        return "android-x86"
    raise RuntimeError(f"Unsupported Android ABI: {abi}")


def download_file(url: str, dst: pathlib.Path) -> None:
    print(url)
    with urllib.request.urlopen(url, timeout=300) as r, open(dst, "wb") as f:
        shutil.copyfileobj(r, f)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start matching frida-server on rooted Android")
    parser.add_argument("--adb", default="adb", help="adb executable path/name")
    parser.add_argument("--device", default="", help="optional adb serial")
    parser.add_argument("--out", default=r"C:\wechat-stage", help="local cache/output directory")
    parser.add_argument("--force-download", action="store_true", help="download frida-server again")
    parser.add_argument("--skip-pip-install", action="store_true", help="do not auto-install Python frida package")
    args = parser.parse_args()

    if args.adb == "adb" and not shutil.which("adb"):
        raise RuntimeError("adb not found in PATH")

    out_dir = pathlib.Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[1/7] Checking adb device...")
    proc = run_adb(args.adb, args.device, "devices", capture=True)
    print_output(proc)
    if "\tdevice" not in (proc.stdout or ""):
        raise RuntimeError("No authorized adb device found")

    print("[2/7] Checking root...")
    proc = run_adb(args.adb, args.device, "shell", "su", "-c", "id", capture=True)
    print_output(proc)
    if "uid=0" not in (proc.stdout or ""):
        raise RuntimeError("Root is required. adb shell su -c id did not return uid=0.")

    print("[3/7] Preparing Python Frida package...")
    frida = ensure_frida(args.skip_pip_install)
    frida_version = getattr(frida, "__version__", None)
    if not frida_version:
        raise RuntimeError("Could not determine Python frida version")
    print(f"Python frida version: {frida_version}")

    print("[4/7] Detecting Android ABI...")
    proc = run_adb(args.adb, args.device, "shell", "getprop", "ro.product.cpu.abi", capture=True)
    abi = (proc.stdout or "").strip().splitlines()[0]
    arch = detect_arch(abi)
    print(f"Device ABI: {abi} -> {arch}")

    server_name = f"frida-server-{frida_version}-{arch}"
    xz_path = out_dir / f"{server_name}.xz"
    server_path = out_dir / "frida-server"
    url = f"https://github.com/frida/frida/releases/download/{frida_version}/{server_name}.xz"

    print("[5/7] Downloading/decompressing matching frida-server if needed...")
    if args.force_download or not server_path.exists():
        if args.force_download or not xz_path.exists():
            download_file(url, xz_path)
        with lzma.open(xz_path, "rb") as src, open(server_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
    print(f"server: {server_path}")

    print("[6/7] Pushing and starting frida-server...")
    proc = run_adb(args.adb, args.device, "push", str(server_path), "/data/local/tmp/frida-server", capture=True)
    print_output(proc)
    # Default frida-server port is 27042. Python frida's USB transport expects that default.
    run_adb(
        args.adb,
        args.device,
        "shell",
        "su",
        "-c",
        "chmod 755 /data/local/tmp/frida-server; pkill -9 frida-server 2>/dev/null; /data/local/tmp/frida-server -D",
    )
    time.sleep(1)

    print("[7/7] Verifying frida-server...")
    proc = run_adb(args.adb, args.device, "shell", "su", "-c", "pgrep -f frida-server", capture=True)
    print_output(proc)

    try:
        device = frida.get_usb_device(timeout=10)
        print(f"Frida USB device: {device}")
        procs = device.enumerate_processes()
        print(f"Frida process enumeration OK, processes={len(procs)}")
    except Exception as exc:
        raise RuntimeError(f"frida-server started but Python frida could not connect: {exc}") from exc

    print("\nOK. frida-server is running and Python frida can connect.")
    print("Next:")
    print("python tools\\wechat_frida_capture_key.py")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
