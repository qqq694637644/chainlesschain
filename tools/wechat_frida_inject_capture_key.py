#!/usr/bin/env python3
r"""
Capture WeChat 8.x WCDB raw AES keys with device-side frida-inject.

This follows the original ChainlessChain route more closely than host-side
Python Frida attach:

  1. Download frida-inject-<version>-android-<arch>.xz.
  2. Push it to /data/local/tmp/cc-frida-inject.
  3. Push tools/wechat-aes-key-hook-standalone.js.
  4. Run, as root on the device:
       /data/local/tmp/cc-frida-inject -p <wechat-pid> \
         -s /data/local/tmp/cc-wechat-aes-hook.js --runtime=v8
  5. Parse stdout for JSON key events from aes_v8_set_encrypt_key.

Use only for a WeChat process/database you are authorized to access.
"""

from __future__ import annotations

import argparse
import importlib
import json
import lzma
import os
import pathlib
import queue
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Iterable, List, Optional, Tuple

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def adb_args(adb: str, device: str, args: Iterable[str]) -> List[str]:
    out = [adb]
    if device:
        out += ["-s", device]
    out += list(args)
    return out


def run(cmd: List[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
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


def run_adb(adb: str, device: str, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return run(adb_args(adb, device, args), check=check, capture=capture)


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def ensure_frida_version(skip_pip_install: bool, explicit_version: str) -> str:
    if explicit_version:
        return explicit_version
    try:
        frida = importlib.import_module("frida")
        version = getattr(frida, "__version__", None)
        if version:
            return str(version)
    except ImportError:
        if skip_pip_install:
            raise RuntimeError("Python package 'frida' is not installed. Pass --frida-version or run without --skip-pip-install.")

    print("Installing Python frida package for version detection...")
    run([sys.executable, "-m", "pip", "install", "--user", "--upgrade", "frida"], capture=False)
    importlib.invalidate_caches()
    frida = importlib.import_module("frida")
    version = getattr(frida, "__version__", None)
    if not version:
        raise RuntimeError("Could not determine Python frida version")
    return str(version)


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


def prepare_frida_inject(adb: str, device: str, out_dir: pathlib.Path, version: str, force_download: bool) -> pathlib.Path:
    proc = run_adb(adb, device, "shell", "getprop", "ro.product.cpu.abi")
    abi = (proc.stdout or "").strip().splitlines()[0]
    arch = detect_arch(abi)
    print(f"Device ABI: {abi} -> {arch}")

    name = f"frida-inject-{version}-{arch}"
    xz_path = out_dir / f"{name}.xz"
    inject_path = out_dir / "frida-inject"
    url = f"https://github.com/frida/frida/releases/download/{version}/{name}.xz"

    if force_download or not inject_path.exists():
        if force_download or not xz_path.exists():
            print("Downloading frida-inject...")
            download_file(url, xz_path)
        print("Decompressing frida-inject...")
        with lzma.open(xz_path, "rb") as src, open(inject_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return inject_path


def pidof_wechat(adb: str, device: str, package: str) -> int:
    proc = run_adb(adb, device, "shell", "su", "-c", f"pidof {package}")
    text = (proc.stdout or "").strip()
    if not text:
        raise RuntimeError(f"{package} is not running. Open WeChat and enter a chat first.")
    for part in text.split():
        try:
            return int(part)
        except ValueError:
            continue
    raise RuntimeError(f"Could not parse pidof output: {text!r}")


def get_selinux(adb: str, device: str) -> str:
    proc = run_adb(adb, device, "shell", "su", "-c", "getenforce 2>/dev/null", check=False)
    return (proc.stdout or "").strip()


def try_set_permissive(adb: str, device: str) -> None:
    before = get_selinux(adb, device)
    if before:
        print(f"SELinux before inject: {before}")
    if before.lower() != "permissive":
        run_adb(adb, device, "shell", "su", "-c", "setenforce 0 2>/dev/null", check=False)
        after = get_selinux(adb, device)
        if after:
            print(f"SELinux before frida-inject launch: {after}")


def print_process_maps_hint(adb: str, device: str, pid: int) -> None:
    pattern = "lib.*(wcdb|sqlite|sqlcipher|crypto|ssl).*\\.so|WCDB|EnMicroMsg|MicroMsg"
    proc = run_adb(
        adb,
        device,
        "shell",
        "su",
        "-c",
        f"cat /proc/{pid}/maps 2>/dev/null | grep -Ei '{pattern}' | head -80",
        check=False,
    )
    text = (proc.stdout or "").strip()
    print("Process maps diagnostic:")
    if text:
        print(text)
    else:
        print(f"  no wcdb/sqlite/crypto/MicroMsg mappings visible in /proc/{pid}/maps")


def push_stage(adb: str, device: str, inject_path: pathlib.Path, agent_path: pathlib.Path) -> Tuple[str, str]:
    remote_inject = "/data/local/tmp/cc-frida-inject"
    remote_agent = "/data/local/tmp/cc-wechat-aes-hook.js"
    print("Pushing frida-inject and agent...")
    print((run_adb(adb, device, "push", str(inject_path), remote_inject).stdout or "").rstrip())
    print((run_adb(adb, device, "push", str(agent_path), remote_agent).stdout or "").rstrip())
    run_adb(adb, device, "shell", "su", "-c", f"chmod 755 {remote_inject}; chmod 644 {remote_agent}")
    return remote_inject, remote_agent


def extract_json_objects(line: str) -> List[dict]:
    out: List[dict] = []
    s = line.strip()
    if s.startswith("[send] "):
        s = s[len("[send] ") :].strip()
    candidates: List[str] = []
    if s.startswith("{") and s.endswith("}"):
        candidates.append(s)
    else:
        # Frida CLI output can wrap send() messages. Accept any JSON object with kind.
        for m in re.finditer(r"\{[^{}]*\"kind\"[^{}]*\}", s):
            candidates.append(m.group(0))
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def normalize_key(value: object) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if HEX64.match(s):
        return s
    return None


def reader_thread(stream, q: "queue.Queue[str]", log_file) -> None:
    try:
        for line in iter(stream.readline, ""):
            if not line:
                break
            log_file.write(line)
            log_file.flush()
            q.put(line.rstrip("\n"))
    except Exception as exc:
        q.put(f"[reader-error] {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture WeChat raw AES DB keys using device-side frida-inject")
    parser.add_argument("--out", default=r"C:\wechat-stage", help="local output/cache directory")
    parser.add_argument("--agent", default="tools/wechat-aes-key-hook-standalone.js", help="Frida agent JS path")
    parser.add_argument("--adb", default="adb", help="adb executable path/name")
    parser.add_argument("--device", default="", help="optional adb serial")
    parser.add_argument("--package", default="com.tencent.mm", help="WeChat package name")
    parser.add_argument("--pid", type=int, default=0, help="explicit WeChat PID")
    parser.add_argument("--seconds", type=int, default=120, help="capture duration")
    parser.add_argument("--frida-version", default="", help="explicit Frida release version, e.g. 17.18.0")
    parser.add_argument("--skip-pip-install", action="store_true", help="do not auto-install Python frida for version detection")
    parser.add_argument("--force-download", action="store_true", help="download frida-inject again")
    parser.add_argument("--keep-device-files", action="store_true", help="do not delete staged frida-inject/agent")
    args = parser.parse_args()

    if args.adb == "adb" and not shutil.which("adb"):
        raise RuntimeError("adb not found in PATH")

    out_dir = pathlib.Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    agent_path = pathlib.Path(args.agent).expanduser().resolve()
    if not agent_path.exists():
        raise RuntimeError(f"Agent not found: {agent_path}")

    print("Checking adb/root...")
    print((run_adb(args.adb, args.device, "devices").stdout or "").rstrip())
    root = run_adb(args.adb, args.device, "shell", "su", "-c", "id")
    print((root.stdout or "").rstrip())
    if "uid=0" not in (root.stdout or ""):
        raise RuntimeError("Root is required")

    version = ensure_frida_version(args.skip_pip_install, args.frida_version)
    print(f"Frida version for frida-inject: {version}")
    inject_path = prepare_frida_inject(args.adb, args.device, out_dir, version, args.force_download)
    try_set_permissive(args.adb, args.device)
    remote_inject, remote_agent = push_stage(args.adb, args.device, inject_path, agent_path)

    pid = args.pid or pidof_wechat(args.adb, args.device, args.package)
    print(f"Using WeChat pid: {pid}")
    print_process_maps_hint(args.adb, args.device, pid)
    print("Keep WeChat open and browse several chats during capture.")
    print("The script collects every 256-bit aes_v8_set_encrypt_key key it sees.")

    raw_key_txt = out_dir / "raw-key.txt"
    raw_keys_json = out_dir / "raw-keys.json"
    log_path = out_dir / "frida-inject-wechat-aes.log"
    for p in [raw_key_txt, raw_keys_json, log_path]:
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    inject_cmd = f"{remote_inject} -p {pid} -s {remote_agent} --runtime=v8"
    adb_cmd = adb_args(args.adb, args.device, ["shell", "su", "-c", inject_cmd])
    print("Running on device:")
    print("  su -c " + sh_quote(inject_cmd))
    print(f"Log: {log_path}")

    keys: List[str] = []
    proc = subprocess.Popen(
        adb_cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    q: "queue.Queue[str]" = queue.Queue()
    with open(log_path, "w", encoding="utf-8") as log_file:
        assert proc.stdout is not None
        assert proc.stderr is not None
        t_out = threading.Thread(target=reader_thread, args=(proc.stdout, q, log_file), daemon=True)
        t_err = threading.Thread(target=reader_thread, args=(proc.stderr, q, log_file), daemon=True)
        t_out.start()
        t_err.start()

        deadline = time.time() + args.seconds
        try:
            while time.time() < deadline:
                try:
                    line = q.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None:
                        # Drain remaining lines.
                        while True:
                            try:
                                line = q.get_nowait()
                            except queue.Empty:
                                break
                            print(line)
                        break
                    continue

                if line:
                    print(line)
                for obj in extract_json_objects(line):
                    kind = obj.get("kind")
                    if kind == "key":
                        for field in ["hex", "key"]:
                            k = normalize_key(obj.get(field))
                            if k and k not in keys:
                                keys.append(k)
                                print(f"CAPTURED key#{len(keys)} {k}")
                    elif kind in {"hooked", "waiting", "agent-started", "error"}:
                        pass
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            # Also kill any lingering device-side injector.
            run_adb(args.adb, args.device, "shell", "su", "-c", "pkill -f cc-frida-inject 2>/dev/null || true", check=False)

    if not args.keep_device_files:
        run_adb(args.adb, args.device, "shell", "su", "-c", f"rm -f {remote_inject} {remote_agent}", check=False)

    # Persist unique keys.
    unique = []
    for k in keys:
        if k not in unique:
            unique.append(k)
    raw_keys_json.write_text(json.dumps(unique, indent=2), encoding="utf-8")
    if unique:
        raw_key_txt.write_text(unique[0], encoding="ascii")

    print(f"\nSaved {len(unique)} unique raw key(s) -> {raw_keys_json}")
    if unique:
        print(f"First key -> {raw_key_txt}")
        print("\nNext command:")
        print(
            'node tools\\wechat-decrypt-standalone.js '
            f'--db "{out_dir}\\enmm.enc.db" '
            f'--out "{out_dir}\\decoded.db" '
            f'--raw-keys "{raw_keys_json}" --force'
        )
        return 0

    tail = ""
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = "\n".join(lines[-60:])
    except Exception:
        pass
    raise RuntimeError(
        "No AES raw keys captured. Make sure WeChat main process is open, then browse several chats/search. "
        f"See log: {log_path}\n{tail}"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
