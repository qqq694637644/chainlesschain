#!/usr/bin/env python3
r"""
Probe/decrypt Android WeChat EnMicroMsg.db through WCDB/SQLCipher hooks.

This intentionally does NOT use aes_v8_set_encrypt_key. It follows the real DB
layer routes used by WeChat/WCDB tooling:

  - Java com.tencent.wcdb.database.SQLiteDatabase openDatabase/openOrCreateDatabase
    byte[] password capture.
  - Native sqlite3_key/sqlite3_key_v2 capture.
  - Method C online export from an already-keyed DB handle using
    ATTACH DATABASE '<app-cache-out>' AS ccpt KEY ''; SELECT sqlcipher_export('ccpt');

Outputs:
  C:\wechat-stage\keys.txt                  printable SQLCipher passphrase candidates
  C:\wechat-stage\raw-keys.json             32-byte raw key candidates
  C:\wechat-stage\sqlcipher-events.jsonl    all JSON events
  C:\wechat-stage\frida-sqlcipher-probe.log raw frida-inject output
  C:\wechat-stage\exports\*.plain.db        exported plaintext DBs, if sqlcipher_export succeeds
"""

from __future__ import annotations

import argparse
import importlib
import json
import lzma
import pathlib
import queue
import re
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
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{(proc.stdout or '').strip()}")
    return proc


def run_adb(adb: str, device: str, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return run(adb_args(adb, device, args), check=check, capture=capture)


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
    abi = (run_adb(adb, device, "shell", "getprop", "ro.product.cpu.abi").stdout or "").strip().splitlines()[0]
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
    text = (run_adb(adb, device, "shell", "su", "-c", f"pidof {package}").stdout or "").strip()
    if not text:
        raise RuntimeError(f"{package} is not running. Open WeChat first.")
    for part in text.split():
        try:
            return int(part)
        except ValueError:
            continue
    raise RuntimeError(f"Could not parse pidof output: {text!r}")


def try_set_permissive(adb: str, device: str) -> None:
    before = (run_adb(adb, device, "shell", "su", "-c", "getenforce 2>/dev/null", check=False).stdout or "").strip()
    if before:
        print(f"SELinux before inject: {before}")
    if before.lower() != "permissive":
        run_adb(adb, device, "shell", "su", "-c", "setenforce 0 2>/dev/null", check=False)
        after = (run_adb(adb, device, "shell", "su", "-c", "getenforce 2>/dev/null", check=False).stdout or "").strip()
        if after:
            print(f"SELinux before frida-inject launch: {after}")


def push_stage(adb: str, device: str, inject_path: pathlib.Path, agent_path: pathlib.Path) -> Tuple[str, str]:
    remote_inject = "/data/local/tmp/cc-frida-inject"
    remote_agent = "/data/local/tmp/cc-wechat-sqlcipher-hook.js"
    print("Pushing frida-inject and SQLCipher/WCDB agent...")
    print((run_adb(adb, device, "push", str(inject_path), remote_inject).stdout or "").rstrip())
    print((run_adb(adb, device, "push", str(agent_path), remote_agent).stdout or "").rstrip())
    run_adb(adb, device, "shell", "su", "-c", f"chmod 755 {remote_inject}; chmod 644 {remote_agent}")
    return remote_inject, remote_agent


def extract_json(line: str) -> Optional[dict]:
    s = line.strip()
    if not s:
        return None
    if s.startswith("[send] "):
        s = s[len("[send] ") :].strip()
    if not s.startswith("{"):
        i = s.find("{")
        if i < 0:
            return None
        s = s[i:]
    try:
        obj = json.loads(s)
    except Exception:
        return None
    if isinstance(obj, dict) and obj.get("type") == "send" and isinstance(obj.get("payload"), dict):
        return obj["payload"]
    return obj if isinstance(obj, dict) else None


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


def persist_candidates(passphrases: List[str], raw_keys: List[str], keys_txt: pathlib.Path, raw_json: pathlib.Path) -> Tuple[List[str], List[str]]:
    pp: List[str] = []
    for k in passphrases:
        k = str(k).strip()
        if k and k not in pp:
            pp.append(k)
    rk: List[str] = []
    for h in raw_keys:
        h = str(h).strip().lower().replace("0x", "")
        if HEX64.match(h) and h not in rk:
            rk.append(h)
    keys_txt.write_text("\n".join(pp) + ("\n" if pp else ""), encoding="ascii")
    raw_json.write_text(json.dumps(rk, indent=2), encoding="ascii")
    return pp, rk


def pull_exports(adb: str, device: str, out_dir: pathlib.Path, clean: bool) -> List[pathlib.Path]:
    exports_dir = out_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    proc = run_adb(
        adb,
        device,
        "shell",
        "su",
        "-c",
        "ls /data/data/com.tencent.mm/cache/cc_plain_*.plain.db 2>/dev/null",
        check=False,
    )
    remotes = [x.strip() for x in (proc.stdout or "").splitlines() if x.strip().endswith(".db")]
    pulled: List[pathlib.Path] = []
    for remote in remotes:
        name = pathlib.PurePosixPath(remote).name
        tmp = f"/data/local/tmp/{name}"
        local = exports_dir / name
        run_adb(adb, device, "shell", "su", "-c", f"cp '{remote}' '{tmp}'; chmod 666 '{tmp}'", check=False)
        pr = run_adb(adb, device, "pull", tmp, str(local), check=False)
        if pr.returncode == 0 and local.exists():
            pulled.append(local)
        run_adb(adb, device, "shell", "su", "-c", f"rm -f '{tmp}'", check=False)
        if clean:
            run_adb(adb, device, "shell", "su", "-c", f"rm -f '{remote}'", check=False)
    return pulled


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe Android WeChat SQLCipher/WCDB key/export points")
    parser.add_argument("--out", default=r"C:\wechat-stage", help="local output/cache directory")
    parser.add_argument("--agent", default="tools/wechat-sqlcipher-hook-standalone.js", help="Frida SQLCipher hook JS path")
    parser.add_argument("--adb", default="adb", help="adb executable path/name")
    parser.add_argument("--device", default="", help="optional adb serial")
    parser.add_argument("--package", default="com.tencent.mm", help="WeChat package name")
    parser.add_argument("--pid", type=int, default=0, help="explicit WeChat PID")
    parser.add_argument("--seconds", type=int, default=180, help="probe duration")
    parser.add_argument("--frida-version", default="", help="explicit Frida release version")
    parser.add_argument("--skip-pip-install", action="store_true", help="do not install Python frida for version detection")
    parser.add_argument("--force-download", action="store_true", help="download frida-inject again")
    parser.add_argument("--keep-device-files", action="store_true", help="keep staged frida files and exported DBs on device")
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
    print("Keep WeChat open. Enter chat list, open chats, search messages, and scroll while this runs.")

    keys_txt = out_dir / "keys.txt"
    raw_json = out_dir / "raw-keys.json"
    events_jsonl = out_dir / "sqlcipher-events.jsonl"
    log_path = out_dir / "frida-sqlcipher-probe.log"
    for p in [keys_txt, raw_json, events_jsonl, log_path]:
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    persist_candidates([], [], keys_txt, raw_json)

    run_adb(args.adb, args.device, "shell", "su", "-c", "rm -f /data/data/com.tencent.mm/cache/cc_plain_*.plain.db", check=False)

    inject_cmd = f"{remote_inject} -p {pid} -s {remote_agent} --runtime=v8"
    print("Running on device:")
    print("  su -c '" + inject_cmd + "'")
    print(f"Log: {log_path}")

    passphrases: List[str] = []
    raw_keys: List[str] = []
    exports_seen: List[dict] = []

    proc = subprocess.Popen(
        adb_args(args.adb, args.device, ["shell", "su", "-c", inject_cmd]),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    q: "queue.Queue[str]" = queue.Queue()
    interrupted = False
    with open(log_path, "w", encoding="utf-8") as log_file, open(events_jsonl, "a", encoding="utf-8") as ev_file:
        assert proc.stdout is not None
        assert proc.stderr is not None
        threading.Thread(target=reader_thread, args=(proc.stdout, q, log_file), daemon=True).start()
        threading.Thread(target=reader_thread, args=(proc.stderr, q, log_file), daemon=True).start()
        deadline = time.time() + args.seconds
        try:
            while time.time() < deadline:
                try:
                    line = q.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                    continue
                if line:
                    print(line)
                obj = extract_json(line)
                if not obj:
                    continue
                ev_file.write(json.dumps(obj, ensure_ascii=False) + "\n")
                ev_file.flush()

                if obj.get("kind") == "key":
                    ctype = obj.get("candidateType")
                    key = str(obj.get("key") or "").strip()
                    if ctype == "passphrase" and key:
                        if key not in passphrases:
                            passphrases.append(key)
                            print(f"CAPTURED passphrase key#{len(passphrases)} {key!r}")
                    elif ctype == "raw-key" and HEX64.match(key):
                        key = key.lower()
                        if key not in raw_keys:
                            raw_keys.append(key)
                            print(f"CAPTURED raw key#{len(raw_keys)} {key}")
                    persist_candidates(passphrases, raw_keys, keys_txt, raw_json)
                    print(f"Saved candidates immediately -> {keys_txt}, {raw_json}")
                elif obj.get("kind") == "export":
                    exports_seen.append(obj)
        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted by user; preserving captured candidates and pulling exports...")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            run_adb(args.adb, args.device, "shell", "su", "-c", "pkill -f cc-frida-inject 2>/dev/null || true", check=False)

    pp, rk = persist_candidates(passphrases, raw_keys, keys_txt, raw_json)
    pulled = pull_exports(args.adb, args.device, out_dir, clean=not args.keep_device_files)

    if not args.keep_device_files:
        run_adb(args.adb, args.device, "shell", "su", "-c", f"rm -f {remote_inject} {remote_agent}", check=False)

    print("\nSummary:")
    print(f"  passphrase candidates: {len(pp)} -> {keys_txt}")
    print(f"  raw-key candidates:    {len(rk)} -> {raw_json}")
    print(f"  export events:         {len(exports_seen)} -> {events_jsonl}")
    print(f"  pulled plain DBs:      {len(pulled)}")
    for p in pulled:
        print(f"    {p}")
    if interrupted:
        print("  note: capture was interrupted, but candidates were saved immediately.")

    if pp or rk:
        print("\nTry offline decrypt:")
        print(
            'node tools\\wechat-decrypt-standalone.js '
            f'--db "{out_dir}\\enmm.enc.db" '
            f'--out "{out_dir}\\decoded.db" '
            f'--keys "{keys_txt}" '
            f'--raw-keys "{raw_json}" --force'
        )
    if pulled:
        print("\nA pulled *.plain.db is already plaintext; open it directly with SQLite/DB Browser.")
    if not (pp or rk or pulled):
        print("\nNo key/export captured. Open WeChat chats/search while the script runs, or inject earlier after app start.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
