#!/usr/bin/env python3
"""
Stage the minimum Android WeChat files needed by wechat-decrypt-standalone.js.

This is the Python version of the lightweight ChainlessChain staging flow.
It does not import the ChainlessChain CLI, npm workspaces, Electron, or native
sqlite packages. It only calls adb + su on a rooted Android device.

Output files:
  enmm.enc.db  - copied EnMicroMsg.db
  uins.txt     - numeric UIN candidates from WeChat shared_prefs
  imeis.txt    - Android ID / IMEI candidates when readable
  info.txt     - diagnostic device and WeChat information

Use only for databases you are authorized to access.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Iterable, List, Optional


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def adb_args(adb: str, device: str, args: Iterable[str]) -> List[str]:
    out = [adb]
    if device:
        out += ["-s", device]
    out += list(args)
    return out


def run_adb(
    adb: str,
    device: str,
    *args: str,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = adb_args(adb, device, args)
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


def print_output(proc: subprocess.CompletedProcess[str]) -> None:
    if proc.stdout:
        print(proc.stdout.rstrip())


def require_tool(name: str) -> None:
    if not shutil.which(name):
        raise RuntimeError(f"{name!r} not found in PATH")


def make_device_script(remote_dir: str, db_path: str) -> str:
    db_assignment = sh_quote(db_path) if db_path else "''"
    remote_assignment = sh_quote(remote_dir)
    return f"""#!/system/bin/sh
WX="com.tencent.mm"
OUT={remote_assignment}
DBPATH={db_assignment}

rm -rf "$OUT" 2>/dev/null
mkdir -p "$OUT" || exit 10

if [ -z "$DBPATH" ]; then
  DBPATH=$(find /data/data/$WX/MicroMsg -name EnMicroMsg.db 2>/dev/null | head -1)
fi

if [ -z "$DBPATH" ]; then
  echo "ERROR: EnMicroMsg.db not found. Is WeChat installed and logged in?" > "$OUT/error.txt"
  chmod 644 "$OUT/error.txt" 2>/dev/null
  exit 20
fi

if ! cp "$DBPATH" "$OUT/enmm.enc.db" 2>"$OUT/cp-db.err"; then
  echo "ERROR: copy EnMicroMsg.db failed: $DBPATH" > "$OUT/error.txt"
  chmod 644 "$OUT"/* 2>/dev/null
  exit 21
fi

# ChainlessChain staging logic: UIN candidates from shared_prefs.
grep -rohE '\\-?[0-9]{{4,12}}' /data/data/$WX/shared_prefs/ 2>/dev/null \
  | sort -u | head -200 > "$OUT/uins.txt" 2>/dev/null

# ChainlessChain staging logic: Android ID plus best-effort IMEI from service call.
{{
  settings get secure android_id 2>/dev/null
  service call iphonesubinfo 1 2>/dev/null | grep -oE "'.{{8,}}'" | tr -d "'. " | tr -d '\\n'; echo
}} | sort -u > "$OUT/imeis.txt" 2>/dev/null

{{
  echo "dbPath=$DBPATH"
  echo "abi=$(getprop ro.product.cpu.abi 2>/dev/null)"
  echo "model=$(getprop ro.product.model 2>/dev/null)"
  echo "android=$(getprop ro.build.version.release 2>/dev/null)"
  dumpsys package $WX 2>/dev/null | grep versionName | head -1
  echo ""
  echo "staged files:"
  ls -l "$OUT" 2>/dev/null
}} > "$OUT/info.txt" 2>/dev/null

chmod 644 "$OUT"/* 2>/dev/null
exit 0
""".replace("\r\n", "\n").replace("\r", "\n")


def pull_optional(adb: str, device: str, remote: str, local: pathlib.Path) -> None:
    run_adb(adb, device, "pull", remote, str(local), check=False, capture=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage Android WeChat DB/key-candidate files via adb + su")
    parser.add_argument("--out", default=r"C:\wechat-stage", help="local output directory")
    parser.add_argument("--adb", default="adb", help="adb executable path/name")
    parser.add_argument("--device", default="", help="optional adb serial")
    parser.add_argument("--db-path", default="", help="optional explicit /data/data/.../EnMicroMsg.db path")
    parser.add_argument("--keep-device-temp", action="store_true", help="do not remove /data/local/tmp staging files")
    args = parser.parse_args()

    if args.adb == "adb":
      require_tool("adb")

    out_dir = pathlib.Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in ["enmm.enc.db", "uins.txt", "imeis.txt", "info.txt", "error.txt", "cp-db.err"]:
        try:
            (out_dir / stale).unlink()
        except FileNotFoundError:
            pass

    print("[1/6] Checking adb...")
    proc = run_adb(args.adb, args.device, "devices", capture=True)
    print_output(proc)
    if "\tdevice" not in (proc.stdout or ""):
        raise RuntimeError("No authorized adb device found. Approve USB debugging and run adb devices again.")

    print("[2/6] Checking root...")
    proc = run_adb(args.adb, args.device, "shell", "su", "-c", "id", capture=True)
    print_output(proc)
    if "uid=0" not in (proc.stdout or ""):
        raise RuntimeError("su did not return uid=0. Root/Magisk adb shell authorization is required.")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    remote_dir = f"/data/local/tmp/cc-wechat-stage-{stamp}"
    remote_script = f"/data/local/tmp/cc-wechat-stage-{stamp}.sh"
    script_text = make_device_script(remote_dir, args.db_path)

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n", encoding="utf-8") as f:
        f.write(script_text)
        tmp_script = pathlib.Path(f.name)

    try:
        print("[3/6] Pushing staging script...")
        proc = run_adb(args.adb, args.device, "push", str(tmp_script), remote_script, capture=True)
        print_output(proc)
        run_adb(args.adb, args.device, "shell", "chmod", "755", remote_script)

        print("[4/6] Staging WeChat files on device...")
        proc = run_adb(args.adb, args.device, "shell", "su", "-c", f"sh {remote_script}", check=False, capture=True)
        print_output(proc)
        if proc.returncode != 0:
            print("warning: device-side staging failed; pulling diagnostics if present", file=sys.stderr)

        print(f"[5/6] Pulling staged files to {out_dir} ...")
        for name in ["enmm.enc.db", "uins.txt", "imeis.txt", "info.txt", "error.txt", "cp-db.err"]:
            pull_optional(args.adb, args.device, f"{remote_dir}/{name}", out_dir / name)

        if (out_dir / "error.txt").exists():
            print((out_dir / "error.txt").read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
            raise RuntimeError(f"WeChat staging failed. See {out_dir}")

        missing = [name for name in ["enmm.enc.db", "uins.txt", "imeis.txt"] if not (out_dir / name).exists()]
        if missing:
            raise RuntimeError(f"Missing staged files: {', '.join(missing)}. See {out_dir}")

        if args.keep_device_temp:
            print(f"[6/6] Keeping device temp files: {remote_dir}")
        else:
            print("[6/6] Cleaning device temp files...")
            run_adb(args.adb, args.device, "shell", "su", "-c", f"rm -rf {remote_dir} {remote_script}", check=False)

        print("\nOK. Staged files:")
        for p in sorted(out_dir.iterdir()):
            if p.is_file():
                print(f"  {p.name:16} {p.stat().st_size} bytes")
        print("\nNext command:")
        print(f'node tools\\wechat-decrypt-standalone.js --db "{out_dir}\\enmm.enc.db" --out "{out_dir}\\decoded.db" --uins "{out_dir}\\uins.txt" --imeis "{out_dir}\\imeis.txt" --force')
        return 0
    finally:
        try:
            tmp_script.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
