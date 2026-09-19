#!/usr/bin/env python3
r"""
Capture Android WeChat SQLCipher raw key with Python Frida.

This script uses the Python `frida` package directly. It does not call the
ChainlessChain CLI, does not run npm, and does not use PowerShell scripts.

While it is running, unlock the phone and enter any WeChat chat. The script
loads tools/wechat-key-hook-standalone.js into com.tencent.mm and writes:

  C:\wechat-stage\raw-key.txt
  C:\wechat-stage\raw-keys.json
  C:\wechat-stage\frida-wechat-key.log
"""

from __future__ import annotations

import argparse
import json
import pathlib
import queue
import re
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import frida  # type: ignore
except ImportError as exc:  # pragma: no cover - user environment
    print("Error: Python package 'frida' is not installed. Run tools\\wechat_frida_start_server.py first.", file=sys.stderr)
    raise SystemExit(1) from exc

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def valid_hex64(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower().replace("0x", "", 1)
    if HEX64.match(s):
        return s
    return None


def append_log(path: pathlib.Path, obj: Any) -> None:
    with open(path, "a", encoding="utf-8") as f:
        if isinstance(obj, str):
            f.write(obj.rstrip() + "\n")
        else:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def find_process(device: Any, package: str) -> Optional[int]:
    for proc in device.enumerate_processes():
        if proc.name == package:
            return proc.pid
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture WeChat raw SQLCipher key with Python Frida")
    parser.add_argument("--out", default=r"C:\wechat-stage", help="output directory")
    parser.add_argument("--agent", default="tools/wechat-key-hook-standalone.js", help="Frida agent JS path")
    parser.add_argument("--package", default="com.tencent.mm", help="Android package name")
    parser.add_argument("--timeout", type=int, default=180, help="capture timeout seconds")
    parser.add_argument("--attach-only", action="store_true", help="attach to already-running WeChat instead of spawning it")
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    agent_path = pathlib.Path(args.agent).expanduser().resolve()
    if not agent_path.exists():
        raise RuntimeError(f"Agent not found: {agent_path}")

    log_path = out_dir / "frida-wechat-key.log"
    raw_key_path = out_dir / "raw-key.txt"
    raw_keys_json_path = out_dir / "raw-keys.json"
    for p in [log_path, raw_key_path, raw_keys_json_path]:
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    agent_source = agent_path.read_text(encoding="utf-8")
    messages: "queue.Queue[Dict[str, Any]]" = queue.Queue()

    def on_message(message: Dict[str, Any], data: Any) -> None:
        append_log(log_path, message)
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                print(json.dumps(payload, ensure_ascii=False))
                messages.put(payload)
        elif message.get("type") == "error":
            print(json.dumps(message, ensure_ascii=False), file=sys.stderr)
            messages.put({"kind": "frida-error", "message": message})
        else:
            print(json.dumps(message, ensure_ascii=False))

    print("Connecting to USB Frida device...")
    device = frida.get_usb_device(timeout=10)
    print(f"Device: {device}")

    pid: Optional[int] = None
    session = None
    script = None
    spawned = False

    try:
        if args.attach_only:
            pid = find_process(device, args.package)
            if not pid:
                raise RuntimeError(f"{args.package} is not running. Open WeChat first, or run without --attach-only.")
            print(f"Attaching to running {args.package}, pid={pid}")
            session = device.attach(pid)
        else:
            print(f"Spawning {args.package} under Frida...")
            pid = device.spawn([args.package])
            spawned = True
            session = device.attach(pid)

        script = session.create_script(agent_source)
        script.on("message", on_message)
        script.load()

        if spawned and pid is not None:
            device.resume(pid)

        print("\nPhone action needed: unlock the phone and enter any WeChat chat.")
        print(f"Waiting up to {args.timeout}s for sqlite3_key/sqlite3_key_v2...")
        print(f"Log: {log_path}\n")

        deadline = time.time() + args.timeout
        keys: List[str] = []
        while time.time() < deadline:
            try:
                payload = messages.get(timeout=1)
            except queue.Empty:
                continue

            if payload.get("kind") == "key":
                for candidate in [payload.get("hex"), payload.get("alt")]:
                    key = valid_hex64(candidate)
                    if key and key not in keys:
                        keys.append(key)
                if keys:
                    break

        if not keys:
            raise RuntimeError(
                f"No 64-hex raw key captured within {args.timeout}s. "
                "Try: force-stop WeChat, rerun without --attach-only, then enter a chat; "
                "or open WeChat first and rerun with --attach-only."
            )

        raw_key_path.write_text(keys[0], encoding="ascii")
        raw_keys_json_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")

        print("\nOK. Captured raw key(s):")
        for key in keys:
            print(key)
        print("\nSaved:")
        print(f"  {raw_key_path}")
        print(f"  {raw_keys_json_path}")
        print("\nNext command:")
        print(
            'node tools\\wechat-decrypt-standalone.js '
            f'--db "{out_dir}\\enmm.enc.db" '
            f'--out "{out_dir}\\decoded.db" '
            f'--raw-keys "{raw_keys_json_path}" --force'
        )
        return 0
    finally:
        try:
            if script is not None:
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
