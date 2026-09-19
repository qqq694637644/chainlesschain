# Standalone Android WeChat decrypt flow

This is the lightweight version of the ChainlessChain WeChat database flow. It avoids the full CLI/workspace install and does not load Electron, `better-sqlite3-multiple-ciphers`, or the ProcessExecutionBroker.

Use only for a rooted Android device and a WeChat account/database you are authorized to access.

## 1. Stage data from Android

From the repository root on Windows PowerShell or CMD:

```powershell
cd C:\Users\Administrator\Desktop\platform-tools\chainlesschain-dev
set PATH=C:\Users\Administrator\Desktop\platform-tools;%PATH%
```

In PowerShell, use:

```powershell
$env:Path = "C:\Users\Administrator\Desktop\platform-tools;$env:Path"
```

Run the Python staging script:

```powershell
python tools\wechat_stage_android.py --out C:\wechat-stage
```

The staging script follows the same minimum data collection as the original Magisk staging daemon:

- `enmm.enc.db` from `/data/data/com.tencent.mm/MicroMsg/.../EnMicroMsg.db`
- `uins.txt` from `/data/data/com.tencent.mm/shared_prefs/`
- `imeis.txt` from `settings get secure android_id` and best-effort `service call iphonesubinfo`
- `info.txt` with diagnostics

## 2. Decrypt with legacy UIN/IMEI key candidates

```powershell
node tools\wechat-decrypt-standalone.js ^
  --db C:\wechat-stage\enmm.enc.db ^
  --out C:\wechat-stage\decoded.db ^
  --uins C:\wechat-stage\uins.txt ^
  --imeis C:\wechat-stage\imeis.txt ^
  --force
```

PowerShell multiline form:

```powershell
node .\tools\wechat-decrypt-standalone.js `
  --db C:\wechat-stage\enmm.enc.db `
  --out C:\wechat-stage\decoded.db `
  --uins C:\wechat-stage\uins.txt `
  --imeis C:\wechat-stage\imeis.txt `
  --force
```

If successful, `C:\wechat-stage\decoded.db` is a normal SQLite database.

## 3. If legacy UIN/IMEI key derivation fails

The script will report:

```text
No key matched. Check UIN/IMEI, or use a saved --key / --raw-key for modern WeChat.
```

That usually means modern WeChat did not use a key derivable from the available IMEI/Android ID candidates. In that case you need either:

- a saved 7-character SQLCipher passphrase:

```powershell
node tools\wechat-decrypt-standalone.js --db C:\wechat-stage\enmm.enc.db --out C:\wechat-stage\decoded.db --key <7-char-key> --force
```

- or a 32-byte raw key hex captured from the live WeChat process:

```powershell
node tools\wechat-decrypt-standalone.js --db C:\wechat-stage\enmm.enc.db --out C:\wechat-stage\decoded.db --raw-key <64-hex-chars> --force
```

The repository's standalone Frida agent for the raw-key route is:

```text
tools/wechat-key-hook-standalone.js
```

The raw-key route requires rooted Android, a running compatible Frida server, and WeChat opened to a chat so `libWCDB.so` calls `sqlite3_key` / `sqlite3_key_v2`.

## 4. Frida raw-key route on Windows, Python-only

No `.ps1` scripts are needed.

### 4.1 Start matching frida-server on the phone

```powershell
$env:Path = "C:\Users\Administrator\Desktop\platform-tools;$env:Path"
python tools\wechat_frida_start_server.py
```

The script installs Python package `frida` for the current user if missing, detects the Android ABI, downloads the matching `frida-server` version from the official Frida GitHub release, pushes it to `/data/local/tmp/frida-server`, starts it as root, and verifies that Python Frida can connect.

### 4.2 Capture WeChat raw key

```powershell
python tools\wechat_frida_capture_key.py
```

While the script runs, unlock the phone and enter any WeChat chat. The capture script starts WeChat through Python Frida, loads `tools/wechat-key-hook-standalone.js`, and writes:

```text
C:\wechat-stage\raw-key.txt
C:\wechat-stage\raw-keys.json
C:\wechat-stage\frida-wechat-key.log
```

On some phones WeChat cannot be started by Frida spawn and fails with an error such as `java.lang.reflect.InvocationTargetException`. The Python script automatically falls back to normal `adb shell monkey` launch plus Frida attach. If you need to force manual attach mode, open WeChat manually first, enter any chat, then run:

```powershell
python tools\wechat_frida_capture_key.py --attach-only
```

### 4.3 Decrypt with captured raw key

```powershell
node tools\wechat-decrypt-standalone.js `
  --db C:\wechat-stage\enmm.enc.db `
  --out C:\wechat-stage\decoded.db `
  --raw-keys C:\wechat-stage\raw-keys.json `
  --force
```

If `decoded.db` is produced, it is a normal SQLite database.
