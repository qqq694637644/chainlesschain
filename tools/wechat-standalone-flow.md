# Standalone Android WeChat decrypt flow

This is the lightweight version of the ChainlessChain WeChat database flow. It avoids the full CLI/workspace install and does not load Electron, `better-sqlite3-multiple-ciphers`, or the ProcessExecutionBroker.

Use only for a rooted Android device and a WeChat account/database you are authorized to access.

## 1. Stage data from Android

From the repository root on Windows PowerShell:

```powershell
$env:Path = "C:\Users\Administrator\Desktop\platform-tools;$env:Path"

.\tools\wechat-stage-android.ps1 -Out C:\wechat-stage
```

The staging script follows the same minimum data collection as the original Magisk staging daemon:

- `enmm.enc.db` from `/data/data/com.tencent.mm/MicroMsg/.../EnMicroMsg.db`
- `uins.txt` from `/data/data/com.tencent.mm/shared_prefs/`
- `imeis.txt` from `settings get secure android_id` and best-effort `service call iphonesubinfo`
- `info.txt` with diagnostics

## 2. Decrypt with the standalone Node script

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
node .\tools\wechat-decrypt-standalone.js --db C:\wechat-stage\enmm.enc.db --out C:\wechat-stage\decoded.db --key <7-char-key> --force
```

- or a 32-byte raw key hex captured from the live WeChat process:

```powershell
node .\tools\wechat-decrypt-standalone.js --db C:\wechat-stage\enmm.enc.db --out C:\wechat-stage\decoded.db --raw-key <64-hex-chars> --force
```

The repository's Frida agent for that raw-key route is:

```text
android-app/app/src/main/assets/frida/wechat-key-hook.js
```

The raw-key route requires rooted Android, a running compatible Frida injector/server, and WeChat opened to a chat so `libWCDB.so` calls `sqlite3_key` / `sqlite3_key_v2`.
