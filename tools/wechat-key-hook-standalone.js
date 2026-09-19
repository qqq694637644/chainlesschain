/**
 * Standalone Frida agent for Android WeChat SQLCipher key capture.
 *
 * This is intentionally plain Frida JS. No npm dependencies.
 * It emits one JSON object per line via console.log(), so the Windows
 * PowerShell capture script can parse frida's output log.
 *
 * Use only on a WeChat process/account/database you are authorized to access.
 */

/* eslint-disable */
/* global Module, Interceptor, Process, send, setTimeout, console */

'use strict';

(function () {
  var TARGET_MODULES = ['libWCDB.so', 'libwcdb.so'];
  var SYMBOLS = [
    'sqlite3_key',
    'sqlite3_key_v2',
    'wcdb_setkey',
    'WCDBKeyDerive',
    '_ZN4WCDB8Database13setCipherKeyERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE',
  ];

  // Longer than the project default 30s. On real phones WeChat may take
  // a while to unlock, enter a chat, and lazily open libWCDB.
  var MAX_ATTEMPTS = 360; // 360 * 500ms = 180s
  var INTERVAL_MS = 500;
  var fired = false;

  function emit(obj) {
    try { send(obj); } catch (_e) {}
    try { console.log(JSON.stringify(obj)); } catch (_e) {}
  }

  function bytesToHex(buf) {
    if (!buf || buf.byteLength === 0) return '';
    var bytes = new Uint8Array(buf);
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i].toString(16);
      if (b.length < 2) b = '0' + b;
      out += b;
    }
    return out;
  }

  function argIndicesFor(symbolName) {
    if (symbolName === 'sqlite3_key_v2') return { key: 2, len: 3, sig: 'v2' };
    if (symbolName.indexOf('_ZN4WCDB') === 0) return { key: -1, len: -1, sig: 'mangled-cpp' };
    return { key: 1, len: 2, sig: 'v1' };
  }

  function makeHook(symbolName) {
    var idx = argIndicesFor(symbolName);
    return {
      onEnter: function (args) {
        if (fired) return;
        if (idx.key < 0) {
          emit({ kind: 'error', message: 'unsupported symbol signature: ' + symbolName });
          return;
        }
        try {
          var len = args[idx.len].toInt32();
          if (len <= 0 || len > 256) {
            emit({ kind: 'error', message: 'implausible key length ' + len + ' at ' + symbolName });
            return;
          }

          var hex = null;
          var alt = null;
          var format = null;

          if (len === 64) {
            var s = Memory.readCString(args[idx.key], len);
            if (s) {
              hex = s.toLowerCase();
              format = 'ascii-hex';
            }
          } else if (len === 32) {
            hex = bytesToHex(args[idx.key].readByteArray(len));
            format = 'raw-bytes';
          } else {
            hex = bytesToHex(args[idx.key].readByteArray(len));
            try {
              var sAmb = Memory.readCString(args[idx.key], len);
              if (sAmb) alt = sAmb.toLowerCase();
            } catch (_e) {}
            format = 'ambiguous';
          }

          if (!hex) {
            emit({ kind: 'error', message: 'empty key at ' + symbolName });
            return;
          }

          fired = true;
          emit({
            kind: 'key',
            hex: hex,
            alt: alt,
            source: symbolName,
            sig: idx.sig,
            format: format,
            length: len,
          });
        } catch (e) {
          emit({ kind: 'error', message: 'hook exception at ' + symbolName + ': ' + (e && e.message ? e.message : String(e)) });
        }
      },
    };
  }

  function tryAttachOnModule(moduleName) {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) return false;

    var attached = 0;
    for (var i = 0; i < SYMBOLS.length; i++) {
      var symbol = SYMBOLS[i];
      var addr = Module.findExportByName(moduleName, symbol);
      if (!addr) continue;
      try {
        Interceptor.attach(addr, makeHook(symbol));
        emit({ kind: 'hooked', symbol: symbol, module: moduleName });
        attached++;
      } catch (e) {
        emit({ kind: 'error', message: 'Interceptor.attach failed for ' + symbol + ': ' + (e && e.message ? e.message : String(e)) });
      }
    }
    return attached > 0;
  }

  function tryAttach() {
    for (var i = 0; i < TARGET_MODULES.length; i++) {
      if (tryAttachOnModule(TARGET_MODULES[i])) return true;
    }
    return false;
  }

  emit({ kind: 'agent-started', pid: Process.id, arch: Process.arch, platform: Process.platform });

  if (!tryAttach()) {
    emit({ kind: 'module-waiting', module: TARGET_MODULES.join('|') });
    var attempts = 0;
    var poll = function () {
      attempts++;
      if (tryAttach()) return;
      if (attempts >= MAX_ATTEMPTS) {
        emit({ kind: 'error', message: TARGET_MODULES.join('|') + ' did not load within ' + Math.floor(MAX_ATTEMPTS * INTERVAL_MS / 1000) + 's' });
        return;
      }
      setTimeout(poll, INTERVAL_MS);
    };
    setTimeout(poll, INTERVAL_MS);
  }
})();
