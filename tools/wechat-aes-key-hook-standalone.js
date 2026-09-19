/**
 * Standalone Frida agent for WeChat 8.x WCDB raw AES key capture.
 *
 * Based on the original ChainlessChain script:
 *   scripts/android/pdh-frida-wechat-aeskey.mjs
 *
 * WeChat 8.x WCDB may not call exported sqlite3_key/sqlite3_key_v2. The 32-byte
 * database AES key passes through aes_v8_set_encrypt_key in libWCDB.so.
 *
 * This agent intentionally dual-emits every event with both send() and
 * console.log(JSON.stringify(...)) so it works with frida-inject stdout parsing.
 */

/* eslint-disable */
/* global Module, Interceptor, Process, Memory, send, setInterval, clearInterval, console */

'use strict';

(function () {
  var MODULES = ['libWCDB.so', 'libwcdb.so'];
  var SYMBOL = 'aes_v8_set_encrypt_key';
  var seen = {};
  var hooked = false;
  var reportedModules = {};
  var reportedExports = {};

  function emit(obj) {
    try { send(obj); } catch (_e) {}
    try { console.log(JSON.stringify(obj)); } catch (_e) {}
  }

  function hex(buf) {
    if (!buf || buf.byteLength === 0) return '';
    var b = new Uint8Array(buf);
    var o = '';
    for (var i = 0; i < b.length; i++) {
      var h = b[i].toString(16);
      if (h.length < 2) h = '0' + h;
      o += h;
    }
    return o;
  }

  function findExport() {
    for (var i = 0; i < MODULES.length; i++) {
      try {
        var m = Process.findModuleByName(MODULES[i]);
        if (!m) continue;
        if (!reportedModules[MODULES[i]]) {
          reportedModules[MODULES[i]] = 1;
          emit({ kind: 'module-seen', module: MODULES[i], base: String(m.base), path: m.path || '' });
        }
        var a = Module.findExportByName(MODULES[i], SYMBOL);
        if (a) return { addr: a, module: MODULES[i] };
        if (!reportedExports[MODULES[i]]) {
          reportedExports[MODULES[i]] = 1;
          var matches = [];
          try {
            var exps = m.enumerateExports();
            for (var j = 0; j < exps.length; j++) {
              var n = exps[j].name || '';
              if (/aes|key|sqlite|wcdb/i.test(n)) matches.push(n);
              if (matches.length >= 80) break;
            }
          } catch (ee) {
            matches.push('enumerateExports failed: ' + String(ee && ee.message ? ee.message : ee));
          }
          emit({ kind: 'module-seen-no-symbol', module: MODULES[i], symbol: SYMBOL, exports: matches });
        }
      } catch (_e) {}
    }
    try {
      var g = Module.findGlobalExportByName(SYMBOL);
      if (g) return { addr: g, module: 'global' };
    } catch (_e2) {}
    return null;
  }

  function hook() {
    if (hooked) return true;
    var found = findExport();
    if (!found) return false;

    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try {
          // aes_v8_set_encrypt_key(const unsigned char *userKey, const int bits, ...)
          var bits = args[1].toInt32();
          if (bits !== 128 && bits !== 192 && bits !== 256) return;
          var key = hex(args[0].readByteArray(bits / 8));
          if (!key || seen[key]) return;
          seen[key] = 1;
          emit({
            kind: 'key',
            hex: key,
            key: key,
            source: SYMBOL,
            module: found.module,
            bits: bits,
          });
        } catch (e) {
          emit({ kind: 'error', source: SYMBOL, message: String(e && e.message ? e.message : e) });
        }
      },
    });

    hooked = true;
    emit({ kind: 'hooked', source: SYMBOL, module: found.module });
    return true;
  }

  emit({ kind: 'agent-started', pid: Process.id, arch: Process.arch, platform: Process.platform });

  try {
    var wcdbMods = [];
    var mods = Process.enumerateModules();
    for (var mi = 0; mi < mods.length; mi++) {
      var nm = mods[mi].name || '';
      var pth = mods[mi].path || '';
      if (/wcdb|sqlite|sqlcipher|crypto|ssl/i.test(nm) || /wcdb|sqlite|sqlcipher|crypto|ssl/i.test(pth)) {
        wcdbMods.push({ name: nm, path: pth });
      }
      if (wcdbMods.length >= 40) break;
    }
    emit({ kind: 'module-snapshot', modules: wcdbMods });
  } catch (se) {
    emit({ kind: 'error', source: 'module-snapshot', message: String(se && se.message ? se.message : se) });
  }

  if (!hook()) {
    emit({ kind: 'waiting', source: SYMBOL, module: MODULES.join('|') });
    var attempts = 0;
    var timer = setInterval(function () {
      attempts++;
      if (hook() || attempts > 300) {
        clearInterval(timer);
        if (!hooked) emit({ kind: 'error', source: SYMBOL, message: 'symbol not found after waiting' });
      }
    }, 500);
  }
})();
