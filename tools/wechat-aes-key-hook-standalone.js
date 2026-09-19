/**
 * Standalone Frida agent for WeChat 8.x WCDB raw AES key capture.
 *
 * Based on the original ChainlessChain script:
 *   scripts/android/pdh-frida-wechat-aeskey.mjs
 *
 * WeChat 8.x WCDB may not call exported sqlite3_key/sqlite3_key_v2. The 32-byte
 * database AES key passes through an AES key-schedule function. Different
 * WeChat/Frida builds expose that symbol through different APIs, so this agent
 * resolves it through several paths and prints diagnostics when not found.
 *
 * This agent intentionally dual-emits every event with both send() and
 * console.log(JSON.stringify(...)) so it works with frida-inject stdout parsing.
 */

/* eslint-disable */
/* global Module, DebugSymbol, Interceptor, Process, Memory, send, setInterval, clearInterval, console */

'use strict';

(function () {
  var MODULES = ['libWCDB.so', 'libwcdb.so', 'libwcdb_legacy.so', 'libcrypto.so'];
  var TARGET_SYMBOLS = [
    'aes_v8_set_encrypt_key',
    'AES_set_encrypt_key',
    'AES_set_decrypt_key',
  ];
  var seen = {};
  var hooked = {};
  var reportedModules = {};
  var reportedExports = {};
  var reportedApi = false;

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

  function moduleExports(m, moduleName) {
    try {
      if (m && typeof m.enumerateExports === 'function') return m.enumerateExports();
    } catch (_e1) {}
    try {
      if (typeof Module.enumerateExports === 'function') return Module.enumerateExports(moduleName);
    } catch (_e2) {}
    try {
      if (typeof Module.enumerateExportsSync === 'function') return Module.enumerateExportsSync(moduleName);
    } catch (_e3) {}
    return [];
  }

  function moduleSymbols(m, moduleName) {
    try {
      if (m && typeof m.enumerateSymbols === 'function') return m.enumerateSymbols();
    } catch (_e1) {}
    try {
      if (typeof Module.enumerateSymbols === 'function') return Module.enumerateSymbols(moduleName);
    } catch (_e2) {}
    try {
      if (typeof Module.enumerateSymbolsSync === 'function') return Module.enumerateSymbolsSync(moduleName);
    } catch (_e3) {}
    return [];
  }

  function findExportByApi(m, moduleName, symbol) {
    try {
      if (m && typeof m.findExportByName === 'function') {
        var a0 = m.findExportByName(symbol);
        if (a0) return a0;
      }
    } catch (_e0) {}
    try {
      if (m && typeof m.getExportByName === 'function') return m.getExportByName(symbol);
    } catch (_e00) {}
    try {
      if (typeof Module.findExportByName === 'function') {
        var a1 = Module.findExportByName(moduleName, symbol);
        if (a1) return a1;
      }
    } catch (_e1) {}
    try {
      if (typeof Module.getExportByName === 'function') return Module.getExportByName(moduleName, symbol);
    } catch (_e2) {}
    try {
      var exps = moduleExports(m, moduleName);
      for (var i = 0; i < exps.length; i++) {
        if (exps[i].name === symbol) return exps[i].address;
      }
    } catch (_e3) {}
    return null;
  }

  function findSymbolByEnumeration(m, moduleName, symbol) {
    var syms = moduleSymbols(m, moduleName);
    for (var i = 0; i < syms.length; i++) {
      if (syms[i].name === symbol) return syms[i].address;
    }
    return null;
  }

  function findSymbolByDebugSymbol(symbol) {
    try {
      if (typeof DebugSymbol !== 'undefined' && typeof DebugSymbol.findFunctionsMatching === 'function') {
        var pats = [
          '*!' + symbol,
          '*' + symbol + '*',
        ];
        for (var i = 0; i < pats.length; i++) {
          var xs = DebugSymbol.findFunctionsMatching(pats[i]);
          if (xs && xs.length > 0) return xs[0];
        }
      }
    } catch (_e) {}
    return null;
  }

  function reportApiOnce() {
    if (reportedApi) return;
    reportedApi = true;
    emit({
      kind: 'frida-api',
      module_find_export: typeof Module.findExportByName,
      module_get_export: typeof Module.getExportByName,
      module_find_global: typeof Module.findGlobalExportByName,
      module_get_global: typeof Module.getGlobalExportByName,
      debug_find_functions: (typeof DebugSymbol !== 'undefined') ? typeof DebugSymbol.findFunctionsMatching : 'undefined',
    });
  }

  function reportModuleNoTarget(m, moduleName) {
    if (reportedExports[moduleName]) return;
    reportedExports[moduleName] = 1;

    var matches = [];
    var exps = moduleExports(m, moduleName);
    for (var i = 0; i < exps.length && matches.length < 80; i++) {
      var n = exps[i].name || '';
      if (/aes|encrypt|decrypt|key|sqlite|wcdb|cipher/i.test(n)) matches.push('export:' + n);
    }

    var syms = moduleSymbols(m, moduleName);
    for (var j = 0; j < syms.length && matches.length < 140; j++) {
      var s = syms[j].name || '';
      if (/aes|encrypt|decrypt|key|sqlite|wcdb|cipher/i.test(s)) matches.push('symbol:' + s);
    }

    emit({ kind: 'module-seen-no-target', module: moduleName, targets: TARGET_SYMBOLS, matches: matches });
  }

  function findTargets() {
    reportApiOnce();
    var found = [];

    for (var i = 0; i < MODULES.length; i++) {
      var moduleName = MODULES[i];
      var m = null;
      try { m = Process.findModuleByName(moduleName); } catch (_e) { m = null; }
      if (!m) continue;

      if (!reportedModules[moduleName]) {
        reportedModules[moduleName] = 1;
        emit({ kind: 'module-seen', module: moduleName, base: String(m.base), path: m.path || '' });
      }

      var moduleFound = false;
      for (var si = 0; si < TARGET_SYMBOLS.length; si++) {
        var sym = TARGET_SYMBOLS[si];
        var addr = findExportByApi(m, moduleName, sym) || findSymbolByEnumeration(m, moduleName, sym);
        if (addr) {
          moduleFound = true;
          found.push({ addr: addr, module: moduleName, symbol: sym });
        }
      }
      if (!moduleFound) reportModuleNoTarget(m, moduleName);
    }

    for (var gi = 0; gi < TARGET_SYMBOLS.length; gi++) {
      var gsym = TARGET_SYMBOLS[gi];
      var gaddr = null;
      try {
        if (typeof Module.findGlobalExportByName === 'function') gaddr = Module.findGlobalExportByName(gsym);
      } catch (_ge1) {}
      try {
        if (!gaddr && typeof Module.getGlobalExportByName === 'function') gaddr = Module.getGlobalExportByName(gsym);
      } catch (_ge2) {}
      if (!gaddr) gaddr = findSymbolByDebugSymbol(gsym);
      if (gaddr) found.push({ addr: gaddr, module: 'global/debug', symbol: gsym });
    }

    return found;
  }

  function hookOne(found) {
    var id = found.module + '!' + found.symbol + '@' + String(found.addr);
    if (hooked[id]) return true;

    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try {
          // AES_set_encrypt_key / aes_v8_set_encrypt_key:
          //   const unsigned char *userKey, const int bits, ...
          var bits = args[1].toInt32();
          if (bits !== 128 && bits !== 192 && bits !== 256) return;
          var key = hex(args[0].readByteArray(bits / 8));
          if (!key || seen[key]) return;
          seen[key] = 1;
          emit({
            kind: 'key',
            hex: key,
            key: key,
            source: found.symbol,
            module: found.module,
            bits: bits,
          });
        } catch (e) {
          emit({ kind: 'error', source: found.symbol, message: String(e && e.message ? e.message : e) });
        }
      },
    });

    hooked[id] = 1;
    emit({ kind: 'hooked', source: found.symbol, module: found.module, address: String(found.addr) });
    return true;
  }

  function hook() {
    var found = findTargets();
    var count = 0;
    for (var i = 0; i < found.length; i++) {
      try {
        if (hookOne(found[i])) count++;
      } catch (e) {
        emit({ kind: 'error', source: found[i].symbol, module: found[i].module, message: String(e && e.message ? e.message : e) });
      }
    }
    return count > 0;
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
    emit({ kind: 'waiting', source: TARGET_SYMBOLS.join('|'), module: MODULES.join('|') });
    var attempts = 0;
    var timer = setInterval(function () {
      attempts++;
      if (hook() || attempts > 300) {
        clearInterval(timer);
        if (Object.keys(hooked).length === 0) emit({ kind: 'error', source: TARGET_SYMBOLS.join('|'), message: 'no target symbol found after waiting' });
      }
    }, 500);
  }
})();
