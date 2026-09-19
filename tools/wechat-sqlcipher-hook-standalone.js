/**
 * Standalone Frida agent for Android WeChat EnMicroMsg.db SQLCipher/WCDB probing.
 *
 * This targets the database layer, not AES key schedule functions:
 *   1. Java WCDB openDatabase/openOrCreateDatabase byte[] password.
 *   2. Native sqlite3_key/sqlite3_key_v2 byte[] password/raw key.
 *   3. Native sqlite3_prepare* DB handles, then Method C online export:
 *        ATTACH DATABASE '<app-cache-out>' AS ccpt KEY '';
 *        SELECT sqlcipher_export('ccpt');
 *        DETACH DATABASE ccpt;
 *
 * It dual-emits send() and console.log(JSON.stringify(...)) for frida-inject.
 */

/* eslint-disable */
/* global Java, Module, DebugSymbol, Interceptor, NativeFunction, Process, Memory, NULL, send, console */

'use strict';

(function () {
  var DB_MATCH = /\/EnMicroMsg\.db$/;
  var OUTDIR = '/data/data/com.tencent.mm/cache/';
  var MODULE_NAMES = ['libWCDB.so', 'libwcdb_legacy.so', 'libwcdb.so', 'libsqlite.so'];
  var installedNative = {};
  var doneExport = {};
  var seenDb = {};
  var seenKeys = {};
  var inExec = false;
  var exportSeq = 0;

  function emit(obj) {
    try { send(obj); } catch (_e) {}
    try { console.log(JSON.stringify(obj)); } catch (_e2) {}
  }

  function hexByte(v) {
    if (v < 0) v += 256;
    var h = v.toString(16);
    return h.length === 1 ? '0' + h : h;
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += hexByte(bytes[i]);
    return out;
  }

  function bytesToAscii(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var v = bytes[i];
      if (v < 0) v += 256;
      if (v === 0) break;
      if (v < 32 || v > 126) return null;
      out += String.fromCharCode(v);
    }
    return out;
  }

  function ptrBytes(p, n) {
    if (!p || p.isNull() || !n || n <= 0 || n > 4096) return [];
    var arr = new Uint8Array(p.readByteArray(n));
    var out = [];
    for (var i = 0; i < arr.length; i++) out.push(arr[i]);
    return out;
  }

  function javaByteArrayToBytes(arr) {
    var out = [];
    if (!arr) return out;
    var len = arr.length;
    for (var i = 0; i < len; i++) out.push(arr[i]);
    return out;
  }

  function emitKey(bytes, source, meta) {
    if (!bytes || bytes.length === 0) return;
    var h = bytesToHex(bytes).toLowerCase();
    var ascii = bytesToAscii(bytes);
    var emitted = false;
    meta = meta || {};

    function base(kind) {
      var o = {
        kind: 'key',
        candidateType: kind,
        source: source,
        length: bytes.length,
        hex: h,
      };
      for (var k in meta) o[k] = meta[k];
      if (ascii != null) o.ascii = ascii;
      return o;
    }

    if (ascii && ascii.length > 0 && ascii.length <= 128) {
      // SQLCipher passphrases are often 7 printable chars on Android WeChat.
      var id1 = 'pass:' + ascii;
      if (!seenKeys[id1]) {
        seenKeys[id1] = 1;
        var ev1 = base('passphrase');
        ev1.key = ascii;
        emit(ev1);
        emitted = true;
      }
      // If password itself is x'<64hex>' or raw 64-hex ASCII, also emit raw.
      var m = /^x'([0-9a-fA-F]{64})'$/.exec(ascii) || /^([0-9a-fA-F]{64})$/.exec(ascii);
      if (m) {
        var rawHex = m[1].toLowerCase();
        var id2 = 'raw:' + rawHex;
        if (!seenKeys[id2]) {
          seenKeys[id2] = 1;
          var ev2 = base('raw-key');
          ev2.key = rawHex;
          ev2.hex = rawHex;
          emit(ev2);
          emitted = true;
        }
      }
    }

    if (bytes.length === 32) {
      var id3 = 'raw:' + h;
      if (!seenKeys[id3]) {
        seenKeys[id3] = 1;
        var ev3 = base('raw-key');
        ev3.key = h;
        emit(ev3);
        emitted = true;
      }
    }

    if (!emitted) {
      var id4 = 'unknown:' + h;
      if (!seenKeys[id4]) {
        seenKeys[id4] = 1;
        emit(base('unknown'));
      }
    }
  }

  function moduleByName(name) {
    try { return Process.findModuleByName(name); } catch (_e) { return null; }
  }

  function enumerateExports(m, name) {
    try { if (m && typeof m.enumerateExports === 'function') return m.enumerateExports(); } catch (_e1) {}
    try { if (typeof Module.enumerateExports === 'function') return Module.enumerateExports(name); } catch (_e2) {}
    try { if (typeof Module.enumerateExportsSync === 'function') return Module.enumerateExportsSync(name); } catch (_e3) {}
    return [];
  }

  function enumerateSymbols(m, name) {
    try { if (m && typeof m.enumerateSymbols === 'function') return m.enumerateSymbols(); } catch (_e1) {}
    try { if (typeof Module.enumerateSymbols === 'function') return Module.enumerateSymbols(name); } catch (_e2) {}
    try { if (typeof Module.enumerateSymbolsSync === 'function') return Module.enumerateSymbolsSync(name); } catch (_e3) {}
    return [];
  }

  function findInModule(m, moduleName, sym) {
    try { if (m && typeof m.findExportByName === 'function') { var a = m.findExportByName(sym); if (a) return a; } } catch (_e0) {}
    try { if (m && typeof m.getExportByName === 'function') return m.getExportByName(sym); } catch (_e1) {}
    var exps = enumerateExports(m, moduleName);
    for (var i = 0; i < exps.length; i++) if (exps[i].name === sym) return exps[i].address;
    var syms = enumerateSymbols(m, moduleName);
    for (var j = 0; j < syms.length; j++) if (syms[j].name === sym) return syms[j].address;
    return null;
  }

  function findGlobal(sym) {
    try { if (typeof Module.findGlobalExportByName === 'function') { var a = Module.findGlobalExportByName(sym); if (a) return a; } } catch (_e1) {}
    try { if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(sym); } catch (_e2) {}
    try {
      if (typeof DebugSymbol !== 'undefined' && typeof DebugSymbol.findFunctionsMatching === 'function') {
        var xs = DebugSymbol.findFunctionsMatching('*' + sym + '*');
        if (xs && xs.length) return xs[0];
      }
    } catch (_e3) {}
    return null;
  }

  function findAny(sym) {
    for (var i = 0; i < MODULE_NAMES.length; i++) {
      var name = MODULE_NAMES[i];
      var m = moduleByName(name);
      if (!m) continue;
      var a = findInModule(m, name, sym);
      if (a) return { address: a, module: name };
    }
    var g = findGlobal(sym);
    return g ? { address: g, module: 'global' } : null;
  }

  function cString(s) {
    return Memory.allocUtf8String(s);
  }

  function sqlQuote(s) {
    return String(s).replace(/'/g, "''");
  }

  function baseName(p) {
    return String(p || '').split('/').pop().replace(/[^A-Za-z0-9_.-]/g, '_');
  }

  function filenameOf(db, api) {
    if (!api || !api.dbFilename || !db || db.isNull()) return null;
    try {
      var fn = new NativeFunction(api.dbFilename, 'pointer', ['pointer', 'pointer']);
      var p = fn(db, cString('main'));
      if (!p || p.isNull()) return null;
      return p.readUtf8String();
    } catch (e) {
      emit({ kind: 'error', source: 'sqlite3_db_filename', message: String(e && e.message ? e.message : e) });
      return null;
    }
  }

  function execOn(db, sql, api) {
    var exec = new NativeFunction(api.exec, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    var errOut = Memory.alloc(Process.pointerSize);
    errOut.writePointer(NULL);
    inExec = true;
    var rc = -999;
    try {
      rc = exec(db, cString(sql), NULL, NULL, errOut);
    } finally {
      inExec = false;
    }
    var ep = errOut.readPointer();
    var msg = '';
    try { msg = ep.isNull() ? '' : ep.readUtf8String(); } catch (_e) {}
    return { rc: rc, msg: msg };
  }

  function tryExport(db, api, reason) {
    if (inExec || !api || !api.exec || !api.dbFilename || !db || db.isNull()) return;
    var fn = filenameOf(db, api);
    if (!fn) return;
    if (!seenDb[fn]) {
      seenDb[fn] = 1;
      if (/MicroMsg|\.db$/i.test(fn)) emit({ kind: 'db-seen', path: fn, reason: reason, module: api.module });
    }
    if (!DB_MATCH.test(fn)) return;

    // Retry failed exports, but don't retry a successful source DB.
    if (doneExport[fn] === 'ok') return;

    exportSeq++;
    var alias = 'ccpt' + exportSeq;
    var out = OUTDIR + 'cc_plain_' + Date.now() + '_' + baseName(fn) + '.plain.db';
    var sql = "ATTACH DATABASE '" + sqlQuote(out) + "' AS " + alias + " KEY ''; " +
      "SELECT sqlcipher_export('" + alias + "'); " +
      "DETACH DATABASE " + alias + ";";
    var r = execOn(db, sql, api);
    emit({ kind: 'export', src: fn, out: out, rc: r.rc, msg: r.msg, reason: reason, module: api.module });
    doneExport[fn] = r.rc === 0 ? 'ok' : 'failed';
  }

  function buildApi(moduleName) {
    var m = moduleByName(moduleName);
    if (!m) return null;
    var api = {
      module: moduleName,
      exec: findInModule(m, moduleName, 'sqlite3_exec'),
      dbFilename: findInModule(m, moduleName, 'sqlite3_db_filename'),
      key: findInModule(m, moduleName, 'sqlite3_key'),
      keyV2: findInModule(m, moduleName, 'sqlite3_key_v2'),
      prepare: findInModule(m, moduleName, 'sqlite3_prepare'),
      prepareV2: findInModule(m, moduleName, 'sqlite3_prepare_v2'),
      prepareV3: findInModule(m, moduleName, 'sqlite3_prepare_v3'),
    };
    var names = [];
    ['exec', 'dbFilename', 'key', 'keyV2', 'prepare', 'prepareV2', 'prepareV3'].forEach(function (k) {
      if (api[k]) names.push(k);
    });
    if (names.length) emit({ kind: 'native-api', module: moduleName, functions: names });
    return api;
  }

  function hookNativeKey(api, symbol, addr, isV2) {
    if (!addr) return;
    var id = api.module + '!' + symbol + '@' + String(addr);
    if (installedNative[id]) return;
    installedNative[id] = 1;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.db = args[0];
        try {
          var keyPtr = isV2 ? args[2] : args[1];
          var len = (isV2 ? args[3] : args[2]).toInt32();
          var fn = filenameOf(this.db, api);
          emitKey(ptrBytes(keyPtr, len), symbol, { path: fn || '', module: api.module, nativeLen: len });
        } catch (e) {
          emit({ kind: 'error', source: symbol, module: api.module, message: String(e && e.message ? e.message : e) });
        }
      },
      onLeave: function () {
        try { tryExport(this.db, api, symbol); } catch (e) { emit({ kind: 'error', source: 'export-after-' + symbol, message: String(e && e.message ? e.message : e) }); }
      },
    });
    emit({ kind: 'hooked', layer: 'native', source: symbol, module: api.module, address: String(addr) });
  }

  function hookNativePrepare(api, symbol, addr) {
    if (!addr) return;
    var id = api.module + '!' + symbol + '@' + String(addr);
    if (installedNative[id]) return;
    installedNative[id] = 1;
    Interceptor.attach(addr, {
      onEnter: function (args) { this.db = args[0]; },
      onLeave: function () {
        try { tryExport(this.db, api, symbol); } catch (e) { emit({ kind: 'error', source: 'export-after-' + symbol, module: api.module, message: String(e && e.message ? e.message : e) }); }
      },
    });
    emit({ kind: 'hooked', layer: 'native', source: symbol, module: api.module, address: String(addr) });
  }

  function installNative() {
    var any = false;
    for (var i = 0; i < MODULE_NAMES.length; i++) {
      var api = buildApi(MODULE_NAMES[i]);
      if (!api) continue;
      any = true;
      hookNativeKey(api, 'sqlite3_key', api.key, false);
      hookNativeKey(api, 'sqlite3_key_v2', api.keyV2, true);
      hookNativePrepare(api, 'sqlite3_prepare', api.prepare);
      hookNativePrepare(api, 'sqlite3_prepare_v2', api.prepareV2);
      hookNativePrepare(api, 'sqlite3_prepare_v3', api.prepareV3);
    }
    if (!any) emit({ kind: 'native-waiting', modules: MODULE_NAMES });
  }

  function inspectJavaArgs(methodName, argTypes, args) {
    var path = '';
    var byteIndexes = [];
    for (var i = 0; i < argTypes.length; i++) {
      try {
        if (argTypes[i] === 'java.lang.String' && args[i] != null) {
          var s = String(args[i]);
          if (/\.db$/i.test(s) || /MicroMsg/i.test(s)) path = s;
        }
        if (argTypes[i] === '[B' && args[i] != null) byteIndexes.push(i);
      } catch (_e) {}
    }
    if (!path || !DB_MATCH.test(path)) return;
    for (var j = 0; j < byteIndexes.length; j++) {
      var idx = byteIndexes[j];
      emitKey(javaByteArrayToBytes(args[idx]), 'java:' + methodName, { path: path, javaArgIndex: idx });
    }
  }

  function installJava() {
    if (typeof Java === 'undefined' || !Java.available) {
      emit({ kind: 'java-unavailable' });
      return;
    }
    Java.perform(function () {
      var classes = [
        'com.tencent.wcdb.database.SQLiteDatabase',
        'com.tencent.wcdb.database.SQLiteConnection',
      ];
      for (var ci = 0; ci < classes.length; ci++) {
        try {
          var clsName = classes[ci];
          var cls = Java.use(clsName);
          ['openDatabase', 'openOrCreateDatabase', 'openInner', 'open'].forEach(function (name) {
            try {
              var method = cls[name];
              if (!method || !method.overloads) return;
              method.overloads.forEach(function (ov, idx) {
                var argTypes = ov.argumentTypes.map(function (t) { return t.name; });
                if (argTypes.indexOf('[B') < 0 || argTypes.indexOf('java.lang.String') < 0) return;
                var id = clsName + '.' + name + '#' + idx + '(' + argTypes.join(',') + ')';
                ov.implementation = function () {
                  try { inspectJavaArgs(id, argTypes, arguments); } catch (e) { emit({ kind: 'error', source: id, message: String(e && e.message ? e.message : e) }); }
                  return ov.apply(this, arguments);
                };
                emit({ kind: 'hooked', layer: 'java', source: id });
              });
            } catch (_eMethod) {}
          });
        } catch (eCls) {
          emit({ kind: 'java-class-missing', className: classes[ci], message: String(eCls && eCls.message ? eCls.message : eCls) });
        }
      }
    });
  }

  emit({ kind: 'agent-started', pid: Process.id, arch: Process.arch, platform: Process.platform, mode: 'sqlcipher-wcdb' });
  installJava();
  installNative();
})();
