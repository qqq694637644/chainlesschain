#!/usr/bin/env node
'use strict';

/**
 * Standalone Android WeChat EnMicroMsg.db decryptor.
 *
 * Zero npm dependencies. This intentionally does NOT import ChainlessChain CLI,
 * personal-data-hub, better-sqlite3, Electron, or any workspace package.
 *
 * Supported key candidates:
 *   - legacy passphrase: MD5(IMEI + UIN).slice(0, 7)
 *   - saved 7-char SQLCipher passphrase via --key / --keys
 *   - 32-byte raw key hex via --raw-key / --raw-keys
 *
 * The output is a plain SQLite database file that can be opened by sqlite3,
 * DB Browser for SQLite, wechat-dump, etc.
 *
 * Use only for databases you are authorized to access.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIGS = [
  { name: 'sqlcipher1', pageSize: 1024, reserve: 16, hmac: 0, kdf: 4000, algo: 'sha1' },
  { name: 'sqlcipher2', pageSize: 1024, reserve: 48, hmac: 20, kdf: 4000, algo: 'sha1' },
  { name: 'sqlcipher3', pageSize: 1024, reserve: 48, hmac: 20, kdf: 64000, algo: 'sha1' },
  { name: 'sqlcipher4', pageSize: 4096, reserve: 80, hmac: 64, kdf: 256000, algo: 'sha512' },
];

function usage(exitCode = 0) {
  const text = `
Standalone Android WeChat EnMicroMsg.db decryptor

Usage:
  node tools/wechat-decrypt-standalone.js --db EnMicroMsg.db --out decoded.db --uin <uin> --imei <imei>
  node tools/wechat-decrypt-standalone.js --db EnMicroMsg.db --out decoded.db --uins uins.txt --imeis imeis.txt
  node tools/wechat-decrypt-standalone.js --db EnMicroMsg.db --out decoded.db --key <7-char-key>
  node tools/wechat-decrypt-standalone.js --db EnMicroMsg.db --out decoded.db --raw-key <64-hex-chars>

Options:
  --db <path>          Encrypted EnMicroMsg.db input file. Required.
  --out <path>         Decrypted SQLite output file. Default: decoded.db
  --uin <value>        Numeric UIN candidate. Can be repeated.
  --uins <path>        Text file with one UIN candidate per line.
  --imei <value>       IMEI / Android ID candidate. Can be repeated.
  --imeis <path>       Text file with one IMEI candidate per line.
  --key <value>        Saved 7-char SQLCipher passphrase. Can be repeated.
  --keys <path>        Text file with one saved key per line.
  --raw-key <hex>      32-byte raw SQLCipher key as 64 hex chars. Can be repeated.
  --raw-keys <path>    JSON array or text file with raw-key hex values.
  --force              Overwrite output file if it already exists.
  --quiet              Only print errors.
  -h, --help           Show this help.

Notes:
  Legacy Android WeChat commonly used key = MD5(IMEI + UIN).slice(0, 7).
  Modern WeChat may require a saved key or raw key captured from the app process.
`;
  console.log(text.trimStart());
  process.exit(exitCode);
}

function parseArgs(argv) {
  const out = {
    db: null,
    out: 'decoded.db',
    uins: [],
    imeis: [],
    keys: [],
    rawKeys: [],
    force: false,
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`Missing value for ${a}`);
      return argv[++i];
    };
    switch (a) {
      case '-h':
      case '--help':
        usage(0);
        break;
      case '--db':
        out.db = next();
        break;
      case '--out':
        out.out = next();
        break;
      case '--uin':
        out.uins.push(next());
        break;
      case '--uins':
        out.uins.push(...readListFile(next()));
        break;
      case '--imei':
        out.imeis.push(next());
        break;
      case '--imeis':
        out.imeis.push(...readListFile(next()));
        break;
      case '--key':
        out.keys.push(next());
        break;
      case '--keys':
        out.keys.push(...readListFile(next()));
        break;
      case '--raw-key':
        out.rawKeys.push(next());
        break;
      case '--raw-keys':
        out.rawKeys.push(...readRawKeysFile(next()));
        break;
      case '--force':
        out.force = true;
        break;
      case '--quiet':
        out.quiet = true;
        break;
      default:
        throw new Error(`Unknown argument: ${a}`);
    }
  }
  return out;
}

function readListFile(file) {
  return fs.readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#'));
}

function readRawKeysFile(file) {
  const txt = fs.readFileSync(file, 'utf8').trim();
  if (!txt) return [];
  if (txt.startsWith('[')) {
    const arr = JSON.parse(txt);
    if (!Array.isArray(arr)) throw new Error(`Raw key JSON must be an array: ${file}`);
    return arr.map(String);
  }
  return readListFile(file);
}

function uniq(xs) {
  return [...new Set(xs.map((x) => String(x).trim()).filter(Boolean))];
}

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function computePassphrases(imeis, uins, savedKeys) {
  const set = new Set(uniq(savedKeys));
  // Match the ChainlessChain collect-wechat CLI behavior: Android 13+
  // often blocks the real IMEI, so always try the empty IMEI and the legacy
  // placeholder candidate in addition to whatever the staging step found.
  const imeiCandidates = uniq([...imeis, '', '1234567890ABCDE']);
  for (const imei of imeiCandidates) {
    for (const uin of uniq(uins)) {
      set.add(md5(String(imei) + String(uin)).slice(0, 7));
    }
  }
  return [...set];
}

function decodeRawKeys(values) {
  return uniq(values).map((hex) => {
    const normalized = hex.replace(/^0x/i, '').replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
      throw new Error(`Invalid raw key, expected 64 hex chars: ${hex}`);
    }
    return Buffer.from(normalized, 'hex');
  });
}

function decryptPage(page, key, cfg, isFirstPage) {
  const reserveOffset = cfg.pageSize - cfg.reserve;
  const ciphertext = page.subarray(isFirstPage ? 16 : 0, reserveOffset);
  const reserved = page.subarray(reserveOffset, cfg.pageSize);
  const iv = cfg.hmac ? reserved.subarray(cfg.hmac, cfg.hmac + 16) : reserved.subarray(0, 16);
  if (iv.length < 16) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

function validFirstBtreePage(plain) {
  return !!(plain && plain.length > 8 && plain[5] === 64 && plain[6] === 32 && plain[7] === 32);
}

function findKey(raw, passphrases, rawKeys) {
  const salt = raw.subarray(0, 16);
  for (const cfg of CONFIGS) {
    for (const pass of passphrases) {
      const digest = cfg.algo === 'sha512' ? 'sha512' : 'sha1';
      const key = crypto.pbkdf2Sync(Buffer.from(pass, 'utf8'), salt, cfg.kdf, 32, digest);
      if (validFirstBtreePage(decryptPage(raw.subarray(0, cfg.pageSize), key, cfg, true))) {
        return { cfg, key, pass, kind: 'passphrase' };
      }
    }
    for (const key of rawKeys) {
      if (validFirstBtreePage(decryptPage(raw.subarray(0, cfg.pageSize), key, cfg, true))) {
        return { cfg, key, pass: null, kind: 'raw-key' };
      }
    }
  }
  return null;
}

function decryptDatabase(raw, found) {
  const { cfg, key } = found;
  const pageCount = Math.floor(raw.length / cfg.pageSize);
  if (pageCount <= 0) throw new Error(`Input is smaller than one ${cfg.pageSize}-byte page`);

  const pages = [];
  for (let i = 0; i < pageCount; i++) {
    const page = raw.subarray(i * cfg.pageSize, (i + 1) * cfg.pageSize);
    const plain = decryptPage(page, key, cfg, i === 0);
    if (!plain) throw new Error(`Failed to decrypt page ${i + 1}`);

    const outPage = Buffer.alloc(cfg.pageSize);
    if (i === 0) {
      Buffer.from('SQLite format 3\0').copy(outPage, 0);
      plain.copy(outPage, 16);
    } else {
      plain.copy(outPage, 0);
    }
    pages.push(outPage);
  }
  return Buffer.concat(pages);
}

function looksPlainSQLite(raw) {
  return raw.length >= 16 && raw.subarray(0, 16).toString('binary') === 'SQLite format 3\0';
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const log = (...xs) => { if (!args.quiet) console.log(...xs); };

  if (!args.db) usage(1);
  if (!fs.existsSync(args.db)) throw new Error(`Input db not found: ${args.db}`);
  if (fs.existsSync(args.out) && !args.force) {
    throw new Error(`Output already exists: ${args.out}. Use --force to overwrite.`);
  }

  const raw = fs.readFileSync(args.db);
  if (looksPlainSQLite(raw)) {
    fs.copyFileSync(args.db, args.out);
    log(`Input is already plain SQLite. Copied to: ${args.out}`);
    return;
  }

  const passphrases = computePassphrases(args.imeis, args.uins, args.keys);
  const rawKeys = decodeRawKeys(args.rawKeys);
  if (!passphrases.length && !rawKeys.length) {
    throw new Error('No key candidates. Provide --uin + --imei, or --key, or --raw-key.');
  }

  log(`Trying ${passphrases.length} passphrase candidate(s) and ${rawKeys.length} raw key candidate(s)...`);
  const found = findKey(raw, passphrases, rawKeys);
  if (!found) {
    throw new Error('No key matched. Check UIN/IMEI, or use a saved --key / --raw-key for modern WeChat.');
  }

  const decrypted = decryptDatabase(raw, found);
  fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
  fs.writeFileSync(args.out, decrypted);

  log(`OK: decrypted ${path.basename(args.db)} -> ${args.out}`);
  log(`Config: ${found.cfg.name}, pageSize=${found.cfg.pageSize}, keyType=${found.kind}`);
  if (found.pass) log(`Matched passphrase: ${found.pass}`);
  if (raw.length % found.cfg.pageSize !== 0) {
    log(`Warning: input size has ${raw.length % found.cfg.pageSize} trailing byte(s) outside full pages; they were not copied.`);
  }
}

try {
  main();
} catch (err) {
  console.error(`Error: ${err && err.message ? err.message : err}`);
  process.exit(1);
}
