/**
 * Data Workbench — desensitization core (independent, generic).
 *
 * Given a header row + array-of-arrays dataset, replace identifying text
 * (IDs, batches/groups, dates, free text) with deterministic pseudonyms while
 * leaving numeric measurements untouched, so the desensitized file can still
 * be analyzed without exposing the source records.
 *
 * Design notes
 * ------------
 * - SHA-256(salt + "|" + value) -> stable pseudonym inside one export;
 *   a different salt produces a different, non-linkable pseudonym.
 * - The mapping table is returned for local audit only; callers must not put
 *   it into the exported file.
 * - Dates are shifted by a fixed number of days so intervals/order survive.
 * - Numeric values are never modified: capability/SPC conclusions stay valid.
 *
 * This module has no DOM, network or company-specific rules.
 */

const HEX = '0123456789abcdef';

/** Compact synchronous SHA-256 over UTF-8 text. */
export function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text));
  const bitLength = BigInt(bytes.length) * 8n;
  const paddedLength = ((bytes.length + 9 + 63) >> 6) << 6;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(bytes);
  buffer[bytes.length] = 0x80;
  for (let i = 0; i < 8; i += 1) {
    buffer[paddedLength - 1 - i] = Number((bitLength >> BigInt(8 * i)) & 0xffn);
  }

  const k = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      const p = offset + i * 4;
      w[i] = ((buffer[p] << 24) | (buffer[p + 1] << 16) | (buffer[p + 2] << 8) | buffer[p + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + k[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  let out = '';
  for (let i = 0; i < h.length; i += 1) {
    out += HEX[(h[i] >>> 28) & 15] + HEX[(h[i] >>> 24) & 15] + HEX[(h[i] >>> 20) & 15] +
      HEX[(h[i] >>> 16) & 15] + HEX[(h[i] >>> 12) & 15] + HEX[(h[i] >>> 8) & 15] +
      HEX[(h[i] >>> 4) & 15] + HEX[h[i] & 15];
  }
  return out;
}

const ID_HEADER = /(编码|编号|序列号|流水号|条码|二维码|serial|code|(^|\W)id(\W|$)|sn\b|uuid|guid)/i;
const DATE_HEADER = /(日期|时间|date|time|day)/i;
const TEXT_HEADER = /(备注|说明|注释|评论|原因|note|comment|remark|description|memo|text)/i;
const DATE_VALUE = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})((?:[ T].*)?)$/;
const EXCEL_SERIAL_MIN = 20000;
const EXCEL_SERIAL_MAX = 80000;

export function randomSalt() {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  if (c && typeof c.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    return Array.from(bytes, (b) => HEX[(b >>> 4) & 15] + HEX[b & 15]).join('');
  }
  return sha256Hex(String(Date.now()) + '|' + String(Math.random()));
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function textOf(value) {
  if (value === null || value === undefined) return '';
  return String(value);
}

function looksLikeDate(value) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return true;
  return DATE_VALUE.test(textOf(value).trim());
}

function looksLikeExcelSerial(value) {
  return isFiniteNumber(value) && Number.isInteger(value) &&
    value >= EXCEL_SERIAL_MIN && value <= EXCEL_SERIAL_MAX;
}

function excelSerialToDate(serial) {
  // Excel's 1900 date system (including its historical leap-year quirk).
  const ms = Math.round((serial - 25569) * 86400000);
  return new Date(ms);
}

function dateToExcelSerial(date) {
  return Math.round(date.getTime() / 86400000 + 25569);
}

function parseDate(value) {
  if (value instanceof Date) {
    return { y: value.getFullYear(), m: value.getMonth() + 1, d: value.getDate(), suffix: '', date: value };
  }
  if (looksLikeExcelSerial(value)) {
    const date = excelSerialToDate(value);
    return { y: date.getUTCFullYear(), m: date.getUTCMonth() + 1, d: date.getUTCDate(), suffix: '', serial: value };
  }
  const match = DATE_VALUE.exec(textOf(value).trim());
  if (!match) return null;
  return { y: Number(match[1]), m: Number(match[2]), d: Number(match[3]), suffix: match[4] || '' };
}

function formatDate(y, m, d) {
  return String(y).padStart(4, '0') + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
}

function shiftDate(value, days) {
  const parsed = parseDate(value);
  if (!parsed) return value;
  if (parsed.serial !== undefined) return parsed.serial + days;
  const date = parsed.date ? new Date(parsed.date.getTime()) : new Date(parsed.y, parsed.m - 1, parsed.d);
  date.setDate(date.getDate() + days);
  if (parsed.date) {
    const hasTime = date.getHours() !== 0 || date.getMinutes() !== 0 || date.getSeconds() !== 0;
    return hasTime ? date.toISOString() : formatDate(date.getFullYear(), date.getMonth() + 1, date.getDate());
  }
  return formatDate(date.getFullYear(), date.getMonth() + 1, date.getDate()) + parsed.suffix;
}

/** Split non-empty text values of one column. */
function columnTexts(rows, index) {
  const out = [];
  for (let r = 0; r < rows.length; r += 1) {
    const row = rows[r] || [];
    const value = row[index];
    const text = textOf(value).trim();
    if (text) out.push(text);
  }
  return out;
}

/** Guess which columns should be treated as ID / group / date / free text. */
export function detectColumns(headers, rows) {
  const nRows = Math.max(1, rows.length);
  const idColumns = [];
  const groupColumns = [];
  const dateColumns = [];
  const textColumns = [];

  for (let c = 0; c < headers.length; c += 1) {
    const texts = columnTexts(rows, c);
    if (!texts.length) continue;
    const header = textOf(headers[c]);
    const unique = new Set(texts);
    const uniqueRatio = unique.size / Math.max(1, texts.length);
    const sample = texts.slice(0, Math.min(200, texts.length));
    const dateish = sample.filter(looksLikeDate).length >= Math.max(2, sample.length * 0.7);
    const numericCount = rows.reduce((acc, row) => acc + (isFiniteNumber(row && row[c]) ? 1 : 0), 0);
    const numericValues = rows
      .map((row) => (row ? row[c] : null))
      .filter((v) => isFiniteNumber(v));

    if (numericCount >= nRows * 0.8) {
      // Numeric identifiers (long integer codes) and Excel serial dates are
      // easy to overlook: a pure number is still a direct identifier.
      if (DATE_HEADER.test(header) && numericValues.some(looksLikeExcelSerial)) {
        dateColumns.push(c);
      } else if (ID_HEADER.test(header) && unique.size >= Math.max(2, texts.length * 0.6)) {
        idColumns.push(c);
      }
      continue;
    }
    if (dateish || DATE_HEADER.test(header)) {
      dateColumns.push(c);
      continue;
    }
    if (TEXT_HEADER.test(header)) {
      textColumns.push(c);
      continue;
    }
    if (ID_HEADER.test(header) || uniqueRatio >= 0.85) {
      idColumns.push(c);
      continue;
    }
    if (unique.size >= 2 && unique.size <= Math.min(200, Math.max(2, Math.floor(nRows * 0.3)))) {
      groupColumns.push(c);
      continue;
    }
    textColumns.push(c);
  }
  return { idColumns, groupColumns, dateColumns, textColumns };
}

/**
 * Desensitize a dataset.
 *
 * @param {string[]} headers
 * @param {Array<Array<unknown>>} rows
 * @param {object} [options]
 * @param {string} [options.salt] random when omitted
 * @param {number[]} [options.idColumns] explicit, otherwise auto-detected
 * @param {number[]} [options.groupColumns]
 * @param {number[]} [options.dateColumns]
 * @param {number[]} [options.textColumns]
 * @param {'hash'|'sequence'|'keep'} [options.idMode='hash']
 * @param {'hash'|'sequence'|'keep'} [options.groupMode='hash']
 * @param {'mask'|'keep'|'drop'} [options.textMode='mask']
 * @param {number|null} [options.dateShiftDays=null] null = deterministic random shift
 * @param {boolean} [options.autoDetect=true]
 * @returns {{headers:string[],rows:Array<Array<unknown>>,policies:object,mapping:object,summary:object,salt:string}}
 */
export function desensitize(headers, rows, options = {}) {
  if (!Array.isArray(headers)) throw new TypeError('headers must be an array');
  if (!Array.isArray(rows)) throw new TypeError('rows must be an array');
  const salt = options.salt || randomSalt();
  const auto = options.autoDetect === false ? null : detectColumns(headers, rows);
  const take = (explicit, detected) => (Array.isArray(explicit) ? explicit.filter((i) => i >= 0 && i < headers.length) : (detected || []));
  const idColumns = take(options.idColumns, auto && auto.idColumns);
  const groupColumns = take(options.groupColumns, auto && auto.groupColumns);
  const dateColumns = take(options.dateColumns, auto && auto.dateColumns);
  const textColumns = take(options.textColumns, auto && auto.textColumns);
  const idMode = options.idMode || 'hash';
  const groupMode = options.groupMode || 'hash';
  const textMode = options.textMode || 'mask';
  const dateShiftDays = options.dateShiftDays === null || options.dateShiftDays === undefined
    ? 7 * (5 + (parseInt(sha256Hex(salt + '|date-shift').slice(0, 6), 16) % 40))
    : Math.trunc(options.dateShiftDays);

  const idMap = new Map();
  const groupMap = new Map();
  const textMap = new Map();
  const idSeq = new Map();
  const groupSeq = new Map();

  const token = (prefix, value, map, length = 14) => {
    if (map.has(value)) return map.get(value);
    const next = prefix + sha256Hex(salt + '|' + value).slice(0, length);
    map.set(value, next);
    return next;
  };
  const sequential = (prefix, value, map) => {
    if (map.has(value)) return map.get(value);
    const next = prefix + String(map.size + 1).padStart(3, '0');
    map.set(value, next);
    return next;
  };

  const output = rows.map((row) => (Array.isArray(row) ? row.slice() : []));
  const summary = { idColumns, groupColumns, dateColumns, textColumns, dateShiftDays, changed: 0, cellsChanged: 0, sensitiveCells: 0 };
  const markChange = (before, after) => {
    summary.sensitiveCells += 1;
    if (String(before) !== String(after)) summary.cellsChanged += 1;
  };

  for (let r = 0; r < output.length; r += 1) {
    const row = output[r] || [];
    for (const c of idColumns) {
      const raw = textOf(row[c]).trim();
      if (!raw) continue;
      const before = row[c];
      row[c] = idMode === 'keep' ? row[c] : idMode === 'sequence' ? sequential('P-', raw, idSeq) : token('P-', raw, idMap);
      markChange(before, row[c]);
    }
    for (const c of groupColumns) {
      const raw = textOf(row[c]).trim();
      if (!raw) continue;
      const before = row[c];
      row[c] = groupMode === 'keep' ? row[c] : groupMode === 'sequence' ? sequential('G-', raw, groupSeq) : token('G-', raw, groupMap);
      markChange(before, row[c]);
    }
    for (const c of dateColumns) {
      if (row[c] === null || row[c] === undefined || row[c] === '') continue;
      const before = row[c];
      row[c] = shiftDate(row[c], dateShiftDays);
      markChange(before, row[c]);
    }
    for (const c of textColumns) {
      if (textMode === 'keep') continue;
      const raw = textOf(row[c]).trim();
      if (!raw) continue;
      const before = row[c];
      row[c] = textMode === 'drop' ? '' : token('T-', raw, textMap);
      markChange(before, row[c]);
    }
  }

  for (let c = 0; c < headers.length; c += 1) {
    if (idColumns.includes(c) || groupColumns.includes(c) || dateColumns.includes(c) || textColumns.includes(c)) {
      summary.changed += 1;
    }
  }
  const invert = (map) => new Map(Array.from(map.entries(), ([original, pseudonym]) => [pseudonym, original]));
  return {
    headers: headers.slice(),
    rows: output,
    policies: {
      idColumns, groupColumns, dateColumns, textColumns,
      idMode, groupMode, textMode, dateShiftDays,
    },
    mapping: { id: invert(idMap), group: invert(groupMap), text: invert(textMap) },
    summary,
    salt,
  };
}
