import assert from 'node:assert/strict';
import { desensitize, detectColumns, sha256Hex, randomSalt } from '../src/core/desensitize.js';

let checks = 0;
const ok = (condition, message) => { checks += 1; assert.ok(condition, message); };

// SHA-256 known vectors
ok(sha256Hex('abc') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256 abc');
ok(sha256Hex('') === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256 empty');

const headers = ['编号', '批次', '生产日期', '容量(Ah)', '内阻(mΩ)', '备注'];
const rows = [
  ['CELL-0001', 'B2026-01', '2026-01-01', 100.2, 17.1, '首件'],
  ['CELL-0002', 'B2026-01', '2026-01-02', 100.4, 17.0, '首件'],
  ['CELL-0003', 'B2026-02', '2026-01-05', 99.8, 17.5, '复测'],
  ['CELL-0004', 'B2026-02', '2026-01-06', 100.1, 17.2, '复测'],
];

const detected = detectColumns(headers, rows);
ok(detected.idColumns.length === 1 && detected.idColumns[0] === 0, 'detect id column');
ok(detected.groupColumns.includes(1), 'detect group column');
ok(detected.dateColumns.includes(2), 'detect date column');
ok(detected.textColumns.includes(5), 'detect free-text column');

const before = JSON.stringify(rows);
const out = desensitize(headers, rows, { salt: 'test-salt', autoDetect: true });
ok(JSON.stringify(rows) === before, 'input rows are not mutated');
ok(out.rows[0][0].startsWith('P-'), 'id becomes pseudonym');
ok(out.rows[0][0] === out.rows[1][0] ? false : true, 'different ids differ');
ok(out.rows[0][1] === out.rows[1][1] && out.rows[0][1] !== out.rows[2][1], 'same batch maps consistently');
ok(out.rows[0][0] !== 'CELL-0001' && !JSON.stringify(out.rows).includes('CELL-0001'), 'no raw id remains');
ok(out.rows[0][3] === 100.2 && out.rows[0][4] === 17.1, 'numeric measurements unchanged');
ok(out.rows[0][2] !== '2026-01-01', 'date is shifted');

const shift = out.policies.dateShiftDays;
const d0 = new Date(out.rows[0][2] + 'T00:00:00Z').getTime();
const d1 = new Date(out.rows[1][2] + 'T00:00:00Z').getTime();
const d2 = new Date(out.rows[2][2] + 'T00:00:00Z').getTime();
ok(d1 - d0 === 86400000, 'one-day interval preserved');
ok(d2 - d0 === 4 * 86400000, 'four-day interval preserved');
ok(Number.isInteger(shift), 'date shift is an integer');

const reverse = new Map(Array.from(out.mapping.id.entries(), ([token, original]) => [token, original]));
ok(reverse.get(out.rows[0][0]) === 'CELL-0001', 'mapping is reversible locally');
ok(out.mapping.group.get(out.rows[0][1]) === 'B2026-01', 'group mapping keeps original for audit');

const out2 = desensitize(headers, rows, { salt: 'test-salt', autoDetect: true });
ok(JSON.stringify(out2.rows) === JSON.stringify(out.rows), 'same salt is deterministic');
const out3 = desensitize(headers, rows, { salt: 'other-salt', autoDetect: true });
ok(JSON.stringify(out3.rows) !== JSON.stringify(out.rows), 'different salt gives different pseudonyms');
ok(out3.rows[0][0] !== out.rows[0][0], 'pseudonyms are salt-specific');

const seq = desensitize(headers, rows, { salt: 's', idMode: 'sequence', groupMode: 'sequence' });
ok(seq.rows[0][0] === 'P-001' && seq.rows[1][0] === 'P-002', 'sequence id mode');
ok(seq.rows[0][1] === 'G-001' && seq.rows[2][1] === 'G-002', 'sequence group mode');

const dropped = desensitize(headers, rows, { salt: 's', textMode: 'drop' });
ok(dropped.rows[0][5] === '', 'textMode=drop empties free text');

const kept = desensitize(headers, rows, { salt: 's', idMode: 'keep', groupMode: 'keep', textMode: 'keep' });
ok(kept.rows[0][0] === 'CELL-0001' && kept.rows[0][1] === 'B2026-01' && kept.rows[0][5] === '首件', 'keep modes leave text intact');

// explicit date shift
const fixed = desensitize(headers, rows, { salt: 's', dateShiftDays: 10 });
ok(fixed.rows[0][2] === '2026-01-11', 'explicit date shift');

// empty / single-value datasets must not throw
ok(desensitize([], []).rows.length === 0, 'empty dataset');
ok(desensitize(['编号'], [['A']]).rows[0][0].startsWith('P-'), 'single row');

// numeric identifiers and Excel serial dates must not leak
const numericHeaders = ['编号', '生产日期', '值'];
const numericRows = [
  [123456789012, 46023, 1.2],
  [123456789013, 46024, 1.3],
];
const numericDetected = detectColumns(numericHeaders, numericRows);
ok(numericDetected.idColumns.includes(0), 'detect long numeric id');
ok(numericDetected.dateColumns.includes(1), 'detect Excel serial date');
const numericOut = desensitize(numericHeaders, numericRows, { salt: 'n', dateShiftDays: 7 });
ok(String(numericOut.rows[0][0]).startsWith('P-'), 'numeric id is pseudonymized');
ok(numericOut.rows[0][1] === 46030, 'Excel serial date shifted');
ok(numericOut.rows[0][2] === 1.2, 'numeric value untouched');

// time-of-day must survive the date shift
const timeHeaders = ['编号', '生产时间'];
const timeRows = [['A-1', '2026-01-01 08:30'], ['A-2', '2026-01-01 20:15']];
const timeOut = desensitize(timeHeaders, timeRows, { salt: 't', dateShiftDays: 10 });
ok(timeOut.rows[0][1] === '2026-01-11 08:30', 'time-of-day preserved');
ok(timeOut.rows[1][1] === '2026-01-11 20:15', 'second time-of-day preserved');

// default shift is a whole number of weeks so weekday/班次 relations survive
const weekShift = desensitize(headers, rows, { salt: 'w' });
ok(weekShift.policies.dateShiftDays % 7 === 0, 'default shift keeps weekday');
ok(weekShift.summary.cellsChanged > 0 && weekShift.summary.sensitiveCells >= weekShift.summary.cellsChanged,
  'summary counts actual changed cells');

// random salt is non-empty and different across calls
const s1 = randomSalt();
const s2 = randomSalt();
ok(typeof s1 === 'string' && s1.length >= 16 && s1 !== s2, 'random salt');

console.log(`desensitize: ${checks} checks passed`);
