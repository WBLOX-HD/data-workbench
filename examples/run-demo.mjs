import { desensitize } from '../src/core/desensitize.js';

const headers = ['样本编号', '批次', '生产日期', '指标A', '指标B', '备注'];
const rows = [
  ['S-001', 'B-2026-01', '2026-01-01', 12.4, 0.82, '首件'],
  ['S-002', 'B-2026-01', '2026-01-02', 12.1, 0.84, '首件'],
  ['S-003', 'B-2026-02', '2026-01-05', 11.8, 0.79, '复测'],
  ['S-004', 'B-2026-02', '2026-01-06', 12.0, 0.81, '复测'],
];

const result = desensitize(headers, rows, { salt: 'demo-salt' });

console.log('策略:', result.policies);
console.log('日期偏移:', result.policies.dateShiftDays, '天');
console.log('脱敏后数据:');
console.log([result.headers, ...result.rows].map((row) => row.join(' | ')).join('\n'));
console.log('\n说明：映射表只用于本地核对，不要随导出文件分发。');
