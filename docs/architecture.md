# Architecture

Data Workbench is an independent, generic analysis project. It must stay free of
company names, customer data, industry-specific code tables and proprietary
sample reports.

## Layers

1. **Core data model** (planned)
   - `Dataset`: headers, typed columns, missing masks, row count.
   - `RoleMapping`: id / group / date / metric roles, auto-detected but
     user-overridable.
2. **Desensitization** (available in v0.1)
   - `src/core/desensitize.js`: salted SHA-256 pseudonyms, group mapping,
     date shifting, free-text masking; numeric values untouched.
3. **Statistics** (planned)
   - descriptive stats, normality (Anderson–Darling), capability, SPC,
     hypothesis tests, correlation, Pareto.
4. **Renderers** (planned)
   - SVG charts, HTML report, DOCX export, XLSX export.
5. **UI** (planned)
   - Import → field roles → desensitize preview → analyze → report.

## Independence rules

- No `battery-workbench` imports, company constants or real datasets.
- Every public example is synthetic.
- The private/industry-specific adapter, if any, stays in a separate private
  repository or a local "domain pack" — never in this public repo.

## Desensitization guarantees

- Pseudonyms are deterministic only with the same salt.
- Mapping tables are returned in memory for audit; they are never serialized
  into exported datasets by the library itself.
- Numeric measurements are copied unchanged so statistical conclusions remain
  valid.
- Dates are shifted by a whole-day offset, preserving intervals and order.
