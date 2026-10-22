# [F007][S005] CSV import release verification

- Scope: [F001][S003] skip only recognized leading Numbers table titles/blank rows; retain existing parser/header validation, quoted commas, name/phone collision checks.
- Re-import preserves existing lesson balance and profile attributes when their columns are absent. Explicit supplied balances retain the prior contract.
- Regression suite: 80 passed. Includes original Numbers shape, BOM/CRLF, localized table titles, normal headers, quoted names, persistence, repeat import, collision rejection, optional-column preservation and payment-sheet rejection.
- Supplied private CSV: isolated SQLite only, 14 inserts first run; 14 updates and no inserts second run; zero skipped rows. No production members added by this verification.
- No member names, identity details, phone lists, private CSV fixtures or credentials are included in this commit.
- Deploy target: existing Render backend service srv-d7mvectckfvc73em37a0, main branch, confirmed Larry LO workspace. No frontend changes or new hosting resources.
- Existing unpublished backend commit 70c22ee is also in the push ancestry; it keeps initial checkout payments pending until Admin confirmation, matching the already deployed frontend label. No migration or external messaging is part of the fix or verification.

- Security gate: pip-audit of production requirements passed with no known vulnerabilities; see adjacent JSON. Python application byte compilation passed.
