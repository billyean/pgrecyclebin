# pgrecyclebin

A PostgreSQL extension that implements an Oracle-like recycle bin for tables.
Instead of dropping tables, it moves them into a protected schema `"_$recyclebin$"`
and records their original schema/name in a small catalog table for later
**flashback**.

> Tested against PostgreSQL 16/17 (new `ProcessUtility` signature with `QueryCompletion *qc`).

## Features

- Intercepts `DROP TABLE ...`:
  - If the table is **not** in `"_$recyclebin$"`: move it to the recycle bin and record metadata.
  - If the table **is** already in `"_$recyclebin$"`: warn that it cannot be restored and perform a real drop.
  - Supports multi-table drops in a single statement by splitting into two lists (move vs drop).
- Handles `RESTRICT` by moving only the specified tables.
- Handles `CASCADE` by recursively moving dependent tables/views/sequences into the recycle bin (best-effort via `pg_depend`).
- Auto-creates the `"_$recyclebin$"` schema and the catalog table when first needed.
- Disallows `CREATE SCHEMA "_$recyclebin$"` by users.
- Disallows `DROP TABLE "_$recyclebin$"._rb_catalog`.
- Provides `flashback(text)` (exposed as `pgrecyclebin_flashback(text)`) restoring the most recently dropped table by *table name only*.
  - Moves the table back to its original schema.
  - Renames it back to the original name if needed.
  - Removes the row from the catalog.

## Install / Build

```bash
make
make install
-- inside psql as superuser
CREATE EXTENSION pgrecyclebin;
```

## Basic Usage

```sql
-- Drop a table: it gets moved to "_$recyclebin$"
DROP TABLE public.t1;

-- Restore the most recently dropped table named t1 (by original table name only):
SELECT pgrecyclebin_flashback('t1');
```

To permanently delete, drop from the recycle bin schema explicitly:

```sql
-- This warns then performs a real drop:
DROP TABLE "_$recyclebin$".t1_$12345;
```

## Internal Design

1. We hook `ProcessUtility` and detect `DropStmt` with `OBJECT_TABLE`.
2. We split the objects into:
   - **to_move**: tables whose `schemaname IS DISTINCT FROM "_$recyclebin$"`
   - **to_drop**: tables already inside the recycle bin
3. For `to_move`:
   - Ensure `"_$recyclebin$"` schema exists (create it + catalog if missing).
   - Generate a unique recycle-bin name `origName_$oid` (truncated to `NAMEDATALEN-1` if needed).
   - Record a row into `"_$recyclebin$"._rb_catalog (rbname, orig_schema, orig_name, drop_time, orig_oid)`.
   - Issue `ALTER TABLE <orig> SET SCHEMA "_$recyclebin$"` and then `ALTER TABLE ... RENAME TO <rbname>`.
   - For `CASCADE`, recursively discover dependent relations and move them too.
4. For `to_drop`:
   - Emit `WARNING` that objects dropped from the recycle bin cannot be restored.
   - Call the standard utility to perform a normal drop and remove their catalog rows.
5. `flashback(text)`:
   - Looks up the most recent row for `orig_name = $1` (ties broken by `drop_time DESC`).
   - Verifies the destination schema is present and target name does not currently exist.
   - Renames the RB object back to the original name if needed, then `SET SCHEMA orig_schema`.
   - Deletes the catalog row.

## Limitations / Notes

- Dependency processing on `CASCADE` is best effort for tables/views/sequences/materialized views.
  Other object kinds (e.g., functions) are not moved.
- RB names are `name` identifiers; very long base names will be truncated.
- OIDs can be reused; we store the original OID for information only.
- The extension focuses on relations (tables, views, sequences, matviews). Indexes and constraints
  follow their owning table and are not independently recycled.
- `DROP SCHEMA ... CASCADE` is not intercepted; drop underlying tables first or enhance the code similarly.

## Troubleshooting

- If catalog or schema gets corrupted, you can recreate them by dropping and re-installing the extension.
- Grant usage/select on `"_$recyclebin$"` if non-superusers need visibility.

## License

PostgreSQL license.
