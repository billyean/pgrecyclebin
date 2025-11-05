-- pgrecyclebin--1.0.sql
-- Installs the extension objects (C functions), no SQL objects required beyond runtime DDL.
CREATE FUNCTION pgrecyclebin_flashback(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pgrecyclebin_flashback'
LANGUAGE C STRICT;
