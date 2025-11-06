/*
 * pgrecyclebin.c
 *
 * A PostgreSQL extension that intercepts DROP TABLE and moves tables
 * into a protected schema "_$recyclebin$". It stores metadata for
 * flashback restoration by table name.
 *
 * Compatible with PostgreSQL 16–18.
 */

#include "postgres.h"
#include "access/htup_details.h"
#include "access/heapam.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/tableam.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "catalog/objectaddress.h"   /* for LockSharedObject/UnlockSharedObject */
#include "commands/alter.h"
#include "commands/schemacmds.h"
#include "commands/tablecmds.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "parser/parse_utilcmd.h"
#include "storage/lmgr.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/timestamp.h"
#include "catalog/catalog.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

#define RB_SCHEMA "_$recyclebin$"
#define RB_CATALOG "_rb_catalog"

static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static bool rb_initialized = false;
static bool rb_in_progress = false;
/* Forward declarations */
static void ensure_recyclebin_schema_and_catalog(void);
static bool is_recyclebin_schema(const char *schemaname);
static void handle_drop_table(DropStmt *stmt,
                              const char *queryString,
                              bool readOnlyTree,
                              ProcessUtilityContext context,
                              ParamListInfo params,
                              QueryEnvironment *queryEnv,
                              DestReceiver *dest,
                              QueryCompletion *qc);
static void move_relation_to_recyclebin(Oid relid, const char *orig_schema,
                                        const char *orig_name, DropBehavior behavior);
static void move_dependents_cascade(Oid relid, DropBehavior behavior);
static void warn_and_normal_drop(DropStmt *stmt,
                                 const char *queryString,
                                 bool readOnlyTree,
                                 ProcessUtilityContext context,
                                 ParamListInfo params,
                                 QueryEnvironment *queryEnv,
                                 DestReceiver *dest,
                                 QueryCompletion *qc);
static char *compose_rbname(const char *orig_name, Oid relid);
static void catalog_insert_rbrow(const char *rbname, const char *orig_schema,
                                 const char *orig_name, Oid orig_oid);
static void catalog_delete_by_rbname(const char *rbname);
static bool name_exists_in_schema(const char *schema, const char *name, Oid *out_oid);
static RangeVar *rv_from_objname(List *objname);
static void pgrecyclebin_ProcessUtility(PlannedStmt *pstmt,
                                        const char *queryString,
                                        bool readOnlyTree,
                                        ProcessUtilityContext context,
                                        ParamListInfo params,
                                        QueryEnvironment *queryEnv,
                                        DestReceiver *dest,
                                        QueryCompletion *qc);

/* SQL function */
PG_FUNCTION_INFO_V1(pgrecyclebin_flashback);
Datum pgrecyclebin_flashback(PG_FUNCTION_ARGS);

/* ---------------- Utilities ---------------- */

static bool
is_recyclebin_schema(const char *schemaname)
{
    if (!schemaname)
        return false;
    return strcmp(schemaname, RB_SCHEMA) == 0;
}

/* Build RangeVar from object name list (PG17+: replacement for makeRangeVarFromNameList) */
static RangeVar *
rv_from_objname(List *objname)
{
    char *schemaname = NULL;
    char *relname = NULL;

    if (list_length(objname) == 2)
    {
        schemaname = strVal(linitial(objname));
        relname    = strVal(lsecond(objname));
    }
    else if (list_length(objname) == 1)
    {
        relname = strVal(linitial(objname));
    }
    else
    {
        elog(ERROR, "unexpected qualified name structure");
    }

    return makeRangeVar(schemaname ? pstrdup(schemaname) : NULL,
                        pstrdup(relname),
                        -1);
}

/* Ensure RB schema and catalog exist */
static void
ensure_recyclebin_schema_and_catalog(void)
{
    int spi_rc;
    int old_client_min_messages;


    PG_TRY(); {
        rb_in_progress = true;
        /* Save current GUC and suppress NOTICE output */
        old_client_min_messages = client_min_messages;
        client_min_messages = WARNING;

        spi_rc = SPI_connect();
        if (spi_rc != SPI_OK_CONNECT)
            elog(ERROR, "SPI_connect failed: %d", spi_rc);

        spi_rc = SPI_execute("CREATE SCHEMA IF NOT EXISTS \"_$recyclebin$\";",
                         false, 0);
#if PG_VERSION_NUM >= 150000
        if (spi_rc != SPI_OK_UTILITY)
#else
        if (spi_rc != SPI_OK_UTILITY)  /* 14/15: still OK_UTILITY for CREATE SCHEMA */
#endif
            elog(ERROR, "CREATE SCHEMA failed rc=%d", spi_rc);

        spi_rc = SPI_execute(
            "CREATE TABLE IF NOT EXISTS \"_$recyclebin$\".\"_rb_catalog\" ("
            "  rbname name PRIMARY KEY,"
            "  orig_schema name NOT NULL,"
            "  orig_name name NOT NULL,"
            "  drop_time timestamptz NOT NULL DEFAULT now(),"
            "  orig_oid oid NOT NULL"
            ");",
            false, 0);
#if PG_VERSION_NUM >= 150000
        if (spi_rc != SPI_OK_UTILITY)
#else
        if (spi_rc != SPI_OK_UTILITY)
#endif
            elog(ERROR, "CREATE TABLE failed rc=%d", spi_rc);

        SPI_finish();
    } PG_CATCH(); {
        rb_in_progress = false;
        PG_RE_THROW();
    } PG_END_TRY();
    rb_in_progress = false;
    client_min_messages = old_client_min_messages;
}

/* Compose RB name like <orig>_$oid (safe within NAMEDATALEN) */
static char *
compose_rbname(const char *orig_name, Oid relid)
{
    char *rbname;
    char oidbuf[64];
    size_t base_len, suffix_len, maxlen, keep;

    snprintf(oidbuf, sizeof(oidbuf), "_$%u", relid);
    base_len = strlen(orig_name);
    suffix_len = strlen(oidbuf);
    maxlen = NAMEDATALEN - 1;

    rbname = palloc0(maxlen + 1);
    if (base_len + suffix_len <= maxlen)
    {
        strcpy(rbname, orig_name);
        strcat(rbname, oidbuf);
    }
    else
    {
        keep = (maxlen > suffix_len) ? (maxlen - suffix_len) : 0;
        strncpy(rbname, orig_name, keep);
        rbname[keep] = '\0';
        strcat(rbname, oidbuf);
    }
    return rbname;
}

/* Insert catalog row */
static void
catalog_insert_rbrow(const char *rbname, const char *orig_schema,
                     const char *orig_name, Oid orig_oid)
{
    Relation    rel;
    HeapTuple   tup;
    Datum       values[5];
    bool        nulls[5] = {false};
    Oid         rb_nspoid;
    Oid         relid;
    TupleDesc   desc;

    rb_nspoid = get_namespace_oid(RB_SCHEMA, false);
    relid = get_relname_relid(RB_CATALOG, rb_nspoid);
    if (!OidIsValid(relid))
        elog(ERROR, "recyclebin catalog table not found");

    rel = table_open(relid, RowExclusiveLock);
    desc = RelationGetDescr(rel);

    values[0] = CStringGetDatum(rbname);
    values[1] = CStringGetDatum(orig_schema);
    values[2] = CStringGetDatum(orig_name);
    values[3] = TimestampTzGetDatum(GetCurrentTimestamp());
    values[4] = ObjectIdGetDatum(orig_oid);

    tup = heap_form_tuple(desc, values, nulls);
    heap_insert(rel, tup, GetCurrentCommandId(true), 0, NULL);
    /* Mark the relation as having been modified so it’s visible */
    CommandCounterIncrement();

    heap_freetuple(tup);
    table_close(rel, RowExclusiveLock);
}

/* Delete catalog row by rbname */
static void
catalog_delete_by_rbname(const char *rbname)
{
    Relation    rel;
    TableScanDesc scan;
    HeapTuple   tup;
    Oid         rb_nspoid;
    Oid         relid;
    ScanKeyData skey;

    rb_nspoid = get_namespace_oid(RB_SCHEMA, false);
    relid = get_relname_relid(RB_CATALOG, rb_nspoid);
    if (!OidIsValid(relid))
        elog(ERROR, "recyclebin catalog table not found");

    rel = table_open(relid, RowExclusiveLock);

    /* Prepare scan key for rbname = value */
    ScanKeyInit(&skey,
                1,                  /* attribute number (rbname is first col) */
                BTEqualStrategyNumber,
                F_NAMEEQ,
                CStringGetDatum(rbname));

    scan = table_beginscan_catalog(rel, 1, &skey);
    while ((tup = heap_getnext(scan, ForwardScanDirection)) != NULL)
    {
        CatalogTupleDelete(rel, &tup->t_self);
    }

    table_endscan(scan);
    table_close(rel, RowExclusiveLock);

    /* Make sure deletion is visible immediately */
    CommandCounterIncrement();
}

/* Check if name exists in schema */
static bool
name_exists_in_schema(const char *schema, const char *name, Oid *out_oid)
{
    Oid nsp, relid;
    nsp = get_namespace_oid(schema, true);
    if (!OidIsValid(nsp))
        return false;
    relid = get_relname_relid(name, nsp);
    if (out_oid)
        *out_oid = relid;
    return OidIsValid(relid);
}
/*
 * has_dependents - check whether a relation has any dependent relations
 * (views, materialized views, or foreign-key children).
 */
static bool
has_dependents(Oid relid)
{
    int spi_rc;
    StringInfoData sql;
    bool hasdeps = false;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    initStringInfo(&sql);

    /* Check pg_depend first (views, matviews, sequences, etc.) */
    appendStringInfo(&sql,
                     "SELECT 1 FROM pg_depend d "
                     "JOIN pg_class c ON c.oid=d.objid "
                     "WHERE d.refobjid=%u AND d.deptype IN ('n','i') "
                     "AND c.relkind IN ('r','v','m','S') "
                     "LIMIT 1",
                     relid);

    spi_rc = SPI_execute(sql.data, true, 1);
    if (spi_rc != SPI_OK_SELECT)
        elog(ERROR, "SPI SELECT failed in has_dependents");

    if (SPI_processed > 0)
        hasdeps = true;

    /* Check pg_constraint for foreign-key references */
    if (!hasdeps)
    {
        resetStringInfo(&sql);
        appendStringInfo(&sql,
                         "SELECT 1 FROM pg_constraint "
                         "WHERE confrelid = %u "
                         "AND contype = 'f' "
                         "LIMIT 1",
                         relid);

        spi_rc = SPI_execute(sql.data, true, 1);
        if (spi_rc != SPI_OK_SELECT)
            elog(ERROR, "SPI SELECT failed in has_dependents (FK)");
        if (SPI_processed > 0)
            hasdeps = true;
    }

    SPI_finish();
    pfree(sql.data);
    return hasdeps;
}
/* Move relation to recycle bin */
static void
move_relation_to_recyclebin(Oid relid, const char *orig_schema,
                            const char *orig_name, DropBehavior behavior)
{
    Relation rel;
    char *rbname;
    AlterObjectSchemaStmt *as;
    RenameStmt *rs;
    Node *node;
    PlannedStmt *wrapper;

    Oid rb_nspoid;

    ensure_recyclebin_schema_and_catalog();

    /* Before moving, ensure this relation has no dependents unless CASCADE */
    if (behavior != DROP_CASCADE && has_dependents(relid))
    {
        ereport(ERROR,
                (errcode(ERRCODE_DEPENDENT_OBJECTS_STILL_EXIST),
                 errmsg("cannot move table \"%s.%s\" to recycle bin because other objects depend on it",
                        orig_schema, orig_name),
                 errhint("Use DROP TABLE ... CASCADE to also recycle dependent objects.")));
    }

    /* Lock destination schema to avoid concurrent drop */
    rb_nspoid = get_namespace_oid(RB_SCHEMA, false);

    LockSharedObject(NamespaceRelationId, rb_nspoid, 0, AccessShareLock);

    /* Lock the relation we are moving */
    rel = relation_open(relid, AccessExclusiveLock);

    /* Compose recycle-bin name and record catalog row */
    rbname = compose_rbname(orig_name, relid);
    catalog_insert_rbrow(rbname, orig_schema, orig_name, relid);

    /* ALTER ... SET SCHEMA to RB */
    as = makeNode(AlterObjectSchemaStmt);
    as->objectType = OBJECT_TABLE;
    as->relation = makeRangeVar(pstrdup(orig_schema), pstrdup(orig_name), -1);
    as->newschema = pstrdup(RB_SCHEMA);
    as->missing_ok = false;

    node = (Node *) as;
    wrapper = makeNode(PlannedStmt);
    wrapper->commandType = CMD_UTILITY;
    wrapper->utilityStmt = node;
    wrapper->canSetTag = false;

    standard_ProcessUtility(wrapper, NULL, false, PROCESS_UTILITY_TOPLEVEL,
                            NULL, NULL, NULL, NULL);

    /*-------------------------------------------*/
    /* RENAME to rbname */
    rs = makeNode(RenameStmt);
    rs->renameType = OBJECT_TABLE;
    rs->relation = makeRangeVar(pstrdup(RB_SCHEMA), pstrdup(orig_name), -1);
    rs->newname = rbname;
    rs->behavior = behavior;
    rs->missing_ok = false;
    node = (Node *) rs;
    wrapper = makeNode(PlannedStmt);
    wrapper->commandType = CMD_UTILITY;
    wrapper->utilityStmt = node;
    wrapper->canSetTag = false;

    standard_ProcessUtility(wrapper, NULL, false, PROCESS_UTILITY_TOPLEVEL,
                            NULL, NULL, NULL, NULL);
    /* User-visible message */
    ereport(NOTICE,
            (errmsg("table \"%s\" is moved to recycle bin as \"%s.%s\"",
                    orig_name, RB_SCHEMA, rbname)));
    relation_close(rel, NoLock);

    if (behavior == DROP_CASCADE)
    {
        move_dependents_cascade(relid, behavior);
    }

    /* (2) Free rbname and release schema lock */
    UnlockSharedObject(NamespaceRelationId, rb_nspoid, 0, AccessShareLock);
    pfree(rbname);
}

/* CASCADE: move dependent relations, best effort */
static void
move_dependents_cascade(Oid relid, DropBehavior behavior)
{
    int spi_rc;
    StringInfoData sql;
    uint64 i;
    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    /*
     * First pass: normal dependencies from pg_depend (views, matviews, etc.)
     */
    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "SELECT c.oid, n.nspname, c.relname "
                     "FROM pg_depend d "
                     "JOIN pg_class c ON c.oid=d.objid "
                     "JOIN pg_namespace n ON n.oid=c.relnamespace "
                     "WHERE d.refobjid=%u AND d.deptype='n' "
                     "AND c.relkind IN ('r','v','m','S')",
                     relid);

    spi_rc = SPI_execute(sql.data, true, 0);
    if (spi_rc != SPI_OK_SELECT)
        elog(ERROR, "SPI SELECT failed");
    for (i = 0; i < SPI_processed; i++)
    {
        bool isnull;
        Oid dep_relid;
        char *nspname;
        char *relname;

        dep_relid = DatumGetObjectId(
            SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull));
        nspname = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
        relname = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3);
        if (!is_recyclebin_schema(nspname))
            move_relation_to_recyclebin(dep_relid, nspname, relname, behavior);
    }

    /*
     * Second pass: foreign-key dependencies via pg_constraint
     */
    resetStringInfo(&sql);
    appendStringInfo(&sql,
                     "SELECT c.oid, n.nspname, c.relname "
                     "FROM pg_constraint con "
                     "JOIN pg_class c ON c.oid = con.conrelid "
                     "JOIN pg_namespace n ON n.oid = c.relnamespace "
                     "WHERE con.confrelid = %u "
                     "  AND c.relkind = 'r'",
                     relid);

    spi_rc = SPI_execute(sql.data, true, 0);
    if (spi_rc != SPI_OK_SELECT)
        elog(ERROR, "[pgrecyclebin] SPI SELECT failed (rc=%d)", spi_rc);

    for (i = 0; i < SPI_processed; i++)
    {
        bool isnull;
        Oid dep_relid;
        char *nspname;
        char *relname;

        dep_relid = DatumGetObjectId(
            SPI_getbinval(SPI_tuptable->vals[i],
                          SPI_tuptable->tupdesc, 1, &isnull));
        nspname = SPI_getvalue(SPI_tuptable->vals[i],
                               SPI_tuptable->tupdesc, 2);
        relname = SPI_getvalue(SPI_tuptable->vals[i],
                               SPI_tuptable->tupdesc, 3);
        if (!is_recyclebin_schema(nspname))
            move_relation_to_recyclebin(dep_relid, nspname, relname, behavior);
    }


    SPI_finish();
    pfree(sql.data);
}

/* Warn + perform normal DROP for tables already inside recycle bin */
static void
warn_and_normal_drop(DropStmt *stmt,
                     const char *queryString,
                     bool readOnlyTree,
                     ProcessUtilityContext context,
                     ParamListInfo params,
                     QueryEnvironment *queryEnv,
                     DestReceiver *dest,
                     QueryCompletion *qc)
{
    ListCell *lc;
    PlannedStmt *wrapper;
    foreach(lc, stmt->objects)
    {
        RangeVar *rv = rv_from_objname((List *) lfirst(lc));
        if (rv->schemaname && is_recyclebin_schema(rv->schemaname))
        {
            ereport(WARNING,
                    (errmsg("dropping \"%s.%s\" permanently", rv->schemaname, rv->relname)));
            catalog_delete_by_rbname(rv->relname);
        }
    }
    wrapper = makeNode(PlannedStmt);
    wrapper->commandType = CMD_UTILITY;
    wrapper->canSetTag = false;
    wrapper->utilityStmt = (Node *) stmt;
    if (prev_ProcessUtility)
        prev_ProcessUtility(wrapper, queryString, readOnlyTree,
                            context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(wrapper, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);
}

/* Handle DROP TABLE interception */
static void
handle_drop_table(DropStmt *stmt,
                  const char *queryString,
                  bool readOnlyTree,
                  ProcessUtilityContext context,
                  ParamListInfo params,
                  QueryEnvironment *queryEnv,
                  DestReceiver *dest,
                  QueryCompletion *qc)
{
    List *to_move = NIL;
    List *to_drop = NIL;
    ListCell *lc;

    if (stmt == NULL || stmt->objects == NIL)
    {
        elog(WARNING, "[pgrecyclebin] handle_drop_table: empty DropStmt or objects list");
        return;
    }

    foreach(lc, stmt->objects)
    {
        RangeVar *rv = rv_from_objname((List *) lfirst(lc));

        if (rv == NULL)
        {
            elog(WARNING, "[pgrecyclebin] handle_drop_table: NULL RangeVar entry");
            continue;
        }

        if (is_recyclebin_schema(rv->schemaname))
            to_drop = lappend(to_drop, rv);
        else
            to_move = lappend(to_move, rv);
    }

    if (list_length(to_drop) > 0)
    {
        DropStmt *drop2 = (DropStmt *) copyObject(stmt);
        drop2->objects = NIL;

        foreach(lc, to_drop)
        {
            RangeVar *rv = (RangeVar *) lfirst(lc);
            List *namelist;
            if (rv->schemaname)
                namelist = list_make2(makeString(pstrdup(rv->schemaname)),
                                      makeString(pstrdup(rv->relname)));
            else
                namelist = list_make1(makeString(pstrdup(rv->relname)));

            drop2->objects = lappend(drop2->objects, namelist);
        }
        warn_and_normal_drop(drop2, queryString, readOnlyTree, context,
                             params, queryEnv, dest, qc);
    }

    foreach(lc, to_move)
    {
        RangeVar *rv = (RangeVar *) lfirst(lc);
        Oid relid = RangeVarGetRelid(rv, AccessExclusiveLock, false);
        if (!OidIsValid(relid))
            continue;
        move_relation_to_recyclebin(relid,
                                    rv->schemaname ? rv->schemaname : "public",
                                    rv->relname,
                                    stmt->behavior);
    }
}

/* flashback(text): restore the most recent entry for a given original name */
Datum
pgrecyclebin_flashback(PG_FUNCTION_ARGS)
{
    text *t = PG_GETARG_TEXT_PP(0);
    char *orig_name = text_to_cstring(t);
    int spi_rc;
    bool ok = false;
    StringInfoData sql;
    char *rbname;
    char *rbname_real;
    char *orig_schema;
    char *orig_name2;
    Oid src_nspoid;
    Oid dest_nspoid;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");
    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "SELECT rbname, orig_schema, orig_name "
                     "FROM \"%s\".\"%s\" WHERE orig_name=%s "
                     "ORDER BY drop_time DESC LIMIT 1",
                     RB_SCHEMA, RB_CATALOG, quote_literal_cstr(orig_name));
    spi_rc = SPI_execute(sql.data, true, 1);
    if (spi_rc != SPI_OK_SELECT)
        elog(ERROR, "[pgrecyclebin] SPI SELECT failed rc=%d", spi_rc);
    if (SPI_processed == 0)
    {
        SPI_finish();
        pfree(sql.data);
        PG_RETURN_BOOL(false);
    }

    rbname = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    orig_schema = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
    orig_name2 = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3);
    /* Keep a durable copy of the recycle-bin name BEFORE any rename happens */
    rbname_real = pstrdup(rbname);
    if (name_exists_in_schema(orig_schema, orig_name2, NULL))
        ereport(ERROR,
                (errcode(ERRCODE_DUPLICATE_TABLE),
                 errmsg("object \"%s.%s\" already exists", orig_schema, orig_name2)));

    /* (1) Lock both source (RB) and destination schema to prevent concurrent DROP */
    src_nspoid  = get_namespace_oid(RB_SCHEMA, false);
    dest_nspoid = get_namespace_oid(orig_schema, false);
    LockSharedObject(NamespaceRelationId, src_nspoid, 0, AccessShareLock);
    LockSharedObject(NamespaceRelationId, dest_nspoid, 0, AccessShareLock);

    /* Rename back to original name if needed */
    if (strcmp(rbname, orig_name2) != 0)
    {
        RenameStmt *rs = makeNode(RenameStmt);
        PlannedStmt *wrap1;

        rs->renameType = OBJECT_TABLE;
        rs->relation = makeRangeVar(pstrdup(RB_SCHEMA), pstrdup(rbname), -1);
        rs->newname = pstrdup(orig_name2);
        rs->behavior = DROP_RESTRICT;
        rs->missing_ok = false;
        wrap1 = makeNode(PlannedStmt);
        wrap1->commandType = CMD_UTILITY;
        wrap1->utilityStmt = (Node *) rs;
        wrap1->canSetTag = false;

        standard_ProcessUtility(wrap1, NULL, false, PROCESS_UTILITY_TOPLEVEL,
                                NULL, NULL, NULL, NULL);
        rbname = orig_name2;
    }

    /* SET SCHEMA back to original */
    {
        AlterObjectSchemaStmt *as = makeNode(AlterObjectSchemaStmt);
        PlannedStmt *wrap2;

        as->objectType = OBJECT_TABLE;
        as->relation = makeRangeVar(pstrdup(RB_SCHEMA), pstrdup(rbname), -1);
        as->newschema = pstrdup(orig_schema);
        as->missing_ok = false;

        wrap2 = makeNode(PlannedStmt);
        wrap2->commandType = CMD_UTILITY;
        wrap2->utilityStmt = (Node *) as;
        wrap2->canSetTag = false;
        standard_ProcessUtility(wrap2, NULL, false, PROCESS_UTILITY_TOPLEVEL,
                                NULL, NULL, NULL, NULL);
    }


    catalog_delete_by_rbname(rbname_real);
    ok = true;

    /* (1) Release locks */
    UnlockSharedObject(NamespaceRelationId, dest_nspoid, 0, AccessShareLock);
    UnlockSharedObject(NamespaceRelationId, src_nspoid, 0, AccessShareLock);
    SPI_finish();
    pfree(sql.data);
    pfree(rbname_real);
    PG_RETURN_BOOL(ok);
}

/* ProcessUtility hook */
static void
pgrecyclebin_ProcessUtility(PlannedStmt *pstmt,
                            const char *queryString,
                            bool readOnlyTree,
                            ProcessUtilityContext context,
                            ParamListInfo params,
                            QueryEnvironment *queryEnv,
                            DestReceiver *dest,
                            QueryCompletion *qc)
{
    Node *parsetree;
    /* If we’re executing internal RB work, just pass through. */
    if (rb_in_progress) 
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                                params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                                    params, queryEnv, dest, qc);
        return;
    }

    /* 1) Lazy one-time (per-backend) schema/catalog ensure */
    if (!rb_initialized && !IsBootstrapProcessingMode() && !rb_in_progress)
    {
        rb_in_progress = true;
        PG_TRY();
        {
            elog(LOG, "[pgrecyclebin] ensuring recycle bin schema (lazy init)");
            ensure_recyclebin_schema_and_catalog();
            rb_initialized = true;
        }
        PG_CATCH();
        {
            rb_in_progress = false;
            PG_RE_THROW();
        }
        PG_END_TRY();
        rb_in_progress = false;
    }

    parsetree = pstmt->utilityStmt;
    /* Disallow CREATE SCHEMA "_$recyclebin$" */
    if (nodeTag(parsetree) == T_CreateSchemaStmt)
    {
        CreateSchemaStmt *cs = (CreateSchemaStmt *) parsetree;
        if (cs->schemaname && is_recyclebin_schema(cs->schemaname))
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("creation of schema \"%s\" is not allowed", RB_SCHEMA)));
    }

    /* Protect dropping of the internal catalog table */
    if (nodeTag(parsetree) == T_DropStmt)
    {
        DropStmt *ds = (DropStmt *) parsetree;
        if (ds->removeType == OBJECT_TABLE)
        {
            ListCell *lc;
            foreach(lc, ds->objects)
            {
                RangeVar *rv = rv_from_objname((List *) lfirst(lc));
                if (rv->schemaname && is_recyclebin_schema(rv->schemaname) &&
                    rv->relname && strcmp(rv->relname, RB_CATALOG) == 0)
                {
                    ereport(ERROR,
                            (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                             errmsg("dropping recycle bin catalog \"%s.%s\" is not allowed",
                                    RB_SCHEMA, RB_CATALOG)));
                }
            }
        }
    }

    /* Main interception: DROP TABLE */
    if (nodeTag(parsetree) == T_DropStmt)
    {
        DropStmt *stmt = (DropStmt *) parsetree;
        if (stmt->removeType == OBJECT_TABLE)
        {
            handle_drop_table(stmt, queryString, readOnlyTree, context,
                              params, queryEnv, dest, qc);
            return;
        }
    }

    /* Pass-through for everything else */
    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                            params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                                params, queryEnv, dest, qc);
}

/* Module load/unload */
void
_PG_init(void)
{
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = pgrecyclebin_ProcessUtility;
}

void
_PG_fini(void)
{
    ProcessUtility_hook = prev_ProcessUtility;
    elog(LOG, "pgrecyclebin unloaded (recycle bin schema remains intact)");
}
