
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
#include "catalog/namespace.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "commands/alter.h"
#include "commands/defrem.h"
#include "commands/schemacmds.h"
#include "commands/sequence.h"
#include "commands/tablecmds.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/parsenodes.h"
#include "parser/parse_node.h"
#include "parser/parse_utilcmd.h"   /* makeNameListFromRangeVar */
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "catalog/objectaddress.h" /* must precede parse_utilcmd.h for PG17+ */
#include "parser/parse_utilcmd.h"  /* makeNameListFromRangeVar */
#include "access/relation.h"       /* relation_open / relation_close */
#include "utils/varlena.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

#define RB_SCHEMA "_$recyclebin$"
#define RB_CATALOG "_rb_catalog"

static ProcessUtility_hook_type prev_ProcessUtility = NULL;

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

/* ------------------------------------------------------------- */

static bool
is_recyclebin_schema(const char *schemaname)
{
    if (!schemaname)
        return false;
    return strcmp(schemaname, RB_SCHEMA) == 0;
}

/* Ensure "_$recyclebin$" schema and catalog exist */
static void
ensure_recyclebin_schema_and_catalog(void)
{
    int spi_rc;
    StringInfoData buf;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed: %d", spi_rc);

    initStringInfo(&buf);
    appendStringInfo(&buf,
                     "DO $$ BEGIN "
                     "IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = %s) THEN "
                     "EXECUTE 'CREATE SCHEMA \"%s\"'; "
                     "END IF; "
                     "IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                     "WHERE n.nspname = %s AND c.relname = %s) THEN "
                     "EXECUTE 'CREATE TABLE \"%s\".\"%s\"("
                     "rbname name PRIMARY KEY,"
                     "orig_schema name NOT NULL,"
                     "orig_name name NOT NULL,"
                     "drop_time timestamptz NOT NULL DEFAULT now(),"
                     "orig_oid oid NOT NULL)'; "
                     "END IF; END $$;",
                     quote_literal_cstr(RB_SCHEMA),
                     RB_SCHEMA,
                     quote_literal_cstr(RB_SCHEMA),
                     quote_literal_cstr(RB_CATALOG),
                     RB_SCHEMA, RB_CATALOG);

    spi_rc = SPI_execute(buf.data, false, 0);

#if PG_VERSION_NUM >= 150000
    if (spi_rc != SPI_OK_UTILITY)
#else
    if (spi_rc != SPI_OK_DO_BLOCK)
#endif
        elog(ERROR, "failed to create recycle bin schema/catalog (rc=%d)", spi_rc);

    SPI_finish();
    pfree(buf.data);
}

/* Compose a safe RB name like <orig>_$oid */
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
    int spi_rc;
    StringInfoData sql;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "INSERT INTO \"%s\".\"%s\"(rbname, orig_schema, orig_name, drop_time, orig_oid) "
                     "VALUES (%s, %s, %s, now(), %u)",
                     RB_SCHEMA, RB_CATALOG,
                     quote_literal_cstr(rbname),
                     quote_literal_cstr(orig_schema),
                     quote_literal_cstr(orig_name),
                     orig_oid);

    spi_rc = SPI_execute(sql.data, false, 0);
    if (spi_rc != SPI_OK_INSERT)
        elog(ERROR, "failed to insert recycle bin catalog row (rc=%d)", spi_rc);

    SPI_finish();
    pfree(sql.data);
}

/* Delete catalog row by rbname */
static void
catalog_delete_by_rbname(const char *rbname)
{
    int spi_rc;
    StringInfoData sql;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "DELETE FROM \"%s\".\"%s\" WHERE rbname = %s",
                     RB_SCHEMA, RB_CATALOG,
                     quote_literal_cstr(rbname));

    spi_rc = SPI_execute(sql.data, false, 0);
    if (spi_rc != SPI_OK_DELETE)
        elog(ERROR, "failed to delete recycle bin row (rc=%d)", spi_rc);

    SPI_finish();
    pfree(sql.data);
}

/* Check if name exists */
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

    ensure_recyclebin_schema_and_catalog();
    rel = relation_open(relid, AccessExclusiveLock);
    rbname = compose_rbname(orig_name, relid);
    catalog_insert_rbrow(rbname, orig_schema, orig_name, relid);

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

    relation_close(rel, NoLock);
    if (behavior == DROP_CASCADE)
        move_dependents_cascade(relid, behavior);
}

/* Cascade dependents (simplified) */
static void
move_dependents_cascade(Oid relid, DropBehavior behavior)
{
    int spi_rc;
    StringInfoData sql;
    uint64 i;

    spi_rc = SPI_connect();
    if (spi_rc != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

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

    SPI_finish();
    pfree(sql.data);
}

/* Warn + perform normal drop for recycle-bin tables */
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

    foreach(lc, stmt->objects)
    {
        RangeVar *rv = makeRangeVarFromNameList((List *) lfirst(lc));
        if (rv->schemaname && is_recyclebin_schema(rv->schemaname))
        {
            ereport(WARNING,
                    (errmsg("dropping \"%s.%s\" permanently", rv->schemaname, rv->relname)));
            catalog_delete_by_rbname(rv->relname);
        }
    }

    if (prev_ProcessUtility)
        prev_ProcessUtility((PlannedStmt *) stmt, queryString, readOnlyTree,
                            context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility((PlannedStmt *) stmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);
}

/* Handle DROP TABLE */
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

    foreach(lc, stmt->objects)
    {
        List *objname = (List *) lfirst(lc);
        RangeVar *rv = NULL;
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
            elog(ERROR, "unexpected object name structure in DROP TABLE");
        }

        rv = makeRangeVar(schemaname ? pstrdup(schemaname) : NULL,
                          pstrdup(relname),
                          -1);
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
        move_relation_to_recyclebin(relid,
                                    rv->schemaname ? rv->schemaname : "public",
                                    rv->relname,
                                    stmt->behavior);
    }
}

/* flashback(text) */
Datum
pgrecyclebin_flashback(PG_FUNCTION_ARGS)
{
    text *t = PG_GETARG_TEXT_PP(0);
    char *orig_name = text_to_cstring(t);
    int spi_rc;
    bool ok = false;
    StringInfoData sql;
    char *rbname;
    char *orig_schema;
    char *orig_name2;
    AlterObjectSchemaStmt *as;
    PlannedStmt *wrap2;

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
        elog(ERROR, "SPI SELECT failed");

    if (SPI_processed == 0)
    {
        SPI_finish();
        PG_RETURN_BOOL(false);
    }

    rbname = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    orig_schema = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
    orig_name2 = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3);

    if (name_exists_in_schema(orig_schema, orig_name2, NULL))
        ereport(ERROR,
                (errcode(ERRCODE_DUPLICATE_TABLE),
                 errmsg("object \"%s.%s\" already exists", orig_schema, orig_name2)));

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

    as = makeNode(AlterObjectSchemaStmt);
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

    catalog_delete_by_rbname(rbname);
    ok = true;
    SPI_finish();
    pfree(sql.data);
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
    Node *parsetree = pstmt->utilityStmt;

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
                RangeVar *rv = makeRangeVarFromNameList((List *) lfirst(lc));
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
}
