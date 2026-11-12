use dbx_authz::{Match, Operations};
use proptest::prelude::*;
use sqlparser::parser::Parser;

use super::*;
use crate::models::connection::DatabaseType;

fn context(database_type: DatabaseType) -> ResolveContext<'static> {
    let (schema_aware, default_schema) = match database_type {
        DatabaseType::SqlServer => (true, Some("dbo")),
        DatabaseType::Postgres | DatabaseType::Oracle | DatabaseType::Dameng | DatabaseType::Kingbase => {
            (true, Some("public"))
        }
        _ => (false, None),
    };
    ResolveContext { connection_id: "c", active_database: Some("app"), default_schema, schema_aware }
}

fn describe(sql: &str, database_type: DatabaseType) -> Vec<String> {
    let requirement = classify_sql_operations(sql, database_type).resolve(&context(database_type));
    let mut lines: Vec<String> = requirement
        .needs
        .iter()
        .map(|need| {
            let prefix = if need.mode == Match::AnyWithin { "~" } else { "" };
            let resource = need.resource.to_string();
            let resource = resource.strip_prefix("c/").unwrap_or(&resource).to_string();
            let operations = if need.any_of == Operations::WRITES && need.all_of.is_empty() {
                "ANY_WRITE".to_string()
            } else {
                need.all_of.names().join("|")
            };
            format!("{prefix}{resource} {operations}")
        })
        .collect();
    lines.sort();
    lines
}

#[track_caller]
fn check(sql: &str, database_type: DatabaseType, expected: &[&str]) {
    let mut expected: Vec<String> = expected.iter().map(|line| line.to_string()).collect();
    expected.sort();
    assert_eq!(describe(sql, database_type), expected, "{database_type:?}: {sql}");
}

#[track_caller]
fn pg(sql: &str, expected: &[&str]) {
    check(sql, DatabaseType::Postgres, expected);
}

#[track_caller]
fn mysql(sql: &str, expected: &[&str]) {
    check(sql, DatabaseType::Mysql, expected);
}

#[track_caller]
fn sqlserver(sql: &str, expected: &[&str]) {
    check(sql, DatabaseType::SqlServer, expected);
}

#[track_caller]
fn assert_unclassified(sql: &str, database_type: DatabaseType) {
    let requirement = classify_sql_operations(sql, database_type);
    assert!(requirement.is_unclassified(), "{database_type:?}: {sql} -> {requirement:?}");
}

#[test]
fn plain_reads_require_select_on_each_table() {
    pg("SELECT * FROM users", &["app/public/users SELECT"]);
    pg(
        "SELECT u.id FROM users u JOIN sales.orders o ON o.user_id = u.id",
        &["app/public/users SELECT", "app/sales/orders SELECT"],
    );
    pg(
        "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)",
        &["app/public/orders SELECT", "app/public/users SELECT"],
    );
    pg("SELECT * FROM public.users, sales.users", &["app/public/users SELECT", "app/sales/users SELECT"]);
    pg("SELECT * FROM \"Users\"", &["app/public/Users SELECT"]);
    sqlserver("SELECT * FROM users", &["app/dbo/users SELECT"]);
}

#[test]
fn table_less_reads_need_select_somewhere_in_the_active_database() {
    pg("SELECT 1", &["~app/*/* SELECT"]);
    pg("SELECT * FROM generate_series(1, 3)", &["~app/*/* SELECT"]);
    mysql("SHOW TABLES", &["~app/*/* SELECT"]);
}

#[test]
fn cte_names_are_not_tables() {
    pg("WITH x AS (SELECT * FROM users) SELECT * FROM x", &["app/public/users SELECT"]);
}

#[test]
fn explain_requires_the_operations_of_the_explained_statement() {
    pg("EXPLAIN SELECT * FROM users", &["app/public/users SELECT"]);
    pg("EXPLAIN ANALYZE DELETE FROM users", &["app/public/users DELETE"]);
    pg("EXPLAIN DELETE FROM users WHERE id = 1", &["app/public/users DELETE"]);
}

#[test]
fn row_locks_require_update() {
    pg("SELECT * FROM users FOR UPDATE", &["app/public/users SELECT|UPDATE"]);
    pg("LOCK TABLE users IN EXCLUSIVE MODE", &["app/public/users SELECT|UPDATE"]);
}

#[test]
fn inserts_and_their_variants() {
    pg("INSERT INTO users (id) VALUES (1)", &["app/public/users INSERT"]);
    pg("INSERT INTO archive SELECT * FROM users", &["app/public/archive INSERT", "app/public/users SELECT"]);
    pg("INSERT INTO users SELECT * FROM users", &["app/public/users SELECT|INSERT"]);
    pg(
        "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = excluded.id",
        &["app/public/users INSERT|UPDATE"],
    );
    pg("INSERT INTO users (id) VALUES (1) ON CONFLICT DO NOTHING", &["app/public/users INSERT"]);
    pg("INSERT INTO users (id) VALUES (1) RETURNING id", &["app/public/users SELECT|INSERT"]);
    mysql("INSERT INTO users (id) VALUES (1) ON DUPLICATE KEY UPDATE id = 2", &["app/*/users INSERT|UPDATE"]);
    mysql("REPLACE INTO users VALUES (1)", &["app/*/users INSERT|DELETE"]);
    check("INSERT OR REPLACE INTO users VALUES (1)", DatabaseType::Sqlite, &["app/*/users INSERT|DELETE"]);
}

#[test]
fn updates_and_their_sources() {
    pg("UPDATE users SET a = 1 WHERE id = 1", &["app/public/users UPDATE"]);
    pg(
        "UPDATE users SET a = o.x FROM orders o WHERE o.id = users.id",
        &["app/public/orders SELECT", "app/public/users UPDATE"],
    );
    pg("UPDATE users SET a = (SELECT max(b) FROM orders)", &["app/public/orders SELECT", "app/public/users UPDATE"]);
    pg("UPDATE users SET a = 1 RETURNING *", &["app/public/users SELECT|UPDATE"]);
    mysql("UPDATE users u JOIN orders o ON u.id = o.uid SET u.a = 1", &["app/*/orders UPDATE", "app/*/users UPDATE"]);
}

#[test]
fn deletes_and_their_sources() {
    pg("DELETE FROM users WHERE id = 1", &["app/public/users DELETE"]);
    pg(
        "DELETE FROM users USING orders WHERE orders.uid = users.id",
        &["app/public/orders SELECT", "app/public/users DELETE"],
    );
    mysql("DELETE u FROM users u JOIN orders o ON u.id = o.uid", &["app/*/orders DELETE", "app/*/users DELETE"]);
}

#[test]
fn merge_requires_the_operations_of_its_branches() {
    pg(
        "MERGE INTO users t USING staging s ON t.id = s.id \
         WHEN MATCHED THEN UPDATE SET a = s.a WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)",
        &["app/public/staging SELECT", "app/public/users INSERT|UPDATE"],
    );
    pg(
        "MERGE INTO users t USING staging s ON t.id = s.id WHEN MATCHED THEN DELETE",
        &["app/public/staging SELECT", "app/public/users DELETE"],
    );
}

#[test]
fn data_modifying_cte_is_detected() {
    pg("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", &["app/public/users SELECT|DELETE"]);
}

#[test]
fn select_into_and_create_table_as_create_and_fill_a_table() {
    pg("SELECT * INTO new_t FROM users", &["app/public/new_t INSERT|CREATE", "app/public/users SELECT"]);
    pg("CREATE TABLE t2 AS SELECT * FROM users", &["app/public/t2 INSERT|CREATE", "app/public/users SELECT"]);
}

#[test]
fn ddl_maps_to_create_alter_drop_and_truncate() {
    pg("CREATE TABLE t (id int)", &["app/public/t CREATE"]);
    pg("CREATE OR REPLACE VIEW v AS SELECT * FROM users", &["app/public/users SELECT", "app/public/v CREATE|ALTER"]);
    pg("CREATE INDEX idx ON users (a)", &["app/public/users CREATE"]);
    pg("CREATE SCHEMA rep", &["app/rep/* CREATE"]);
    pg("CREATE DATABASE other", &["other/*/* CREATE"]);
    pg("CREATE SEQUENCE s", &["app/public/* CREATE"]);
    pg("CREATE FUNCTION sales.f() RETURNS int AS 'SELECT 1' LANGUAGE sql", &["app/sales/* CREATE"]);
    pg("ALTER TABLE users ADD COLUMN x int", &["app/public/users ALTER"]);
    pg("COMMENT ON COLUMN users.name IS 'x'", &["app/public/users ALTER"]);
    pg("DROP TABLE users, orders", &["app/public/orders DROP", "app/public/users DROP"]);
    pg("DROP SCHEMA rep", &["app/rep/* DROP"]);
    pg("DROP DATABASE other", &["other/*/* DROP"]);
    pg("DROP INDEX sales.idx", &["app/sales/* DROP"]);
    pg("TRUNCATE users", &["app/public/users TRUNCATE"]);
}

#[test]
fn privilege_statements_require_grant_on_the_connection() {
    pg("GRANT SELECT ON users TO bob", &["*/*/* GRANT"]);
    pg("REVOKE SELECT ON users FROM bob", &["*/*/* GRANT"]);
    pg("CREATE ROLE bob", &["*/*/* GRANT"]);
    pg("DROP ROLE bob", &["*/*/* GRANT"]);
}

#[test]
fn procedures_require_execute_and_dynamic_execution_is_unclassified() {
    pg("CALL sales.refresh()", &["app/sales/* EXECUTE"]);
    sqlserver("EXEC dbo.archive_orders", &["app/dbo/* EXECUTE"]);
    pg("EXECUTE my_plan", &["*/*/* UNCLASSIFIED"]);
    assert_unclassified("DO $$ BEGIN DELETE FROM users; END $$", DatabaseType::Postgres);
    assert_unclassified("BEGIN DELETE FROM users; END;", DatabaseType::Oracle);
}

#[test]
fn prepare_alone_requires_nothing() {
    pg("PREPARE p AS DELETE FROM users", &[]);
}

#[test]
fn copy_requires_insert_or_export_and_server_files_are_unclassified() {
    pg("COPY users FROM STDIN", &["app/public/users INSERT"]);
    pg("COPY users TO STDOUT", &["app/public/users SELECT|EXPORT"]);
    pg("COPY (SELECT * FROM users) TO STDOUT", &["app/public/users SELECT|EXPORT"]);
    pg("COPY users FROM '/etc/passwd'", &["*/*/* UNCLASSIFIED"]);
}

#[test]
fn transactions_require_some_write_in_the_active_database() {
    pg("BEGIN; UPDATE users SET a = 1; COMMIT", &["app/public/users UPDATE", "~app/*/* ANY_WRITE"]);
    pg("INSERT INTO users DEFAULT VALUES; ROLLBACK", &["app/public/users INSERT", "~app/*/* ANY_WRITE"]);
}

#[test]
fn session_settings_are_neutral_but_privilege_changes_are_not() {
    pg("SET statement_timeout = 1000", &[]);
    pg("SET search_path TO sales; SELECT * FROM orders", &["app/*/* SELECT"]);
    pg("SET ROLE admin", &["*/*/* UNCLASSIFIED"]);
    mysql("SET GLOBAL max_connections = 10", &["*/*/* UNCLASSIFIED"]);
    mysql("SET @@global.max_connections = 10", &["*/*/* UNCLASSIFIED"]);
}

#[test]
fn use_switches_the_database_for_following_statements() {
    mysql("USE other; SELECT * FROM t", &["other/*/t SELECT"]);
    mysql("SELECT * FROM other.t", &["other/*/t SELECT"]);
    sqlserver("SELECT * FROM otherdb.dbo.t", &["otherdb/dbo/t SELECT"]);
}

#[test]
fn four_part_names_reach_other_servers_and_are_unclassified() {
    sqlserver("SELECT * FROM srv.db.dbo.t", &["*/*/* SELECT|UNCLASSIFIED"]);
}

#[test]
fn administrative_statements_are_unclassified() {
    assert_unclassified("PRAGMA journal_mode = WAL", DatabaseType::Sqlite);
    assert_unclassified("VACUUM", DatabaseType::Postgres);
    assert_unclassified("KILL 12", DatabaseType::Mysql);
    assert_unclassified("SHOW PROCESSLIST", DatabaseType::Mysql);
    assert_unclassified("ALTER SYSTEM SET work_mem = '1GB'", DatabaseType::Postgres);
    assert_unclassified("CREATE EXTENSION dblink", DatabaseType::Postgres);
}

#[test]
fn side_effect_functions_raise_the_requirement() {
    pg("SELECT nextval('s')", &["~app/*/* SELECT|UPDATE"]);
    pg("SELECT pg_terminate_backend(123)", &["*/*/* UNCLASSIFIED", "~app/*/* SELECT"]);
    assert_unclassified("SELECT set_config('role', 'admin', false)", DatabaseType::Postgres);
    assert_unclassified("SELECT * FROM dblink('host=x', 'DELETE FROM t') AS t(a int)", DatabaseType::Postgres);
}

#[test]
fn called_functions_are_reported_for_strict_mode() {
    let requirement = classify_sql_operations("SELECT lower(name), sales.score(id) FROM users", DatabaseType::Postgres);
    assert_eq!(requirement.functions, vec!["lower".to_string(), "sales.score".to_string()]);
}

#[test]
fn batches_combine_every_statement() {
    pg("SELECT * FROM users; DELETE FROM orders", &["app/public/orders DELETE", "app/public/users SELECT"]);
}

#[test]
fn cursor_declaration_reads_its_query() {
    pg("DECLARE c CURSOR FOR SELECT * FROM users", &["app/public/users SELECT"]);
}

#[test]
fn comments_only_require_nothing() {
    pg("-- nada", &[]);
}

#[test]
fn mysql_executable_comments_are_expanded() {
    mysql("/*!40000 DROP TABLE users */", &["app/*/users DROP"]);
    mysql("/*!40101 SET NAMES utf8mb4 */", &[]);
    assert_unclassified("SELECT * FROM users /*!50000 INTO OUTFILE '/tmp/x' */", DatabaseType::Mysql);
    assert_unclassified("SELECT * FROM users INTO OUTFILE '/tmp/x'", DatabaseType::Mysql);
}

#[test]
fn lexical_fallback_is_used_when_parsing_fails() {
    let requirement = classify_sql_operations(
        "SELECT * FROM t WHERE ROWNUM <= 10 CONNECT BY PRIOR a = b START",
        DatabaseType::Oracle,
    );
    if requirement.analysis == Analysis::Lexical {
        assert_eq!(requirement.operations(), Operations::SELECT);
    }
    assert_unclassified("SELECT * FROM t@remote_link", DatabaseType::Oracle);
    let lexical = classify_lexically("INSERT INTO t VALUES (1)", DatabaseType::Dameng);
    assert_eq!(lexical.operations(), Operations::INSERT | Operations::SELECT);
    let lexical = classify_lexically("MERGE INTO t USING s ON (1=1)", DatabaseType::Dameng);
    assert!(lexical.is_unclassified());
    let lexical = classify_lexically("SELECT 1; DROP TABLE t", DatabaseType::Dameng);
    assert_eq!(lexical.operations(), Operations::SELECT | Operations::DROP);
}

#[test]
fn engine_specific_classifiers_are_used() {
    let requirement = classify_sql_operations("SELECT Id FROM Account", DatabaseType::Salesforce);
    assert_eq!(requirement.analysis, Analysis::Engine);
    assert_eq!(requirement.operations(), Operations::SELECT);
}

#[test]
fn resolution_without_active_database_falls_back_to_the_connection() {
    let requirement = classify_sql_operations("BEGIN; SELECT * FROM users", DatabaseType::Postgres);
    let context = ResolveContext {
        connection_id: "c",
        active_database: None,
        default_schema: Some("public"),
        schema_aware: true,
    };
    let resolved = requirement.resolve(&context);
    assert!(resolved.needs.iter().all(|need| need.resource == Resource::connection("c")));
}

const DIFFERENTIAL_DATABASES: &[DatabaseType] = &[
    DatabaseType::Postgres,
    DatabaseType::Mysql,
    DatabaseType::SqlServer,
    DatabaseType::Sqlite,
    DatabaseType::Oracle,
    DatabaseType::ClickHouse,
    DatabaseType::Dameng,
];

const DIFFERENTIAL_CORPUS: &[&str] = &[
    "SELECT * FROM users",
    "SELECT 1",
    "SELECT * FROM users FOR UPDATE",
    "SELECT * FROM users LOCK IN SHARE MODE",
    "SELECT * INTO new_t FROM users",
    "SELECT * FROM users INTO OUTFILE '/tmp/x'",
    "/*!40000 DROP TABLE users */",
    "SELECT 1 /*!50000 , (SELECT 1 FROM secret) */",
    "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d",
    "INSERT INTO users VALUES (1)",
    "INSERT INTO users SELECT * FROM users ON CONFLICT DO NOTHING",
    "REPLACE INTO users VALUES (1)",
    "UPDATE users SET a = 1",
    "DELETE FROM users",
    "MERGE INTO users t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
    "TRUNCATE users",
    "CREATE TABLE t (id int)",
    "ALTER TABLE users ADD x int",
    "DROP TABLE users",
    "GRANT ALL ON users TO bob",
    "CALL refresh()",
    "EXEC refresh",
    "EXECUTE IMMEDIATE 'DROP TABLE t'",
    "BEGIN; DELETE FROM t; COMMIT",
    "BEGIN DELETE FROM t; END;",
    "COMMIT",
    "SAVEPOINT a",
    "EXPLAIN SELECT * FROM users",
    "EXPLAIN ANALYZE DELETE FROM users",
    "SHOW TABLES",
    "SHOW CREATE TABLE users",
    "DESCRIBE users",
    "PRAGMA journal_mode = WAL",
    "PRAGMA table_info(users)",
    "VACUUM",
    "ANALYZE users",
    "SET GLOBAL x = 1",
    "SET x = 1",
    "COPY users FROM STDIN",
    "COPY users TO '/tmp/x'",
    "LOAD DATA INFILE '/tmp/x' INTO TABLE users",
    "SELECT nextval('s')",
    "SELECT pg_advisory_lock(1)",
    "SELECT lo_unlink(1)",
    "SELECT * FROM t@link",
    "HANDLER users OPEN",
    "OPTIMIZE TABLE users",
    "RENAME TABLE a TO b",
    "LOCK TABLES users WRITE",
    "CHECKSUM TABLE users",
    "SELECT * FROM users WHERE note = 'DROP TABLE x'",
    "values (1), (2)",
    "UPSERT INTO users VALUES (1)",
    "WITH x AS (SELECT 1) INSERT INTO users SELECT * FROM x",
    "SELECT * FROM users; UPDATE users SET a = 1",
    "SELECT 1 -- ; DROP TABLE users",
    "SELECT 1; /* x */ DROP TABLE users",
];

fn is_write_requirement(requirement: &SqlRequirement) -> bool {
    requirement.operations().has_write() || requirement.transaction_control
}

fn statement_units(sql: &str, database_type: DatabaseType) -> Vec<String> {
    let units = if is_mysql_compatible_database(database_type) {
        let (outer, bodies) = split_executable_comments(sql);
        std::iter::once(outer).chain(bodies).collect()
    } else {
        vec![sql.to_string()]
    };
    let dialect = resolve_dialect(normalize_dialect(&format!("{database_type:?}")));
    units
        .into_iter()
        .flat_map(|unit| match Parser::parse_sql(dialect.as_ref(), &unit) {
            Ok(statements) => statements
                .iter()
                .filter(|statement| !is_neutral_statement(statement) && !is_reviewed_read(statement))
                .map(ToString::to_string)
                .collect(),
            Err(_) => vec![unit],
        })
        .collect()
}

fn assert_not_more_permissive(sql: &str, database_type: DatabaseType) -> Result<(), String> {
    let requirement = classify_sql_operations(sql, database_type);
    if is_write_requirement(&requirement) {
        return Ok(());
    }
    for unit in statement_units(sql, database_type) {
        if is_write_sql_for_database(&unit, database_type) {
            return Err(format!(
                "{database_type:?}: read-only check says write for `{unit}`, got {requirement:?}: {sql}"
            ));
        }
        if let Ok(risk) = classify_sql_risk_for_database(&unit, database_type) {
            if risk != SqlRisk::ReadOnly {
                return Err(format!("{database_type:?}: SqlRisk says {risk} for `{unit}`, got {requirement:?}: {sql}"));
            }
        }
    }
    Ok(())
}

#[test]
fn classifier_is_never_more_permissive_than_existing_checks_on_the_corpus() {
    let failures: Vec<String> = DIFFERENTIAL_CORPUS
        .iter()
        .flat_map(|sql| DIFFERENTIAL_DATABASES.iter().map(move |database_type| (sql, *database_type)))
        .filter_map(|(sql, database_type)| assert_not_more_permissive(sql, database_type).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

const FRAGMENTS: &[&str] = &[
    "SELECT",
    "INSERT",
    "INTO",
    "UPDATE",
    "DELETE",
    "FROM",
    "WHERE",
    "SET",
    "VALUES",
    "MERGE",
    "USING",
    "WHEN",
    "MATCHED",
    "THEN",
    "WITH",
    "AS",
    "(",
    ")",
    ",",
    ";",
    "*",
    "1",
    "=",
    "users",
    "t",
    "s.t",
    "a.b.c.d",
    "'x'",
    "'; DROP TABLE x; --'",
    "/*!",
    "*/",
    "--",
    "\n",
    "FOR",
    "SHARE",
    "RETURNING",
    "CREATE",
    "TABLE",
    "DROP",
    "ALTER",
    "TRUNCATE",
    "GRANT",
    "CALL",
    "EXEC",
    "EXECUTE",
    "IMMEDIATE",
    "BEGIN",
    "END",
    "COMMIT",
    "USE",
    "app",
    "EXPLAIN",
    "ANALYZE",
    "COPY",
    "STDIN",
    "TO",
    "nextval('s')",
    "pg_terminate_backend(1)",
    "GLOBAL",
    "OUTFILE",
    "LOCK",
    "IN",
    "MODE",
    "REPLACE",
    "OR",
    "IGNORE",
    "DUPLICATE",
    "KEY",
    "ON",
    "CONFLICT",
    "DO",
    "NOTHING",
    "$$",
    "@link",
    "JOIN",
    "LATERAL",
    "UNION",
    "ALL",
    "ORDER",
    "BY",
    "LIMIT",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn classifier_is_never_more_permissive_than_existing_checks_on_generated_sql(
        words in proptest::collection::vec(proptest::sample::select(FRAGMENTS), 1..14),
        database_type in proptest::sample::select(DIFFERENTIAL_DATABASES),
    ) {
        let sql = words.join(" ");
        if let Err(message) = assert_not_more_permissive(&sql, database_type) {
            prop_assert!(false, "{}", message);
        }
    }
}
