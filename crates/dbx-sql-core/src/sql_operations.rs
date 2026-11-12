use std::collections::HashSet;
use std::ops::ControlFlow;

use dbx_authz::{Need, Operations, Requirement, Resource};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    CommentObject, ContextModifier, CopySource, CopyTarget, CreateTableLikeKind, Expr, FromTable, Insert, MergeAction,
    ObjectName, ObjectNamePart, ObjectType, OnConflictAction, OnInsert, Query, SchemaName, Select, Set, SetExpr,
    SqliteOnConflict, Statement, TableFactor, TableObject, TableWithJoins, Use, Visit, Visitor,
};
use sqlparser::parser::Parser;

use crate::models::connection::DatabaseType;
use crate::query_execution_sql::{
    classify_salesforce_statement_risk, classify_search_engine_query_risk, has_dialect_specific_write,
    is_mysql_compatible_database, is_write_sql_for_database, strip_sql_comments_and_literals, SalesforceStatementRisk,
    SearchEngineQueryRisk,
};
use crate::sql_risk::{
    classify_sql_risk_for_database, normalize_dialect, resolve_dialect, sql_contains_locking_clause,
    supports_select_into_table_creation, SqlRisk,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum SchemaHint {
    Default,
    Named(String),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Relation,
    Container,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Target {
    Connection,
    Database { name: Option<String>, within: bool },
    Object { database: Option<String>, schema: SchemaHint, parts: Vec<String>, kind: ObjectKind },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAccess {
    pub target: Target,
    pub operations: Operations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Analysis {
    Ast,
    Lexical,
    Engine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlRequirement {
    pub accesses: Vec<ObjectAccess>,
    pub transaction_control: bool,
    pub functions: Vec<String>,
    pub analysis: Analysis,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolveContext<'a> {
    pub connection_id: &'a str,
    pub active_database: Option<&'a str>,
    pub default_schema: Option<&'a str>,
    pub schema_aware: bool,
}

impl SqlRequirement {
    fn empty(analysis: Analysis) -> Self {
        Self { accesses: Vec::new(), transaction_control: false, functions: Vec::new(), analysis }
    }

    pub fn operations(&self) -> Operations {
        self.accesses.iter().fold(Operations::empty(), |acc, access| acc | access.operations)
    }

    pub fn is_unclassified(&self) -> bool {
        self.operations().contains(Operations::UNCLASSIFIED)
    }

    fn add(&mut self, target: Target, operations: Operations) {
        if operations.is_empty() {
            return;
        }
        match self.accesses.iter_mut().find(|access| access.target == target) {
            Some(access) => access.operations |= operations,
            None => self.accesses.push(ObjectAccess { target, operations }),
        }
    }

    fn merge(&mut self, other: SqlRequirement) {
        for access in other.accesses {
            self.add(access.target, access.operations);
        }
        self.transaction_control |= other.transaction_control;
        for function in other.functions {
            if !self.functions.contains(&function) {
                self.functions.push(function);
            }
        }
        if other.analysis == Analysis::Lexical {
            self.analysis = Analysis::Lexical;
        }
    }

    pub fn resolve(&self, context: &ResolveContext<'_>) -> Requirement {
        let mut requirement = Requirement::new();
        for access in &self.accesses {
            let (resource, within) = resolve_target(&access.target, context);
            let need = if within {
                Need::within(resource, access.operations)
            } else {
                Need::exact(resource, access.operations)
            };
            requirement.push(need);
        }
        if self.transaction_control {
            let (resource, _) = resolve_target(&Target::Database { name: None, within: true }, context);
            requirement.push(Need::any_write_within(resource));
        }
        requirement
    }
}

fn resolve_target(target: &Target, context: &ResolveContext<'_>) -> (Resource, bool) {
    let connection = Resource::connection(context.connection_id);
    match target {
        Target::Connection => (connection, false),
        Target::Database { name, within } => {
            let database = name.as_deref().or(context.active_database);
            (build_resource(connection, database, None, None), *within)
        }
        Target::Object { database, schema, parts, kind } => {
            let base = database.as_deref().or(context.active_database);
            let current_schema = match schema {
                SchemaHint::Default => context.default_schema,
                SchemaHint::Named(name) => Some(name.as_str()),
                SchemaHint::Unknown => None,
            };
            let part = |index: usize| parts.get(index).map(String::as_str);
            let resource = match (context.schema_aware, kind, parts.len()) {
                (_, _, len) if len >= 4 => connection,
                (true, ObjectKind::Relation, 1) => match current_schema {
                    Some(schema) => build_resource(connection, base, Some(schema), part(0)),
                    None => build_resource(connection, base, None, None),
                },
                (true, ObjectKind::Relation, 2) => build_resource(connection, base, part(0), part(1)),
                (true, ObjectKind::Relation, _) => build_resource(connection, part(0), part(1), part(2)),
                (true, ObjectKind::Container, 0) => build_resource(connection, base, current_schema, None),
                (true, ObjectKind::Container, 1) => build_resource(connection, base, part(0), None),
                (true, ObjectKind::Container, 2) => build_resource(connection, part(0), part(1), None),
                (true, ObjectKind::Container, _) => connection,
                (false, ObjectKind::Relation, 1) => build_resource(connection, base, None, part(0)),
                (false, ObjectKind::Relation, 2) => build_resource(connection, part(0), None, part(1)),
                (false, ObjectKind::Relation, _) => build_resource(connection, part(0), None, None),
                (false, ObjectKind::Container, 0) => build_resource(connection, base, None, None),
                (false, ObjectKind::Container, _) => build_resource(connection, part(0), None, None),
            };
            (resource, false)
        }
    }
}

fn build_resource(connection: Resource, database: Option<&str>, schema: Option<&str>, table: Option<&str>) -> Resource {
    let Some(database) = database else {
        return connection;
    };
    let mut resource = connection.with_database(database);
    if let Some(schema) = schema {
        resource = resource.with_schema(schema);
    }
    if let Some(table) = table {
        resource = resource.with_table(table);
    }
    resource
}

pub fn classify_sql_operations(sql: &str, database_type: DatabaseType) -> SqlRequirement {
    if let Some(requirement) = classify_engine_specific(sql, database_type) {
        return requirement;
    }
    if is_mysql_compatible_database(database_type) {
        classify_mysql_text(sql, database_type)
    } else {
        classify_sql_text(sql, database_type)
    }
}

fn existing_checks_report_write(sql: &str, database_type: DatabaseType) -> bool {
    is_write_sql_for_database(sql, database_type)
        || !matches!(classify_sql_risk_for_database(sql, database_type), Ok(SqlRisk::ReadOnly) | Err(_))
}

pub(crate) fn is_neutral_statement(statement: &Statement) -> bool {
    if let Statement::Query(query) = statement {
        return query.with.is_none() && matches!(query.body.as_ref(), SetExpr::Values(_));
    }
    matches!(
        statement,
        Statement::Set(_)
            | Statement::Use(_)
            | Statement::Declare { .. }
            | Statement::Fetch { .. }
            | Statement::Close { .. }
            | Statement::Deallocate { .. }
            | Statement::Discard { .. }
            | Statement::Reset(_)
            | Statement::Prepare { .. }
            | Statement::Print(_)
            | Statement::UnlockTables
    )
}

fn reads_where_existing_checks_see_a_write(statement: &Statement, database_type: DatabaseType) -> bool {
    if is_neutral_statement(statement) || is_reviewed_read(statement) {
        return false;
    }
    let text = statement.to_string();
    if !existing_checks_report_write(&text, database_type) {
        return false;
    }
    let dialect = resolve_dialect(normalize_dialect(&format!("{database_type:?}")));
    let mut alone = Classifier::new(database_type);
    alone.lock_everything = sql_contains_locking_clause(&text, dialect.as_ref());
    alone.statement(statement);
    !alone.out.operations().has_write() && !alone.out.transaction_control
}

fn is_reviewed_read(statement: &Statement) -> bool {
    matches!(statement, Statement::Copy { to: true, target: CopyTarget::Stdout, .. })
}

fn classify_mysql_text(sql: &str, database_type: DatabaseType) -> SqlRequirement {
    let (outer, bodies) = split_executable_comments(sql);
    let mut requirement = classify_sql_text(&outer, database_type);
    if has_dialect_specific_write(&outer, database_type) {
        requirement.add(Target::Connection, Operations::UNCLASSIFIED);
    }
    for body in bodies {
        let inner = classify_sql_text(&body, database_type);
        let fragment = inner.analysis == Analysis::Lexical || has_dialect_specific_write(&body, database_type);
        requirement.merge(inner);
        if fragment {
            requirement.add(Target::Connection, Operations::UNCLASSIFIED);
        }
    }
    requirement
}

fn split_executable_comments(sql: &str) -> (String, Vec<String>) {
    let mut outer = String::with_capacity(sql.len());
    let mut bodies = Vec::new();
    let mut rest = sql;
    while let Some(start) = rest.find("/*") {
        let after = &rest[start + 2..];
        let marker = if after.starts_with('!') {
            1
        } else if after.starts_with("M!") {
            2
        } else {
            outer.push_str(&rest[..start + 2]);
            rest = after;
            continue;
        };
        outer.push_str(&rest[..start]);
        outer.push(' ');
        let body_start = &after[marker..];
        let (body, remainder) = match body_start.find("*/") {
            Some(end) => (&body_start[..end], &body_start[end + 2..]),
            None => (body_start, ""),
        };
        bodies.push(body.trim_start_matches(|ch: char| ch.is_ascii_digit()).to_string());
        rest = remainder;
    }
    outer.push_str(rest);
    (outer, bodies)
}

fn classify_engine_specific(sql: &str, database_type: DatabaseType) -> Option<SqlRequirement> {
    let active = Target::Database { name: None, within: false };
    let mut requirement = SqlRequirement::empty(Analysis::Engine);
    if database_type == DatabaseType::Salesforce {
        let operations = match classify_salesforce_statement_risk(sql) {
            SalesforceStatementRisk::Read => Operations::SELECT,
            SalesforceStatementRisk::ScopedWrite => Operations::INSERT | Operations::UPDATE | Operations::DELETE,
            SalesforceStatementRisk::OpaqueWrite => Operations::UNCLASSIFIED,
        };
        requirement.add(active, operations);
        return Some(requirement);
    }
    if let Some(risk) = classify_search_engine_query_risk(sql, database_type) {
        match risk {
            SearchEngineQueryRisk::ReadOnly => requirement.add(active, Operations::SELECT),
            SearchEngineQueryRisk::Write => {
                requirement.add(active, Operations::INSERT | Operations::UPDATE | Operations::DELETE)
            }
            SearchEngineQueryRisk::Dangerous => requirement.add(Target::Connection, Operations::UNCLASSIFIED),
        }
        return Some(requirement);
    }
    if matches!(database_type, DatabaseType::Neo4j | DatabaseType::VictoriaMetrics | DatabaseType::DynamoDb) {
        if is_write_sql_for_database(sql, database_type) {
            requirement.add(Target::Connection, Operations::UNCLASSIFIED);
        } else {
            requirement.add(active, Operations::SELECT);
        }
        return Some(requirement);
    }
    None
}

fn classify_sql_text(sql: &str, database_type: DatabaseType) -> SqlRequirement {
    let dialect_name = format!("{database_type:?}");
    let dialect = resolve_dialect(normalize_dialect(&dialect_name));
    match Parser::parse_sql(dialect.as_ref(), sql) {
        Ok(statements) => {
            let mut classifier = Classifier::new(database_type);
            classifier.lock_everything = sql_contains_locking_clause(sql, dialect.as_ref());
            for statement in &statements {
                classifier.statement(statement);
            }
            let mut requirement = classifier.out;
            if statements.iter().any(|statement| reads_where_existing_checks_see_a_write(statement, database_type)) {
                requirement.add(Target::Connection, Operations::UNCLASSIFIED);
            }
            requirement
        }
        Err(_) => classify_lexically(sql, database_type),
    }
}

struct Write {
    name: ObjectName,
    kind: ObjectKind,
    operations: Operations,
    visited: bool,
}

impl Write {
    fn visited(name: &ObjectName, operations: Operations) -> Self {
        Self { name: name.clone(), kind: ObjectKind::Relation, operations, visited: true }
    }

    fn named(name: &ObjectName, kind: ObjectKind, operations: Operations) -> Self {
        Self { name: name.clone(), kind, operations, visited: false }
    }
}

#[derive(Default)]
struct Scan {
    relations: Vec<ObjectName>,
    ctes: HashSet<String>,
    table_functions: Vec<ObjectName>,
    functions: Vec<String>,
    locks: bool,
}

impl Visitor for Scan {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.ctes.insert(cte.alias.name.value.to_lowercase());
            }
        }
        if !query.locks.is_empty() {
            self.locks = true;
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<()> {
        self.relations.push(relation.clone());
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<()> {
        if let TableFactor::Table { name, args: Some(_), .. } = table_factor {
            self.table_functions.push(name.clone());
            self.functions.push(qualified_name(name));
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::Function(function) = expr {
            self.functions.push(qualified_name(&function.name));
        }
        ControlFlow::Continue(())
    }
}

fn name_parts(name: &ObjectName) -> Option<Vec<String>> {
    name.0
        .iter()
        .map(|part| match part {
            ObjectNamePart::Identifier(ident) => Some(ident.value.clone()),
            ObjectNamePart::Function(_) => None,
        })
        .collect()
}

fn qualified_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|part| match part {
            ObjectNamePart::Identifier(ident) => ident.value.to_lowercase(),
            ObjectNamePart::Function(function) => function.name.value.to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn same_object(left: &ObjectName, right: &ObjectName) -> bool {
    qualified_name(left) == qualified_name(right)
}

fn remove_one(list: &mut Vec<ObjectName>, name: &ObjectName) -> bool {
    match list.iter().position(|candidate| same_object(candidate, name)) {
        Some(index) => {
            list.remove(index);
            true
        }
        None => false,
    }
}

const SEQUENCE_AND_LOCK_FUNCTIONS: &[&str] = &[
    "nextval",
    "setval",
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_unlock",
    "pg_advisory_unlock_all",
    "pg_advisory_unlock_shared",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
    "get_lock",
    "release_lock",
    "release_all_locks",
];

const LARGE_OBJECT_INSERT_FUNCTIONS: &[&str] = &["lo_create", "lo_creat", "lo_from_bytea", "lo_put", "lowrite"];

const LARGE_OBJECT_DELETE_FUNCTIONS: &[&str] = &["lo_unlink"];

const SYSTEM_FUNCTIONS: &[&str] = &[
    "lo_import",
    "lo_export",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_stat_file",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "sys_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_switch_wal",
    "pg_create_restore_point",
    "set_config",
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "dblink_send_query",
    "query_to_xml",
    "query_to_xml_and_xmlschema",
    "query_to_xmlschema",
    "cursor_to_xml",
    "table_to_xml",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "database_to_xml",
    "load_file",
    "sys_exec",
    "sys_eval",
    "openrowset",
    "opendatasource",
    "openquery",
    "xp_cmdshell",
];

fn short_name(qualified: &str) -> &str {
    qualified.rsplit('.').next().unwrap_or(qualified)
}

struct Classifier {
    database_type: DatabaseType,
    out: SqlRequirement,
    current_database: Option<String>,
    schema: SchemaHint,
    lock_everything: bool,
}

impl Classifier {
    fn new(database_type: DatabaseType) -> Self {
        Self {
            database_type,
            out: SqlRequirement::empty(Analysis::Ast),
            current_database: None,
            schema: SchemaHint::Default,
            lock_everything: false,
        }
    }

    fn active(&self, within: bool) -> Target {
        Target::Database { name: self.current_database.clone(), within }
    }

    fn unclassified(&mut self) {
        self.out.add(Target::Connection, Operations::UNCLASSIFIED);
    }

    fn object(&mut self, name: &ObjectName, kind: ObjectKind) -> Target {
        let Some(parts) = name_parts(name) else {
            self.unclassified();
            return self.active(false);
        };
        if uses_database_links(self.database_type) && parts.iter().any(|part| part.contains('@')) {
            self.unclassified();
        }
        let limit = match kind {
            ObjectKind::Relation => 3,
            ObjectKind::Container => 2,
        };
        if parts.len() > limit {
            self.unclassified();
        }
        Target::Object { database: self.current_database.clone(), schema: self.schema.clone(), parts, kind }
    }

    fn container_of(&mut self, name: &ObjectName) -> Target {
        let mut qualifier = name.clone();
        qualifier.0.pop();
        self.object(&qualifier, ObjectKind::Container)
    }

    fn add_object(&mut self, name: &ObjectName, kind: ObjectKind, operations: Operations) {
        let target = self.object(name, kind);
        self.out.add(target, operations);
    }

    fn add_in_container(&mut self, name: &ObjectName, operations: Operations) {
        let target = self.container_of(name);
        self.out.add(target, operations);
    }

    fn statement(&mut self, statement: &Statement) {
        match statement {
            Statement::Explain { statement: inner, .. } => {
                self.statement(inner);
                return;
            }
            Statement::Prepare { .. } => return,
            _ => {}
        }

        let mut scan = Scan::default();
        let _ = statement.visit(&mut scan);
        let mut writes: Vec<Write> = Vec::new();
        let mut read_operations = Operations::SELECT;
        let mut needs_context_read = false;

        match statement {
            Statement::Query(query) => {
                self.query_writes(query, &mut writes);
                needs_context_read = true;
            }
            Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_) | Statement::Merge(_) => {
                self.dml_writes(statement, &mut writes);
            }
            Statement::Truncate(truncate) => {
                for target in &truncate.table_names {
                    writes.push(Write::visited(&target.name, Operations::TRUNCATE));
                }
            }
            Statement::CreateTable(create) => {
                let mut operations = Operations::CREATE;
                if create.query.is_some() {
                    operations |= Operations::INSERT;
                }
                if create.or_replace {
                    operations |= Operations::DROP;
                }
                writes.push(Write::visited(&create.name, operations));
                if let Some(query) = &create.query {
                    self.query_writes(query, &mut writes);
                }
                if let Some(like) = &create.like {
                    let (CreateTableLikeKind::Parenthesized(like) | CreateTableLikeKind::Plain(like)) = like;
                    self.add_object(&like.name, ObjectKind::Relation, Operations::SELECT);
                }
                if let Some(clone) = &create.clone {
                    self.add_object(clone, ObjectKind::Relation, Operations::SELECT);
                }
                if let Some(parent) = &create.partition_of {
                    writes.push(Write::visited(parent, Operations::ALTER));
                }
                for parent in create.inherits.iter().flatten() {
                    writes.push(Write::named(parent, ObjectKind::Relation, Operations::ALTER));
                }
            }
            Statement::CreateView(view) => {
                let mut operations = Operations::CREATE;
                if view.or_replace || view.or_alter {
                    operations |= Operations::ALTER;
                }
                writes.push(Write::named(&view.name, ObjectKind::Relation, operations));
                if let Some(to) = &view.to {
                    writes.push(Write::named(to, ObjectKind::Relation, Operations::INSERT));
                }
                self.query_writes(&view.query, &mut writes);
            }
            Statement::CreateIndex(index) => writes.push(Write::visited(&index.table_name, Operations::CREATE)),
            Statement::CreateVirtualTable { name, .. } => writes.push(Write::visited(name, Operations::CREATE)),
            Statement::CreateSchema { schema_name, .. } => match schema_name {
                SchemaName::Simple(name) | SchemaName::NamedAuthorization(name, _) => {
                    self.add_object(name, ObjectKind::Container, Operations::CREATE)
                }
                SchemaName::UnnamedAuthorization(_) => self.out.add(self.active(false), Operations::CREATE),
            },
            Statement::CreateDatabase { db_name, .. } => {
                let name = name_parts(db_name).and_then(|parts| parts.last().cloned());
                match name {
                    Some(name) => {
                        self.out.add(Target::Database { name: Some(name), within: false }, Operations::CREATE)
                    }
                    None => self.unclassified(),
                }
            }
            Statement::CreateSequence { name, .. }
            | Statement::CreateType { name, .. }
            | Statement::CreateProcedure { name, .. }
            | Statement::CreateMacro { name, .. } => self.add_in_container(name, Operations::CREATE),
            Statement::CreateFunction(function) => self.add_in_container(&function.name, Operations::CREATE),
            Statement::CreateDomain(domain) => self.add_in_container(&domain.name, Operations::CREATE),
            Statement::CreateTrigger(trigger) => {
                writes.push(Write::named(&trigger.table_name, ObjectKind::Relation, Operations::CREATE))
            }
            Statement::CreateRole(_)
            | Statement::CreateUser(_)
            | Statement::AlterRole { .. }
            | Statement::AlterUser(_)
            | Statement::Grant(_)
            | Statement::Revoke(_)
            | Statement::Deny(_) => self.out.add(Target::Connection, Operations::GRANT),
            Statement::CreatePolicy(policy) => writes.push(Write::visited(&policy.table_name, Operations::GRANT)),
            Statement::AlterPolicy(policy) => writes.push(Write::visited(&policy.table_name, Operations::GRANT)),
            Statement::DropPolicy(policy) => writes.push(Write::visited(&policy.table_name, Operations::GRANT)),
            Statement::AlterTable(alter) => writes.push(Write::visited(&alter.name, Operations::ALTER)),
            Statement::AlterView { name, query, .. } => {
                writes.push(Write::visited(name, Operations::ALTER));
                self.query_writes(query, &mut writes);
            }
            Statement::AlterSchema(alter) => self.add_object(&alter.name, ObjectKind::Container, Operations::ALTER),
            Statement::AlterIndex { name, .. } => self.add_in_container(name, Operations::ALTER),
            Statement::AlterType(alter) => self.add_in_container(&alter.name, Operations::ALTER),
            Statement::AlterFunction(alter) => self.add_in_container(&alter.function.name, Operations::ALTER),
            Statement::Drop { object_type, names, table, .. } => self.drop(*object_type, names, table.as_ref()),
            Statement::DropFunction(drop) => {
                for function in &drop.func_desc {
                    self.add_in_container(&function.name, Operations::DROP);
                }
            }
            Statement::DropProcedure { proc_desc, .. } => {
                for procedure in proc_desc {
                    self.add_in_container(&procedure.name, Operations::DROP);
                }
            }
            Statement::DropDomain(drop) => self.add_in_container(&drop.name, Operations::DROP),
            Statement::DropTrigger(drop) => match &drop.table_name {
                Some(table) => self.add_object(table, ObjectKind::Relation, Operations::DROP),
                None => self.add_in_container(&drop.trigger_name, Operations::DROP),
            },
            Statement::RenameTable(renames) => {
                for rename in renames {
                    self.add_object(&rename.old_name, ObjectKind::Relation, Operations::ALTER);
                    self.add_object(&rename.new_name, ObjectKind::Relation, Operations::CREATE);
                }
            }
            Statement::Comment { object_type, object_name, .. } => self.comment(*object_type, object_name),
            Statement::Call(function) => self.add_in_container(&function.name, Operations::EXECUTE),
            Statement::Execute { name, immediate, .. } => match name {
                Some(name) if !*immediate && !is_postgresql_like(self.database_type) => {
                    self.add_in_container(name, Operations::EXECUTE)
                }
                _ => self.unclassified(),
            },
            Statement::Copy { source, to, target, .. } => match target {
                CopyTarget::File { .. } | CopyTarget::Program { .. } => self.unclassified(),
                CopyTarget::Stdin | CopyTarget::Stdout => match source {
                    CopySource::Table { table_name, .. } => {
                        let operations = if *to { Operations::SELECT | Operations::EXPORT } else { Operations::INSERT };
                        self.add_object(table_name, ObjectKind::Relation, operations);
                    }
                    CopySource::Query(query) => {
                        self.query_writes(query, &mut writes);
                        read_operations |= Operations::EXPORT;
                    }
                },
            },
            Statement::Lock(_) => read_operations |= Operations::UPDATE,
            Statement::LockTables { tables } => {
                for table in tables {
                    let name = ObjectName::from(vec![table.table.clone()]);
                    self.add_object(&name, ObjectKind::Relation, Operations::SELECT | Operations::UPDATE);
                }
            }
            Statement::UnlockTables => {}
            Statement::ExplainTable { .. } => {}
            Statement::ShowCreate { obj_name, .. } => {
                self.add_object(obj_name, ObjectKind::Relation, Operations::SELECT)
            }
            Statement::ShowTables { .. }
            | Statement::ShowColumns { .. }
            | Statement::ShowCatalogs { .. }
            | Statement::ShowDatabases { .. }
            | Statement::ShowSchemas { .. }
            | Statement::ShowViews { .. }
            | Statement::ShowFunctions { .. }
            | Statement::ShowVariable { .. }
            | Statement::ShowVariables { .. }
            | Statement::ShowStatus { .. }
            | Statement::ShowCharset(_)
            | Statement::ShowObjects(_)
            | Statement::ShowCollation { .. } => needs_context_read = true,
            Statement::Use(target) => self.use_statement(target),
            Statement::Set(set) => self.set(set),
            Statement::StartTransaction { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::Savepoint { .. }
            | Statement::ReleaseSavepoint { .. } => self.out.transaction_control = true,
            Statement::Fetch { .. } => needs_context_read = true,
            Statement::Declare { .. }
            | Statement::Close { .. }
            | Statement::Deallocate { .. }
            | Statement::Discard { .. }
            | Statement::Reset(_)
            | Statement::Print(_) => {}
            _ => self.unclassified(),
        }

        if scan.locks || self.lock_everything {
            read_operations |= Operations::UPDATE;
        }
        self.finish(scan, writes, read_operations, needs_context_read);
    }

    fn finish(&mut self, mut scan: Scan, writes: Vec<Write>, read_operations: Operations, needs_context_read: bool) {
        for name in std::mem::take(&mut scan.table_functions) {
            remove_one(&mut scan.relations, &name);
        }
        let ctes = std::mem::take(&mut scan.ctes);
        scan.relations.retain(|relation| !(relation.0.len() == 1 && ctes.contains(&qualified_name(relation))));
        for write in &writes {
            if write.visited {
                remove_one(&mut scan.relations, &write.name);
            }
        }
        let had_objects = !scan.relations.is_empty() || !writes.is_empty();
        for relation in &scan.relations {
            self.add_object(relation, ObjectKind::Relation, read_operations);
        }
        for write in &writes {
            self.add_object(&write.name, write.kind, write.operations);
        }
        if needs_context_read && !had_objects {
            self.out.add(self.active(true), read_operations);
        }
        self.functions(&scan.functions);
    }

    fn functions(&mut self, functions: &[String]) {
        for function in functions {
            let short = short_name(function);
            let operations = if SYSTEM_FUNCTIONS.contains(&short) {
                Some((Target::Connection, Operations::UNCLASSIFIED))
            } else if SEQUENCE_AND_LOCK_FUNCTIONS.contains(&short) {
                Some((self.active(true), Operations::UPDATE))
            } else if LARGE_OBJECT_INSERT_FUNCTIONS.contains(&short) {
                Some((self.active(true), Operations::INSERT))
            } else if LARGE_OBJECT_DELETE_FUNCTIONS.contains(&short) {
                Some((self.active(true), Operations::DELETE))
            } else {
                None
            };
            if let Some((target, operations)) = operations {
                self.out.add(target, operations);
            }
            if !self.out.functions.contains(function) {
                self.out.functions.push(function.clone());
            }
        }
    }

    fn query_writes(&mut self, query: &Query, writes: &mut Vec<Write>) {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.query_writes(&cte.query, writes);
            }
        }
        self.set_expr_writes(&query.body, writes);
    }

    fn set_expr_writes(&mut self, body: &SetExpr, writes: &mut Vec<Write>) {
        match body {
            SetExpr::Select(select) => self.select_into(select, writes),
            SetExpr::Query(query) => self.query_writes(query, writes),
            SetExpr::SetOperation { left, right, .. } => {
                self.set_expr_writes(left, writes);
                self.set_expr_writes(right, writes);
            }
            SetExpr::Insert(statement)
            | SetExpr::Update(statement)
            | SetExpr::Delete(statement)
            | SetExpr::Merge(statement) => self.dml_writes(statement, writes),
            SetExpr::Values(_) | SetExpr::Table(_) => {}
        }
    }

    fn select_into(&mut self, select: &Select, writes: &mut Vec<Write>) {
        if let Some(into) = &select.into {
            if supports_select_into_table_creation(self.database_type) {
                writes.push(Write::named(&into.name, ObjectKind::Relation, Operations::CREATE | Operations::INSERT));
            }
        }
    }

    fn dml_writes(&mut self, statement: &Statement, writes: &mut Vec<Write>) {
        match statement {
            Statement::Insert(insert) => self.insert_writes(insert, writes),
            Statement::Update(update) => {
                let returning = update.returning.is_some() || update.output.is_some();
                let operations = Operations::UPDATE | if returning { Operations::SELECT } else { Operations::empty() };
                let tables = table_names(std::slice::from_ref(&update.table));
                if tables.len() != 1 + update.table.joins.len() {
                    self.unclassified();
                }
                for name in tables {
                    writes.push(Write::visited(&name, operations));
                }
            }
            Statement::Delete(delete) => {
                let returning = delete.returning.is_some() || delete.output.is_some();
                let operations = Operations::DELETE | if returning { Operations::SELECT } else { Operations::empty() };
                let from = match &delete.from {
                    FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from) => from,
                };
                let names = table_names(from);
                if names.is_empty() {
                    self.unclassified();
                }
                for name in names {
                    writes.push(Write::visited(&name, operations));
                }
            }
            Statement::Merge(merge) => {
                let TableFactor::Table { name, .. } = &merge.table else {
                    self.unclassified();
                    return;
                };
                let mut operations = if merge.output.is_some() { Operations::SELECT } else { Operations::empty() };
                for clause in &merge.clauses {
                    operations |= match clause.action {
                        MergeAction::Insert(_) => Operations::INSERT,
                        MergeAction::Update(_) => Operations::UPDATE,
                        MergeAction::Delete { .. } => Operations::DELETE,
                    };
                }
                if operations.is_empty() {
                    operations = Operations::INSERT | Operations::UPDATE | Operations::DELETE;
                }
                writes.push(Write::visited(name, operations));
            }
            _ => self.unclassified(),
        }
    }

    fn insert_writes(&mut self, insert: &Insert, writes: &mut Vec<Write>) {
        let mut operations = Operations::INSERT;
        match &insert.on {
            Some(OnInsert::DuplicateKeyUpdate(_)) => operations |= Operations::UPDATE,
            Some(OnInsert::OnConflict(conflict)) => {
                if let OnConflictAction::DoUpdate(_) = conflict.action {
                    operations |= Operations::UPDATE;
                }
            }
            Some(_) => operations |= Operations::UPDATE,
            None => {}
        }
        if insert.replace_into || insert.overwrite || matches!(insert.or, Some(SqliteOnConflict::Replace)) {
            operations |= Operations::DELETE;
        }
        if insert.returning.is_some() || insert.output.is_some() {
            operations |= Operations::SELECT;
        }
        match &insert.table {
            TableObject::TableName(name) => writes.push(Write::visited(name, operations)),
            TableObject::TableFunction(_) | TableObject::TableQuery(_) => self.unclassified(),
        }
        if let Some(source) = &insert.source {
            self.query_writes(source, writes);
        }
    }

    fn drop(&mut self, object_type: ObjectType, names: &[ObjectName], table: Option<&ObjectName>) {
        if let Some(table) = table {
            self.add_object(table, ObjectKind::Relation, Operations::DROP);
            return;
        }
        for name in names {
            match object_type {
                ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => {
                    self.add_object(name, ObjectKind::Relation, Operations::DROP)
                }
                ObjectType::Schema => self.add_object(name, ObjectKind::Container, Operations::DROP),
                ObjectType::Database => match name_parts(name).and_then(|parts| parts.last().cloned()) {
                    Some(database) => {
                        self.out.add(Target::Database { name: Some(database), within: false }, Operations::DROP)
                    }
                    None => self.unclassified(),
                },
                ObjectType::Role | ObjectType::User => self.out.add(Target::Connection, Operations::GRANT),
                _ => self.add_in_container(name, Operations::DROP),
            }
        }
    }

    fn comment(&mut self, object_type: CommentObject, name: &ObjectName) {
        match object_type {
            CommentObject::Table | CommentObject::View | CommentObject::MaterializedView => {
                self.add_object(name, ObjectKind::Relation, Operations::ALTER)
            }
            CommentObject::Column => {
                let mut table = name.clone();
                table.0.pop();
                self.add_object(&table, ObjectKind::Relation, Operations::ALTER);
            }
            CommentObject::Schema => self.add_object(name, ObjectKind::Container, Operations::ALTER),
            CommentObject::Database => match name_parts(name).and_then(|parts| parts.last().cloned()) {
                Some(database) => {
                    self.out.add(Target::Database { name: Some(database), within: false }, Operations::ALTER)
                }
                None => self.unclassified(),
            },
            CommentObject::Role | CommentObject::User => self.out.add(Target::Connection, Operations::GRANT),
            CommentObject::Extension | CommentObject::Collation => self.unclassified(),
            _ => self.add_in_container(name, Operations::ALTER),
        }
    }

    fn use_statement(&mut self, target: &Use) {
        match target {
            Use::Database(name) | Use::Catalog(name) | Use::Object(name) => match name_parts(name) {
                Some(parts) if parts.len() == 1 => {
                    self.current_database = parts.into_iter().next();
                    self.schema = SchemaHint::Default;
                }
                Some(parts) if parts.len() == 2 => {
                    let mut parts = parts.into_iter();
                    self.current_database = parts.next();
                    self.schema = parts.next().map_or(SchemaHint::Unknown, SchemaHint::Named);
                }
                _ => self.unclassified(),
            },
            Use::Schema(name) => match name_parts(name) {
                Some(parts) if parts.len() == 1 => self.schema = SchemaHint::Named(parts[0].clone()),
                Some(parts) if parts.len() == 2 => {
                    self.current_database = Some(parts[0].clone());
                    self.schema = SchemaHint::Named(parts[1].clone());
                }
                _ => self.unclassified(),
            },
            _ => self.unclassified(),
        }
    }

    fn set(&mut self, set: &Set) {
        match set {
            Set::SingleAssignment { scope, variable, .. } => self.assignment(scope.as_ref(), variable),
            Set::ParenthesizedAssignments { variables, .. } => {
                for variable in variables {
                    self.assignment(None, variable);
                }
            }
            Set::MultipleAssignments { assignments } => {
                for assignment in assignments {
                    self.assignment(assignment.scope.as_ref(), &assignment.name);
                }
            }
            Set::SetTimeZone { .. } | Set::SetNames { .. } | Set::SetNamesDefault { .. } | Set::SetSessionParam(_) => {}
            Set::SetTransaction { .. } => self.out.transaction_control = true,
            _ => self.unclassified(),
        }
    }

    fn assignment(&mut self, scope: Option<&ContextModifier>, variable: &ObjectName) {
        if matches!(scope, Some(ContextModifier::Global)) {
            self.unclassified();
            return;
        }
        let name = qualified_name(variable);
        if name.starts_with("@@global") || name.starts_with("@@persist") || name.starts_with("global.") {
            self.unclassified();
            return;
        }
        match short_name(&name) {
            "search_path" | "schema" | "current_schema" => self.schema = SchemaHint::Unknown,
            "role" | "session_authorization" | "session authorization" => self.unclassified(),
            _ => {}
        }
    }
}

fn table_names(tables: &[TableWithJoins]) -> Vec<ObjectName> {
    let mut names = Vec::new();
    for table in tables {
        for factor in std::iter::once(&table.relation).chain(table.joins.iter().map(|join| &join.relation)) {
            if let TableFactor::Table { name, args: None, .. } = factor {
                names.push(name.clone());
            }
        }
    }
    names
}

fn is_postgresql_like(database_type: DatabaseType) -> bool {
    normalize_dialect(&format!("{database_type:?}")) == "postgres"
}

fn uses_database_links(database_type: DatabaseType) -> bool {
    matches!(
        database_type,
        DatabaseType::Oracle
            | DatabaseType::Dameng
            | DatabaseType::Yashandb
            | DatabaseType::Oscar
            | DatabaseType::OceanbaseOracle
            | DatabaseType::Xugu
    )
}

const LEXICAL_READ_KEYWORDS: &[&str] = &["SELECT", "WITH", "SHOW", "DESC", "DESCRIBE", "VALUES", "TABLE"];

fn classify_lexically(sql: &str, database_type: DatabaseType) -> SqlRequirement {
    let mut requirement = SqlRequirement::empty(Analysis::Lexical);
    let statements = crate::sql::split_sql_statements_for_database(sql, database_type);
    for statement in &statements {
        classify_lexical_statement(statement, database_type, &mut requirement);
    }
    requirement
}

fn classify_lexical_statement(statement: &str, database_type: DatabaseType, requirement: &mut SqlRequirement) {
    let cleaned = strip_sql_comments_and_literals(statement);
    let trimmed = cleaned.trim_matches(|ch: char| ch.is_whitespace() || ch == ';');
    if trimmed.is_empty() {
        return;
    }
    if !trimmed.starts_with(|ch: char| ch.is_alphabetic() || ch == '_') {
        requirement.add(Target::Connection, Operations::UNCLASSIFIED);
        return;
    }
    let words: Vec<String> = cleaned
        .split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '$' || ch == '@'))
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    let Some(first) = words.first().map(String::as_str) else {
        return;
    };
    let has = |word: &str| words.iter().any(|candidate| candidate == word);
    let active = Target::Database { name: None, within: false };
    let unclassified = (Target::Connection, Operations::UNCLASSIFIED);
    if uses_database_links(database_type) && cleaned.contains('@') {
        requirement.add(unclassified.0, unclassified.1);
        return;
    }
    let (target, operations) = match first {
        keyword if LEXICAL_READ_KEYWORDS.contains(&keyword) => {
            let dialect = resolve_dialect(normalize_dialect(&format!("{database_type:?}")));
            if is_write_sql_for_database(statement, database_type) {
                unclassified
            } else if sql_contains_locking_clause(statement, dialect.as_ref()) {
                (active, Operations::SELECT | Operations::UPDATE)
            } else {
                (active, Operations::SELECT)
            }
        }
        "EXPLAIN" if !has("ANALYZE") => (active, Operations::SELECT),
        "INSERT" => {
            let mut operations = Operations::INSERT | Operations::SELECT;
            if has("UPDATE") || has("CONFLICT") || has("DUPLICATE") {
                operations |= Operations::UPDATE;
            }
            (active, operations)
        }
        "UPDATE" => (active, Operations::UPDATE | Operations::SELECT),
        "DELETE" => (active, Operations::DELETE | Operations::SELECT),
        "TRUNCATE" => (active, Operations::TRUNCATE),
        "CREATE" if has("SELECT") => (active, Operations::CREATE | Operations::INSERT | Operations::SELECT),
        "CREATE" if has("USER") || has("ROLE") => (Target::Connection, Operations::GRANT),
        "CREATE" => (active, Operations::CREATE),
        "ALTER" if has("USER") || has("ROLE") || has("SYSTEM") || has("SESSION") => unclassified,
        "ALTER" => (active, Operations::ALTER),
        "DROP" if has("USER") || has("ROLE") => (Target::Connection, Operations::GRANT),
        "DROP" => (active, Operations::DROP),
        "GRANT" | "REVOKE" => (Target::Connection, Operations::GRANT),
        "CALL" | "EXEC" if words.len() > 1 => (active, Operations::EXECUTE),
        "EXECUTE" if !has("IMMEDIATE") && words.len() > 1 => (active, Operations::EXECUTE),
        "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" => {
            requirement.transaction_control = true;
            return;
        }
        "START" if words.get(1).map(String::as_str) == Some("TRANSACTION") => {
            requirement.transaction_control = true;
            return;
        }
        "BEGIN"
            if words.len() == 1
                || (words.len() == 2 && matches!(words[1].as_str(), "TRANSACTION" | "TRAN" | "WORK")) =>
        {
            requirement.transaction_control = true;
            return;
        }
        _ => unclassified,
    };
    if !operations.has_write() && existing_checks_report_write(statement, database_type) {
        requirement.add(Target::Connection, Operations::UNCLASSIFIED);
    }
    requirement.add(target, operations);
}
