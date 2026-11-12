use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub connection_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
}

impl Resource {
    pub fn connection(connection_id: impl Into<String>) -> Self {
        Self { connection_id: connection_id.into(), database: None, schema: None, table: None }
    }

    pub fn with_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }

    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table = Some(table.into());
        self
    }

    pub fn connection_level(&self) -> Self {
        Self::connection(self.connection_id.clone())
    }

    pub fn covers(&self, other: &Resource) -> bool {
        self.connection_id == other.connection_id
            && level_covers(&self.database, &other.database)
            && level_covers(&self.schema, &other.schema)
            && level_covers(&self.table, &other.table)
    }

    pub fn overlaps(&self, other: &Resource) -> bool {
        self.connection_id == other.connection_id
            && level_overlaps(&self.database, &other.database)
            && level_overlaps(&self.schema, &other.schema)
            && level_overlaps(&self.table, &other.table)
    }
}

fn same_name(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

fn level_covers(pattern: &Option<String>, target: &Option<String>) -> bool {
    match (pattern, target) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(pattern), Some(target)) => same_name(pattern, target),
    }
}

fn level_overlaps(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => same_name(left, right),
        _ => true,
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.connection_id)?;
        for level in [&self.database, &self.schema, &self.table] {
            match level {
                Some(name) => write!(f, "/{name}")?,
                None => f.write_str("/*")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Resource;

    #[test]
    fn coarser_pattern_covers_finer_resource() {
        let connection = Resource::connection("c");
        let database = connection.clone().with_database("app");
        let table = database.clone().with_schema("public").with_table("users");
        assert!(connection.covers(&table));
        assert!(database.covers(&table));
        assert!(table.covers(&table));
        assert!(!table.covers(&database));
        assert!(!database.covers(&connection));
    }

    #[test]
    fn names_match_case_insensitively_including_unicode() {
        let pattern = Resource::connection("c").with_database("Ventas").with_schema("ÑANDÚ");
        let target = Resource::connection("c").with_database("ventas").with_schema("ñandú").with_table("t");
        assert!(pattern.covers(&target));
    }

    #[test]
    fn different_connections_never_match() {
        assert!(!Resource::connection("a").covers(&Resource::connection("b")));
        assert!(!Resource::connection("a").overlaps(&Resource::connection("b")));
    }

    #[test]
    fn overlap_is_symmetric_between_ancestor_and_descendant() {
        let database = Resource::connection("c").with_database("app");
        let table = database.clone().with_schema("s").with_table("t");
        let sibling = Resource::connection("c").with_database("other");
        assert!(database.overlaps(&table) && table.overlaps(&database));
        assert!(!sibling.overlaps(&table));
    }

    #[test]
    fn display_marks_unspecified_levels() {
        let resource = Resource::connection("c").with_database("app");
        assert_eq!(resource.to_string(), "c/app/*/*");
    }
}
