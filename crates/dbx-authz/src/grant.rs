use serde::{Deserialize, Serialize};

use crate::{Operations, Resource};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Subject {
    User(String),
    Group(String),
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Scope {
    All,
    ConnectionGroup(String),
    Resource(Resource),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub subject: Subject,
    pub scope: Scope,
    pub effect: Effect,
    pub operations: Operations,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Grant {
    pub fn is_active(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    pub(crate) fn pattern_for(&self, connection_id: &str, group_path: &[String]) -> Option<Resource> {
        match &self.scope {
            Scope::All => Some(Resource::connection(connection_id)),
            Scope::ConnectionGroup(group) => {
                group_path.iter().any(|ancestor| ancestor == group).then(|| Resource::connection(connection_id))
            }
            Scope::Resource(resource) => (resource.connection_id == connection_id).then(|| resource.clone()),
        }
    }
}
