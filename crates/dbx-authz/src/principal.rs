use serde::{Deserialize, Serialize};

use crate::{Operations, Subject};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRole {
    Admin,
    User,
}

impl PlatformRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    User {
        user_id: String,
        #[serde(default)]
        groups: Vec<String>,
        role: PlatformRole,
    },
    System {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id: Option<String>,
    },
    Local,
}

impl Principal {
    pub fn is_subject(&self, subject: &Subject) -> bool {
        match (self, subject) {
            (Self::User { user_id, .. }, Subject::User(id)) => user_id == id,
            (Self::User { groups, .. }, Subject::Group(id)) => groups.iter().any(|group| group == id),
            (Self::System { .. }, Subject::System) => true,
            _ => false,
        }
    }

    pub fn implicit_operations(&self) -> Operations {
        match self {
            Self::User { role: PlatformRole::Admin, .. } | Self::Local => Operations::all(),
            Self::User { role: PlatformRole::User, .. } | Self::System { .. } => Operations::empty(),
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Self::User { role: PlatformRole::Admin, .. } | Self::Local)
    }
}
