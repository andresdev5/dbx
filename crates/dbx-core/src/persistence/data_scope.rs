use std::future::Future;

pub const OWNER_COLUMN: &str = "owner_user_id";
pub const USER_DATA_TABLES: &[&str] =
    &["history", "saved_sql_folders", "saved_sql_files", "ai_conversations", "tab_runtime_cache"];
pub const USER_APP_STATE_KEYS: &[&str] = &["saved_sql_editor_positions"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataScope {
    Shared,
    User { user_id: String, sees_unowned: bool },
    Nobody,
}

tokio::task_local! {
    static DATA_SCOPE: DataScope;
}

pub fn current_task_scope() -> Option<DataScope> {
    DATA_SCOPE.try_with(Clone::clone).ok()
}

pub async fn with_data_scope<F>(scope: DataScope, future: F) -> F::Output
where
    F: Future,
{
    DATA_SCOPE.scope(scope, future).await
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

impl DataScope {
    pub fn owner(&self) -> Option<&str> {
        match self {
            Self::User { user_id, .. } => Some(user_id),
            Self::Shared | Self::Nobody => None,
        }
    }

    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }

    pub fn filter(&self, column: &str) -> String {
        match self {
            Self::Shared => "1".to_string(),
            Self::Nobody => "0".to_string(),
            Self::User { user_id, sees_unowned: false } => format!("{column} = {}", sql_literal(user_id)),
            Self::User { user_id, sees_unowned: true } => {
                format!("({column} = {} OR {column} IS NULL)", sql_literal(user_id))
            }
        }
    }

    pub fn owner_filter(&self) -> String {
        self.filter(OWNER_COLUMN)
    }

    pub fn app_state_key(&self, key: &str) -> Option<String> {
        match self {
            Self::Shared => Some(key.to_string()),
            Self::User { user_id, .. } => Some(format!("{key}:user:{user_id}")),
            Self::Nobody => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scopes_are_task_local_and_absent_by_default() {
        assert_eq!(current_task_scope(), None);
        let scope = DataScope::User { user_id: "u1".into(), sees_unowned: false };
        assert_eq!(with_data_scope(scope.clone(), async { current_task_scope() }).await, Some(scope));
        assert_eq!(current_task_scope(), None);
    }

    #[test]
    fn filters_quote_user_ids_and_fail_closed() {
        assert_eq!(DataScope::Shared.owner_filter(), "1");
        assert_eq!(DataScope::Nobody.owner_filter(), "0");
        assert_eq!(
            DataScope::User { user_id: "a'b".into(), sees_unowned: false }.owner_filter(),
            "owner_user_id = 'a''b'"
        );
        assert_eq!(
            DataScope::User { user_id: "u1".into(), sees_unowned: true }.filter("f.owner_user_id"),
            "(f.owner_user_id = 'u1' OR f.owner_user_id IS NULL)"
        );
        assert_eq!(DataScope::Nobody.app_state_key("k"), None);
        assert_eq!(
            DataScope::User { user_id: "u1".into(), sees_unowned: true }.app_state_key("k").as_deref(),
            Some("k:user:u1")
        );
    }
}
