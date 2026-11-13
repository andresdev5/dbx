use super::*;
use crate::persistence::data_scope::{with_data_scope, DataScope};
use crate::persistence::history::{HistoryEntry, HistorySearchRequest};
use crate::persistence::saved_sql::{SavedSqlFile, SavedSqlFolder, SavedSqlLibrary};

async fn storage() -> (tempfile::TempDir, Storage) {
    let directory = tempfile::tempdir().unwrap();
    let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
    (directory, storage)
}

fn user(id: &str) -> DataScope {
    DataScope::User { user_id: id.into(), sees_unowned: false }
}

fn admin(id: &str) -> DataScope {
    DataScope::User { user_id: id.into(), sees_unowned: true }
}

fn entry(id: &str, executed_at: &str) -> HistoryEntry {
    serde_json::from_value(serde_json::json!({
        "id": id, "connection_id": "c1", "connection_name": "Sales", "database": "crm",
        "sql": format!("SELECT {id}"), "executed_at": executed_at, "execution_time_ms": 1,
        "success": true, "error": null
    }))
    .unwrap()
}

fn file(id: &str, default_query: bool) -> SavedSqlFile {
    serde_json::from_value(serde_json::json!({
        "id": id, "connectionId": "c1", "folderId": null, "name": id, "database": "crm",
        "schema": null, "sql": format!("-- {id}"), "openedAt": null, "isDefaultQuery": default_query,
        "createdAt": "2026-01-01", "updatedAt": "2026-01-01"
    }))
    .unwrap()
}

fn folder(id: &str) -> SavedSqlFolder {
    serde_json::from_value(serde_json::json!({
        "id": id, "connectionId": "c1", "parentFolderId": null, "name": id,
        "createdAt": "2026-01-01", "updatedAt": "2026-01-01"
    }))
    .unwrap()
}

async fn history_ids(storage: &Storage, scope: DataScope) -> Vec<String> {
    with_data_scope(scope, storage.search_history_entries(HistorySearchRequest::default()))
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.id)
        .collect()
}

#[tokio::test]
async fn desktop_storage_keeps_sharing_everything() {
    let (_directory, storage) = storage().await;
    storage.save_history_entry(&entry("h1", "2026-01-01T00:00:01")).await.unwrap();
    with_data_scope(user("ana"), storage.save_history_entry(&entry("h2", "2026-01-01T00:00:02"))).await.unwrap();
    assert_eq!(history_ids(&storage, user("bob")).await, vec!["h2", "h1"]);
}

#[tokio::test]
async fn history_is_private_to_its_owner() {
    let (_directory, storage) = storage().await;
    storage.save_history_entry(&entry("legacy", "2026-01-01T00:00:00")).await.unwrap();
    storage.enable_user_scoped_data();
    with_data_scope(user("ana"), storage.save_history_entry(&entry("a1", "2026-01-01T00:00:01"))).await.unwrap();
    with_data_scope(user("bob"), storage.save_history_entry(&entry("b1", "2026-01-01T00:00:02"))).await.unwrap();

    assert_eq!(history_ids(&storage, user("ana")).await, vec!["a1"]);
    assert_eq!(history_ids(&storage, user("bob")).await, vec!["b1"]);
    assert_eq!(history_ids(&storage, admin("root")).await, vec!["legacy"]);
    assert!(history_ids(&storage, DataScope::Nobody).await.is_empty());
    assert!(storage.search_history_entries(HistorySearchRequest::default()).await.unwrap().entries.is_empty());

    let overwrite = with_data_scope(user("bob"), storage.save_history_entry(&entry("a1", "2026-01-02"))).await;
    assert!(overwrite.is_err());
    with_data_scope(user("bob"), storage.delete_history_entry("a1")).await.unwrap();
    with_data_scope(user("bob"), storage.clear_history()).await.unwrap();
    assert_eq!(history_ids(&storage, user("ana")).await, vec!["a1"]);
    assert!(history_ids(&storage, user("bob")).await.is_empty());

    let options = with_data_scope(user("bob"), storage.load_history_connection_options()).await.unwrap();
    assert!(options.is_empty());
    let loaded = with_data_scope(user("ana"), storage.load_history_entries(10, 0, None)).await.unwrap();
    assert_eq!(loaded.len(), 1);
}

#[tokio::test]
async fn history_retention_counts_each_owner_separately() {
    let (_directory, storage) = storage().await;
    storage.enable_user_scoped_data();
    storage.save_history_retention_limit(200).await.unwrap();
    with_data_scope(user("ana"), storage.save_history_entry(&entry("a1", "2026-01-01T00:00:00"))).await.unwrap();
    with_data_scope(user("bob"), async {
        for index in 0..201 {
            let at = format!("2026-01-02T00:{:02}:{:02}", index / 60, index % 60);
            storage.save_history_entry(&entry(&format!("b{index:03}"), &at)).await.unwrap();
        }
    })
    .await;
    assert_eq!(history_ids(&storage, user("ana")).await, vec!["a1"]);
    let bob = with_data_scope(user("bob"), storage.load_history_entries(500, 0, None)).await.unwrap();
    assert_eq!(bob.len(), 200);
    assert!(bob.iter().all(|entry| entry.id != "b000"));
}

#[tokio::test]
async fn saved_sql_libraries_are_private_and_each_user_has_a_default_query() {
    let (_directory, storage) = storage().await;
    storage.enable_user_scoped_data();
    with_data_scope(user("ana"), async {
        storage.save_saved_sql_folder(&folder("fa")).await.unwrap();
        storage.save_saved_sql_file(&file("ana-default", true)).await.unwrap();
        storage.save_saved_sql_file(&file("ana-report", false)).await.unwrap();
    })
    .await;
    with_data_scope(user("bob"), storage.save_saved_sql_file(&file("bob-default", true))).await.unwrap();

    let ana = with_data_scope(user("ana"), storage.load_saved_sql_library()).await.unwrap();
    assert_eq!(ana.files.len(), 2);
    assert_eq!(ana.folders.len(), 1);
    let bob = with_data_scope(user("bob"), storage.load_saved_sql_library_summary()).await.unwrap();
    assert_eq!(bob.files.iter().map(|file| file.id.as_str()).collect::<Vec<_>>(), vec!["bob-default"]);
    assert!(bob.folders.is_empty());

    assert!(with_data_scope(user("bob"), storage.load_saved_sql_file("ana-report")).await.unwrap().is_none());
    assert!(with_data_scope(user("bob"), storage.save_saved_sql_file(&file("ana-report", false))).await.is_err());
    assert!(with_data_scope(user("bob"), storage.save_default_query_content("ana-default", "DROP", "x"))
        .await
        .is_err());
    with_data_scope(user("bob"), async {
        storage.delete_saved_sql_file("ana-report").await.unwrap();
        storage.delete_saved_sql_folder("fa").await.unwrap();
        storage.replace_saved_sql_library(&SavedSqlLibrary::default()).await.unwrap();
    })
    .await;
    let ana = with_data_scope(user("ana"), storage.load_saved_sql_library()).await.unwrap();
    assert_eq!(ana.files.len(), 2);
    assert_eq!(ana.folders.len(), 1);
    assert!(with_data_scope(user("bob"), storage.load_saved_sql_library()).await.unwrap().files.is_empty());

    with_data_scope(user("ana"), storage.save_saved_sql_editor_positions(&serde_json::json!({ "x": 1 })))
        .await
        .unwrap();
    assert!(with_data_scope(user("bob"), storage.load_saved_sql_editor_positions()).await.unwrap().is_none());
    assert_eq!(
        with_data_scope(user("ana"), storage.load_saved_sql_editor_positions()).await.unwrap(),
        Some(serde_json::json!({ "x": 1 }))
    );
}

#[tokio::test]
async fn existing_data_is_assigned_to_the_first_administrator() {
    let (_directory, storage) = storage().await;
    storage.save_history_entry(&entry("legacy", "2026-01-01T00:00:00")).await.unwrap();
    storage.save_saved_sql_file(&file("legacy-file", false)).await.unwrap();
    storage.save_saved_sql_editor_positions(&serde_json::json!({ "legacy": true })).await.unwrap();
    storage.enable_user_scoped_data();

    assert_eq!(storage.assign_unowned_user_data("root").await.unwrap(), 3);
    assert_eq!(history_ids(&storage, user("root")).await, vec!["legacy"]);
    let files = with_data_scope(user("root"), storage.load_saved_sql_library()).await.unwrap().files;
    assert_eq!(files.len(), 1);
    assert_eq!(
        with_data_scope(user("root"), storage.load_saved_sql_editor_positions()).await.unwrap(),
        Some(serde_json::json!({ "legacy": true }))
    );
    assert_eq!(storage.assign_unowned_user_data("root").await.unwrap(), 0);
}

#[tokio::test]
async fn spawned_request_tasks_keep_the_data_scope() {
    let (_directory, storage) = storage().await;
    storage.enable_user_scoped_data();
    with_data_scope(user("ana"), storage.save_history_entry(&entry("a1", "2026-01-01T00:00:01"))).await.unwrap();
    let spawned = {
        let storage = storage.clone();
        with_data_scope(user("ana"), async move {
            crate::connection::session_credentials::spawn_in_request_scope(async move {
                storage.search_history_entries(HistorySearchRequest::default()).await
            })
            .await
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert_eq!(spawned.entries.len(), 1);
    let lost = {
        let storage = storage.clone();
        tokio::spawn(async move { storage.search_history_entries(HistorySearchRequest::default()).await })
            .await
            .unwrap()
            .unwrap()
    };
    assert!(lost.entries.is_empty());
}

fn conversation(id: &str, updated_at: &str) -> AiConversation {
    serde_json::from_value(serde_json::json!({
        "id": id, "title": id, "connectionName": "Sales", "database": "crm",
        "messages": [], "createdAt": updated_at, "updatedAt": updated_at
    }))
    .unwrap()
}

#[tokio::test]
async fn ai_conversations_are_private_and_capped_per_owner() {
    let (_directory, storage) = storage().await;
    storage.enable_user_scoped_data();
    with_data_scope(user("ana"), storage.save_ai_conversation(&conversation("ana-chat", "2026-01-01T00:00:00")))
        .await
        .unwrap();
    with_data_scope(user("bob"), async {
        for index in 0..55 {
            let at = format!("2026-01-02T00:00:{index:02}");
            storage.save_ai_conversation(&conversation(&format!("bob-{index:02}"), &at)).await.unwrap();
        }
    })
    .await;

    let ana = with_data_scope(user("ana"), storage.load_ai_conversations()).await.unwrap();
    assert_eq!(ana.iter().map(|conv| conv.id.as_str()).collect::<Vec<_>>(), vec!["ana-chat"]);
    let bob = with_data_scope(user("bob"), storage.load_ai_conversations()).await.unwrap();
    assert_eq!(bob.len(), 50);
    assert!(bob.iter().all(|conv| conv.id != "bob-00"));

    assert!(with_data_scope(user("bob"), storage.save_ai_conversation(&conversation("ana-chat", "2026-02-01")))
        .await
        .is_err());
    with_data_scope(user("bob"), storage.delete_ai_conversation("ana-chat")).await.unwrap();
    assert_eq!(with_data_scope(user("ana"), storage.load_ai_conversations()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn tab_caches_are_private_and_pruned_per_owner() {
    let (_directory, storage) = storage().await;
    storage.enable_user_scoped_data();
    with_data_scope(user("ana"), storage.save_tab_runtime_cache("ana-tab", vec![1; 10], 1, 1, Some("w1".into())))
        .await
        .unwrap();
    with_data_scope(user("bob"), storage.save_tab_runtime_cache("bob-tab", vec![2; 10], 1, 1, Some("w2".into())))
        .await
        .unwrap();

    assert!(with_data_scope(user("bob"), storage.load_tab_runtime_cache("ana-tab")).await.unwrap().is_none());
    assert!(with_data_scope(user("bob"), storage.save_tab_runtime_cache("ana-tab", vec![], 0, 0, None)).await.is_err());
    let listed = with_data_scope(user("bob"), storage.list_tab_runtime_cache_metadata()).await.unwrap();
    assert_eq!(listed.iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>(), vec!["bob-tab"]);

    let pruned = with_data_scope(user("bob"), storage.prune_tab_runtime_cache(Vec::new(), 0, 0, None)).await.unwrap();
    assert_eq!(pruned.deleted_entries, 1);
    with_data_scope(user("bob"), async {
        storage.delete_tab_runtime_cache("ana-tab").await.unwrap();
        storage.delete_tab_runtime_cache_owner("w1").await.unwrap();
    })
    .await;
    assert!(with_data_scope(user("ana"), storage.load_tab_runtime_cache("ana-tab")).await.unwrap().is_some());
}
