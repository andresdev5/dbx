use dbx_core::audit::{AuditEvent, SESSION_REF_CHARS};

use crate::sessions::SessionUser;
use crate::state::WebState;

pub fn by_session(user: &SessionUser, event: &str) -> AuditEvent {
    let mut record = AuditEvent::new(event).by_user(&user.user_id, &user.username);
    record.session_ref = Some(user.token_hash.chars().take(SESSION_REF_CHARS).collect());
    record
}

pub fn record_action(state: &WebState, admin: &SessionUser, event: &str, detail: serde_json::Value) {
    if state.app.audit.is_enabled() {
        state.app.audit.record_in_request(by_session(admin, event).detail(detail));
    }
}
