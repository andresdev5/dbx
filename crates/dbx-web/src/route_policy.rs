use axum::http::Method;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    Public,
    Authenticated,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Methods {
    Any,
    Writes,
}

impl Methods {
    fn matches(self, method: &Method) -> bool {
        match self {
            Self::Any => true,
            Self::Writes => !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS),
        }
    }
}

use RouteClass::{Admin, Authenticated, Public};

const RULES: &[(&str, RouteClass)] = &[
    ("auth/login", Public),
    ("auth/setup", Public),
    ("auth/check", Public),
    ("auth/captcha", Public),
    ("auth/change-password", Authenticated),
    ("auth/logout", Authenticated),
    ("admin/**", Admin),
    ("agents/**", Authenticated),
    ("WRITE agents/**", Admin),
    ("agents/update-blockers", Authenticated),
    ("agents/storage-usage", Authenticated),
    ("agents/installed", Authenticated),
    ("agents/installed-local", Authenticated),
    ("agents/progress/{operationId}", Authenticated),
    ("ai/**", Authenticated),
    ("WRITE ai/config", Admin),
    ("WRITE ai/config-item", Admin),
    ("WRITE ai/config/{config_id}", Admin),
    ("WRITE ai/configs", Admin),
    ("WRITE ai/default-config", Admin),
    ("WRITE ai/provider-config", Admin),
    ("WRITE ai/provider-configs", Admin),
    ("WRITE ai/test-connection", Admin),
    ("WRITE ai/model-effort", Admin),
    ("app-settings/**", Authenticated),
    ("WRITE app-settings/**", Admin),
    ("app-settings/pinned-tree-node-ids", Authenticated),
    ("app-settings/plugin-mcp/view", Authenticated),
    ("changelog", Authenticated),
    ("changelog/**", Authenticated),
    ("cloud-sync/**", Admin),
    ("connection/**", Authenticated),
    ("connection/save", Admin),
    ("connection/mcp/add", Admin),
    ("connection/mcp/duplicate", Admin),
    ("connection/mcp/remove", Admin),
    ("connection/test", Admin),
    ("connection/test-info", Admin),
    ("connection/test-ssh-tunnel", Admin),
    ("connection/salesforce-oauth-browser-authorize", Admin),
    ("connection/salesforce-oauth-device-start", Admin),
    ("connection/salesforce-oauth-device-poll", Admin),
    ("connection/salesforce-oauth-password-login", Admin),
    ("connection/salesforce-oauth-refresh", Admin),
    ("consul/**", Authenticated),
    ("data-compare/**", Authenticated),
    ("database-backups", Admin),
    ("database-backups/**", Admin),
    ("dialect/**", Authenticated),
    ("docs/**", Authenticated),
    ("document-store/**", Authenticated),
    ("etcd/**", Authenticated),
    ("export/**", Authenticated),
    ("hbase/**", Authenticated),
    ("history", Authenticated),
    ("history/**", Authenticated),
    ("import/**", Authenticated),
    ("jdbc/**", Authenticated),
    ("WRITE jdbc/**", Admin),
    ("layout/**", Authenticated),
    ("migration/status", Authenticated),
    ("migration/**", Admin),
    ("mongo/**", Authenticated),
    ("mq/**", Authenticated),
    ("nacos/**", Authenticated),
    ("pl-debug/**", Authenticated),
    ("plugin/**", Authenticated),
    ("plugin/data/grant", Admin),
    ("plugins", Authenticated),
    ("plugins/**", Authenticated),
    ("plugins/install", Admin),
    ("plugins/uninstall", Admin),
    ("plugins/activate", Admin),
    ("plugins/rollback", Admin),
    ("plugins/stop", Admin),
    ("plugins/marketplace/install", Admin),
    ("plugins/repositories/save", Admin),
    ("plugins/repositories/remove", Admin),
    ("plugins/trusted-keys/save", Admin),
    ("plugins/trusted-keys/remove", Admin),
    ("prompt-templates", Authenticated),
    ("prompt-templates/**", Authenticated),
    ("query/**", Authenticated),
    ("redis/**", Authenticated),
    ("salesforce/**", Authenticated),
    ("saved-sql", Authenticated),
    ("saved-sql/**", Authenticated),
    ("schema/**", Authenticated),
    ("schema-diff/**", Authenticated),
    ("sql-file/**", Authenticated),
    ("ssh/config-hosts", Admin),
    ("ssh/prompts", Authenticated),
    ("ssh/prompts/**", Authenticated),
    ("system/**", Authenticated),
    ("tab-runtime-cache", Authenticated),
    ("tab-runtime-cache/**", Authenticated),
    ("task-runs", Authenticated),
    ("task-runs/**", Authenticated),
    ("transfer/**", Authenticated),
    ("tunnel-profiles/list", Authenticated),
    ("tunnel-profiles/save", Admin),
    ("tunnel-profiles/test", Admin),
    ("update/**", Authenticated),
    ("vector/**", Authenticated),
    ("version", Authenticated),
    ("zookeeper/**", Authenticated),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Specificity {
    exact: bool,
    method_specific: bool,
    literal_segments: usize,
    segments: usize,
}

struct Rule {
    methods: Methods,
    segments: Vec<&'static str>,
    prefix: bool,
    class: RouteClass,
}

impl Rule {
    fn parse(spec: &'static str, class: RouteClass) -> Self {
        let (methods, pattern) = match spec.strip_prefix("WRITE ") {
            Some(pattern) => (Methods::Writes, pattern),
            None => (Methods::Any, spec),
        };
        let mut segments: Vec<&'static str> = pattern.split('/').collect();
        let prefix = segments.last() == Some(&"**");
        if prefix {
            segments.pop();
        }
        Self { methods, segments, prefix, class }
    }

    fn matches(&self, method: &Method, path: &[&str]) -> Option<Specificity> {
        if !self.methods.matches(method) {
            return None;
        }
        let mut index = 0;
        for segment in &self.segments {
            if segment.starts_with("{*") {
                return (index < path.len()).then(|| self.specificity());
            }
            let candidate = path.get(index)?;
            let is_param = segment.starts_with('{') && segment.ends_with('}');
            if !is_param && segment != candidate {
                return None;
            }
            index += 1;
        }
        let complete = if self.prefix { index < path.len() } else { index == path.len() };
        complete.then(|| self.specificity())
    }

    fn specificity(&self) -> Specificity {
        Specificity {
            exact: !self.prefix,
            method_specific: self.methods != Methods::Any,
            literal_segments: self.segments.iter().filter(|segment| !segment.starts_with('{')).count(),
            segments: self.segments.len(),
        }
    }
}

fn rules() -> &'static [Rule] {
    static PARSED: std::sync::OnceLock<Vec<Rule>> = std::sync::OnceLock::new();
    PARSED.get_or_init(|| RULES.iter().map(|(spec, class)| Rule::parse(spec, *class)).collect())
}

pub fn classify(method: &Method, suffix: &str) -> Option<RouteClass> {
    let path: Vec<&str> = suffix.trim_matches('/').split('/').filter(|segment| !segment.is_empty()).collect();
    if path.is_empty() {
        return None;
    }
    rules()
        .iter()
        .filter_map(|rule| rule.matches(method, &path).map(|specificity| (specificity, rule.class)))
        .max_by_key(|(specificity, _)| *specificity)
        .map(|(_, class)| class)
}

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) fn registered_routes() -> Vec<String> {
        let mut routes = Vec::new();
        for source in [include_str!("main.rs"), include_str!("routes/pl_debug.rs")] {
            let production = source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source);
            let mut rest = production;
            while let Some(start) = rest.find(".route(") {
                rest = &rest[start + ".route(".len()..];
                let trimmed = rest.trim_start();
                if let Some(literal) = trimmed.strip_prefix('"') {
                    if let Some(end) = literal.find('"') {
                        routes.push(literal[..end].to_string());
                    }
                }
            }
        }
        routes.sort();
        routes.dedup();
        routes
    }

    pub(crate) fn concrete(pattern: &str) -> String {
        pattern
            .trim_start_matches('/')
            .split('/')
            .map(|segment| if segment.starts_with('{') { "sample" } else { segment })
            .collect::<Vec<_>>()
            .join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{concrete, registered_routes};
    use super::*;

    const ALL_METHODS: [Method; 5] = [Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH];

    #[test]
    fn every_registered_route_is_classified_for_every_method() {
        let routes = registered_routes();
        assert!(routes.len() > 800, "only found {} routes", routes.len());
        let missing: Vec<String> = routes
            .iter()
            .flat_map(|route| ALL_METHODS.iter().map(move |method| (method, route)))
            .filter(|(method, route)| classify(method, &concrete(route)).is_none())
            .map(|(method, route)| format!("{method} {route}"))
            .collect();
        assert!(missing.is_empty(), "routes without a policy:\n{}", missing.join("\n"));
    }

    #[test]
    fn every_rule_matches_at_least_one_registered_route() {
        let routes: Vec<String> = registered_routes().iter().map(|route| concrete(route)).collect();
        let stale: Vec<&str> = RULES
            .iter()
            .zip(rules())
            .filter(|(_, rule)| {
                !routes.iter().any(|route| {
                    let path: Vec<&str> = route.split('/').collect();
                    ALL_METHODS.iter().any(|method| rule.matches(method, &path).is_some())
                })
            })
            .map(|((spec, _), _)| *spec)
            .collect();
        assert!(stale.is_empty(), "rules that match no route: {stale:?}");
    }

    #[test]
    fn unknown_routes_are_not_classified() {
        assert_eq!(classify(&Method::POST, "brand-new/feature"), None);
        assert_eq!(classify(&Method::GET, ""), None);
        assert_eq!(classify(&Method::GET, "plugins/../admin"), Some(Authenticated));
    }

    #[test]
    fn platform_management_is_admin_only() {
        for (method, path) in [
            (Method::POST, "connection/save"),
            (Method::POST, "connection/test"),
            (Method::POST, "connection/mcp/remove"),
            (Method::POST, "cloud-sync/webdav/upload"),
            (Method::POST, "database-backups"),
            (Method::GET, "database-backups/abc/files/0"),
            (Method::POST, "plugins/install"),
            (Method::POST, "plugin/data/grant"),
            (Method::POST, "agents/install"),
            (Method::DELETE, "agents/download-cache"),
            (Method::PUT, "app-settings/web-login-captcha"),
            (Method::PUT, "app-settings/mcp-http"),
            (Method::POST, "app-settings/config/decrypt"),
            (Method::POST, "ai/configs"),
            (Method::POST, "migration/start"),
            (Method::POST, "jdbc/plugin/install"),
            (Method::DELETE, "jdbc/drivers/some-driver"),
            (Method::GET, "ssh/config-hosts"),
            (Method::POST, "tunnel-profiles/save"),
            (Method::POST, "admin/users/list"),
        ] {
            assert_eq!(classify(&method, path), Some(Admin), "{method} {path}");
        }
    }

    #[test]
    fn everyday_work_stays_available_to_users() {
        for (method, path) in [
            (Method::GET, "connection/list"),
            (Method::POST, "connection/connect"),
            (Method::POST, "connection/database-info/save"),
            (Method::POST, "query/execute"),
            (Method::POST, "schema/tables"),
            (Method::GET, "app-settings/web-login-captcha"),
            (Method::PUT, "app-settings/pinned-tree-node-ids"),
            (Method::POST, "app-settings/plugin-mcp/view"),
            (Method::GET, "ai/configs"),
            (Method::POST, "ai/stream"),
            (Method::POST, "agents/update-blockers"),
            (Method::GET, "agents/progress/op-1"),
            (Method::GET, "jdbc/plugin/status"),
            (Method::GET, "migration/status"),
            (Method::GET, "plugins/my-plugin/assets/js/app.js"),
            (Method::POST, "plugins/invoke"),
            (Method::POST, "pl-debug/start"),
            (Method::POST, "auth/change-password"),
        ] {
            assert_eq!(classify(&method, path), Some(Authenticated), "{method} {path}");
        }
    }

    #[test]
    fn bootstrap_routes_are_public() {
        for path in ["auth/login", "auth/setup", "auth/check", "auth/captcha"] {
            assert_eq!(classify(&Method::POST, path), Some(Public));
        }
    }
}
