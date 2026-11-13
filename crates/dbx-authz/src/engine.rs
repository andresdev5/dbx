use serde::{Deserialize, Serialize};

use crate::{Effect, Grant, Operations, Principal, Resource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    Exact,
    AnyWithin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Need {
    pub resource: Resource,
    pub all_of: Operations,
    pub any_of: Operations,
    pub mode: Match,
}

impl Need {
    pub fn exact(resource: Resource, operations: Operations) -> Self {
        Self { resource, all_of: operations, any_of: Operations::empty(), mode: Match::Exact }
    }

    pub fn within(resource: Resource, operations: Operations) -> Self {
        Self { resource, all_of: operations, any_of: Operations::empty(), mode: Match::AnyWithin }
    }

    pub fn any_write_within(resource: Resource) -> Self {
        Self { resource, all_of: Operations::empty(), any_of: Operations::WRITES, mode: Match::AnyWithin }
    }

    fn is_satisfied_by(&self, available: Operations) -> bool {
        available.contains(self.all_of) && (self.any_of.is_empty() || available.intersects(self.any_of))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    pub needs: Vec<Need>,
}

impl Requirement {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn single(need: Need) -> Self {
        Self { needs: vec![need] }
    }

    pub fn is_empty(&self) -> bool {
        self.needs.is_empty()
    }

    pub fn push(&mut self, need: Need) {
        if need.all_of.is_empty() && need.any_of.is_empty() {
            return;
        }
        if let Some(existing) = self.needs.iter_mut().find(|existing| {
            existing.resource == need.resource && existing.mode == need.mode && existing.any_of == need.any_of
        }) {
            existing.all_of |= need.all_of;
        } else {
            self.needs.push(need);
        }
    }

    pub fn operations(&self) -> Operations {
        self.needs.iter().fold(Operations::empty(), |acc, need| acc | need.all_of | need.any_of)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Denial {
    pub resource: Resource,
    pub missing: Operations,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_by: Option<String>,
    pub limited_by_ceiling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny(Denial),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectionContext<'a> {
    pub connection_id: &'a str,
    pub group_path: &'a [String],
    pub ceiling: Operations,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    pattern: Resource,
    operations: Operations,
    grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissions {
    connection_id: String,
    allows: Vec<Rule>,
    denies: Vec<Rule>,
    ceiling: Operations,
}

pub fn compile(principal: &Principal, grants: &[Grant], context: ConnectionContext<'_>) -> EffectivePermissions {
    let mut allows = Vec::new();
    let mut denies = Vec::new();
    let implicit = principal.implicit_operations();
    if !implicit.is_empty() {
        allows.push(Rule {
            pattern: Resource::connection(context.connection_id),
            operations: implicit,
            grant_id: None,
        });
    }
    for grant in grants {
        if grant.operations.is_empty() || !grant.is_active(context.now) || !principal.is_subject(&grant.subject) {
            continue;
        }
        let Some(pattern) = grant.pattern_for(context.connection_id, context.group_path) else {
            continue;
        };
        let rule = Rule { pattern, operations: grant.operations, grant_id: Some(grant.id.clone()) };
        match grant.effect {
            Effect::Allow => allows.push(rule),
            Effect::Deny => denies.push(rule),
        }
    }
    EffectivePermissions { connection_id: context.connection_id.to_string(), allows, denies, ceiling: context.ceiling }
}

impl EffectivePermissions {
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn ceiling(&self) -> Operations {
        self.ceiling
    }

    pub fn operations_at(&self, resource: &Resource) -> Operations {
        if resource.connection_id != self.connection_id {
            return Operations::empty();
        }
        let allowed = self
            .allows
            .iter()
            .filter(|rule| rule.pattern.covers(resource))
            .fold(Operations::empty(), |acc, rule| acc | rule.operations);
        let denied = self
            .denies
            .iter()
            .filter(|rule| rule.pattern.overlaps(resource))
            .fold(Operations::empty(), |acc, rule| acc | rule.operations);
        allowed.difference(denied) & self.ceiling
    }

    pub fn operations_within(&self, resource: &Resource) -> Operations {
        self.candidates_within(resource)
            .fold(Operations::empty(), |acc, candidate| acc | self.operations_at(&candidate))
    }

    pub fn has_rules_below_connection(&self) -> bool {
        self.allows.iter().chain(&self.denies).any(|rule| rule.pattern.database.is_some())
    }

    pub fn is_visible(&self) -> bool {
        !self.operations_within(&Resource::connection(self.connection_id.clone())).is_empty()
    }

    pub fn check(&self, need: &Need) -> Result<(), Box<Denial>> {
        let satisfied = match need.mode {
            Match::Exact => need.is_satisfied_by(self.operations_at(&need.resource)),
            Match::AnyWithin => self
                .candidates_within(&need.resource)
                .any(|candidate| need.is_satisfied_by(self.operations_at(&candidate))),
        };
        if satisfied {
            Ok(())
        } else {
            Err(Box::new(self.denial(need)))
        }
    }

    pub fn authorize(&self, requirement: &Requirement) -> Decision {
        for need in &requirement.needs {
            if let Err(denial) = self.check(need) {
                return Decision::Deny(*denial);
            }
        }
        Decision::Allow
    }

    fn candidates_within<'a>(&'a self, resource: &'a Resource) -> impl Iterator<Item = Resource> + 'a {
        std::iter::once(resource.clone()).chain(
            self.allows
                .iter()
                .filter(move |rule| rule.pattern != *resource && resource.covers(&rule.pattern))
                .map(|rule| rule.pattern.clone()),
        )
    }

    fn denial(&self, need: &Need) -> Denial {
        let available = match need.mode {
            Match::Exact => self.operations_at(&need.resource),
            Match::AnyWithin => self.operations_within(&need.resource),
        };
        let mut missing = need.all_of.difference(available);
        if !need.any_of.is_empty() && !available.intersects(need.any_of) {
            missing |= need.any_of;
        }
        if missing.is_empty() {
            missing = need.all_of | need.any_of;
        }
        let denied_by = self
            .denies
            .iter()
            .find(|rule| rule.pattern.overlaps(&need.resource) && rule.operations.intersects(missing))
            .and_then(|rule| rule.grant_id.clone());
        Denial {
            resource: need.resource.clone(),
            missing,
            denied_by,
            limited_by_ceiling: missing.intersects(Operations::all().difference(self.ceiling)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuiltinRole, PlatformRole, Scope, Subject};

    const NOW: i64 = 1_800_000_000;

    fn user(groups: &[&str]) -> Principal {
        Principal::User {
            user_id: "ana".into(),
            groups: groups.iter().map(|group| group.to_string()).collect(),
            role: PlatformRole::User,
        }
    }

    fn admin() -> Principal {
        Principal::User { user_id: "root".into(), groups: Vec::new(), role: PlatformRole::Admin }
    }

    fn grant(id: &str, subject: Subject, scope: Scope, effect: Effect, operations: Operations) -> Grant {
        Grant { id: id.into(), subject, scope, effect, operations, expires_at: None }
    }

    fn context(group_path: &[String]) -> ConnectionContext<'_> {
        ConnectionContext { connection_id: "ventas", group_path, ceiling: Operations::all(), now: NOW }
    }

    fn ventas() -> Resource {
        Resource::connection("ventas")
    }

    #[test]
    fn group_editor_with_user_deny_matches_spec_example() {
        let grants = vec![
            grant(
                "g1",
                Subject::Group("soporte".into()),
                Scope::Resource(ventas()),
                Effect::Allow,
                BuiltinRole::Editor.operations(),
            ),
            grant(
                "g2",
                Subject::User("ana".into()),
                Scope::Resource(ventas().with_database("prod")),
                Effect::Deny,
                Operations::DELETE,
            ),
            grant(
                "g3",
                Subject::Group("soporte".into()),
                Scope::Resource(ventas()),
                Effect::Allow,
                BuiltinRole::FullEditor.operations(),
            ),
        ];
        let permissions = compile(&user(&["soporte"]), &grants, context(&[]));
        let staging = ventas().with_database("staging").with_schema("public").with_table("orders");
        let prod = ventas().with_database("prod").with_schema("public").with_table("orders");
        assert!(permissions.operations_at(&staging).contains(Operations::DELETE));
        assert!(!permissions.operations_at(&prod).contains(Operations::DELETE));
        assert!(permissions.operations_at(&prod).contains(Operations::UPDATE | Operations::IMPORT));

        let decision = permissions.authorize(&Requirement::single(Need::exact(prod.clone(), Operations::DELETE)));
        assert_eq!(
            decision,
            Decision::Deny(Denial {
                resource: prod,
                missing: Operations::DELETE,
                denied_by: Some("g2".into()),
                limited_by_ceiling: false
            })
        );
    }

    #[test]
    fn deny_on_a_descendant_blocks_the_operation_on_the_whole_ancestor() {
        let grants = vec![
            grant("a", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::DELETE),
            grant(
                "d",
                Subject::User("ana".into()),
                Scope::Resource(ventas().with_database("prod").with_schema("s").with_table("t")),
                Effect::Deny,
                Operations::DELETE,
            ),
        ];
        let permissions = compile(&user(&[]), &grants, context(&[]));
        assert!(!permissions.operations_at(&ventas().with_database("prod")).contains(Operations::DELETE));
        assert!(permissions.operations_at(&ventas().with_database("dev")).contains(Operations::DELETE));
    }

    #[test]
    fn admin_gets_everything_but_explicit_deny_still_applies() {
        let grants = vec![grant(
            "d",
            Subject::User("root".into()),
            Scope::Resource(ventas().with_database("prod")),
            Effect::Deny,
            Operations::DROP,
        )];
        let permissions = compile(&admin(), &grants, context(&[]));
        assert_eq!(permissions.operations_at(&ventas().with_database("dev")), Operations::all());
        assert_eq!(permissions.operations_at(&ventas().with_database("prod")), Operations::all() - Operations::DROP);
    }

    #[test]
    fn local_principal_has_everything_and_no_grant_matches_it() {
        let grants = vec![grant("d", Subject::System, Scope::All, Effect::Deny, Operations::all())];
        let permissions = compile(&Principal::Local, &grants, context(&[]));
        assert_eq!(permissions.operations_at(&ventas()), Operations::all());
    }

    #[test]
    fn system_principal_only_gets_system_grants() {
        let grants = vec![
            grant(
                "s",
                Subject::System,
                Scope::Resource(ventas()),
                Effect::Allow,
                Operations::SELECT | Operations::EXPORT,
            ),
            grant("u", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::all()),
        ];
        let permissions = compile(&Principal::System { task_id: Some("backup-1".into()) }, &grants, context(&[]));
        assert_eq!(permissions.operations_at(&ventas().with_database("x")), Operations::SELECT | Operations::EXPORT);
    }

    #[test]
    fn expired_grants_are_ignored() {
        let mut expired = grant("e", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::UPDATE);
        expired.expires_at = Some(NOW);
        let mut alive = grant("a", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::SELECT);
        alive.expires_at = Some(NOW + 1);
        let permissions = compile(&user(&[]), &[expired, alive], context(&[]));
        assert_eq!(permissions.operations_at(&ventas()), Operations::SELECT);
    }

    #[test]
    fn connection_group_grant_applies_only_inside_that_group() {
        let grants = vec![grant(
            "g",
            Subject::User("ana".into()),
            Scope::ConnectionGroup("prod-dbs".into()),
            Effect::Allow,
            Operations::SELECT,
        )];
        let inside = vec!["root".to_string(), "prod-dbs".to_string()];
        assert_eq!(compile(&user(&[]), &grants, context(&inside)).operations_at(&ventas()), Operations::SELECT);
        assert!(compile(&user(&[]), &grants, context(&[])).operations_at(&ventas()).is_empty());
    }

    #[test]
    fn grants_for_other_connections_are_ignored() {
        let grants = vec![grant(
            "g",
            Subject::User("ana".into()),
            Scope::Resource(Resource::connection("otra")),
            Effect::Allow,
            Operations::all(),
        )];
        let permissions = compile(&user(&[]), &grants, context(&[]));
        assert!(!permissions.is_visible());
        assert!(permissions.operations_at(&Resource::connection("otra")).is_empty());
    }

    #[test]
    fn read_only_ceiling_caps_everything_and_is_reported() {
        let grants = vec![grant("g", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::all())];
        let ctx = ConnectionContext { ceiling: Operations::READ_ONLY_CEILING, ..context(&[]) };
        let permissions = compile(&user(&[]), &grants, ctx);
        assert_eq!(permissions.operations_at(&ventas()), Operations::READ_ONLY_CEILING);
        let Decision::Deny(denial) =
            permissions.authorize(&Requirement::single(Need::exact(ventas(), Operations::UPDATE)))
        else {
            panic!("expected deny");
        };
        assert!(denial.limited_by_ceiling);
        assert_eq!(denial.denied_by, None);
    }

    #[test]
    fn schema_level_grant_makes_connection_visible_and_satisfies_any_within() {
        let schema = ventas().with_database("app").with_schema("reporting");
        let grants = vec![grant(
            "g",
            Subject::User("ana".into()),
            Scope::Resource(schema.clone()),
            Effect::Allow,
            Operations::SELECT,
        )];
        let permissions = compile(&user(&[]), &grants, context(&[]));
        assert!(permissions.is_visible());
        let app = ventas().with_database("app");
        assert!(permissions.check(&Need::within(app.clone(), Operations::SELECT)).is_ok());
        assert!(permissions.check(&Need::exact(app.clone(), Operations::SELECT)).is_err());
        assert!(permissions.check(&Need::within(ventas().with_database("other"), Operations::SELECT)).is_err());
        assert!(permissions.check(&Need::exact(schema.with_table("t"), Operations::SELECT)).is_ok());
    }

    #[test]
    fn any_within_requires_all_operations_at_the_same_place() {
        let app = ventas().with_database("app");
        let grants = vec![
            grant(
                "s",
                Subject::User("ana".into()),
                Scope::Resource(app.clone().with_schema("a")),
                Effect::Allow,
                Operations::SELECT,
            ),
            grant(
                "u",
                Subject::User("ana".into()),
                Scope::Resource(app.clone().with_schema("b")),
                Effect::Allow,
                Operations::UPDATE,
            ),
        ];
        let permissions = compile(&user(&[]), &grants, context(&[]));
        let need = Need::within(app, Operations::SELECT | Operations::UPDATE);
        let denial = permissions.check(&need).unwrap_err();
        assert_eq!(denial.missing, Operations::SELECT | Operations::UPDATE);
    }

    #[test]
    fn transaction_control_needs_some_write_somewhere() {
        let app = ventas().with_database("app");
        let reader = vec![grant("r", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::SELECT)];
        let writer = vec![grant(
            "w",
            Subject::User("ana".into()),
            Scope::Resource(app.clone().with_schema("s").with_table("t")),
            Effect::Allow,
            Operations::INSERT,
        )];
        let need = Need::any_write_within(app);
        let denial = compile(&user(&[]), &reader, context(&[])).check(&need).unwrap_err();
        assert_eq!(denial.missing, Operations::WRITES);
        assert!(compile(&user(&[]), &writer, context(&[])).check(&need).is_ok());
    }

    #[test]
    fn requirement_stops_at_first_failing_need_and_empty_requirement_is_allowed() {
        let grants = vec![grant("g", Subject::User("ana".into()), Scope::All, Effect::Allow, Operations::SELECT)];
        let permissions = compile(&user(&[]), &grants, context(&[]));
        assert!(permissions.authorize(&Requirement::new()).is_allowed());
        let mut requirement = Requirement::new();
        requirement.push(Need::exact(ventas().with_database("a"), Operations::SELECT));
        requirement.push(Need::exact(ventas().with_database("b"), Operations::INSERT));
        let Decision::Deny(denial) = permissions.authorize(&requirement) else { panic!("expected deny") };
        assert_eq!(denial.resource, ventas().with_database("b"));
        assert_eq!(denial.missing, Operations::INSERT);
    }

    #[test]
    fn requirement_push_merges_same_resource_and_skips_empty_needs() {
        let mut requirement = Requirement::new();
        requirement.push(Need::exact(ventas(), Operations::SELECT));
        requirement.push(Need::exact(ventas(), Operations::INSERT));
        requirement.push(Need::exact(ventas(), Operations::empty()));
        requirement.push(Need::within(ventas(), Operations::SELECT));
        assert_eq!(requirement.needs.len(), 2);
        assert_eq!(requirement.needs[0].all_of, Operations::SELECT | Operations::INSERT);
    }

    #[test]
    fn foreign_connection_need_is_denied() {
        let permissions = compile(&admin(), &[], context(&[]));
        assert!(permissions.check(&Need::exact(Resource::connection("otra"), Operations::SELECT)).is_err());
    }

    #[test]
    fn reports_rules_below_the_connection() {
        let connection_only = vec![grant(
            "a",
            Subject::User("ana".into()),
            Scope::Resource(Resource::connection("c")),
            Effect::Allow,
            Operations::SELECT,
        )];
        let context = ConnectionContext { connection_id: "c", group_path: &[], ceiling: Operations::all(), now: NOW };
        assert!(!compile(&user(&[]), &connection_only, context).has_rules_below_connection());
        let mut scoped = connection_only.clone();
        scoped.push(grant(
            "d",
            Subject::User("ana".into()),
            Scope::Resource(Resource::connection("c").with_database("hr")),
            Effect::Deny,
            Operations::SELECT,
        ));
        assert!(compile(&user(&[]), &scoped, context).has_rules_below_connection());
    }
}
