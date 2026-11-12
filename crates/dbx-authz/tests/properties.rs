use dbx_authz::{
    compile, ConnectionContext, Effect, Grant, Need, Operations, PlatformRole, Principal, Resource, Scope, Subject,
};
use proptest::prelude::*;

const NOW: i64 = 1_800_000_000;

fn name(options: &'static [&'static str]) -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), proptest::sample::select(options).prop_map(|value| Some(value.to_string()))]
}

fn resource() -> impl Strategy<Value = Resource> {
    (name(&["app", "APP", "prod"]), name(&["public", "s"]), name(&["t", "users"]))
        .prop_map(|(database, schema, table)| Resource { connection_id: "c".into(), database, schema, table })
}

fn operations() -> impl Strategy<Value = Operations> {
    any::<u32>().prop_map(Operations::from_bits_truncate)
}

fn subject() -> impl Strategy<Value = Subject> {
    prop_oneof![
        Just(Subject::User("ana".into())),
        Just(Subject::User("otro".into())),
        Just(Subject::Group("soporte".into())),
        Just(Subject::System),
    ]
}

fn scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::All),
        Just(Scope::ConnectionGroup("grupo".into())),
        Just(Scope::ConnectionGroup("ajeno".into())),
        resource().prop_map(Scope::Resource),
    ]
}

fn grant() -> impl Strategy<Value = Grant> {
    (subject(), scope(), prop_oneof![Just(Effect::Allow), Just(Effect::Deny)], operations(), any::<bool>()).prop_map(
        |(subject, scope, effect, operations, expired)| Grant {
            id: "g".into(),
            subject,
            scope,
            effect,
            operations,
            expires_at: expired.then_some(NOW - 1),
        },
    )
}

fn principal() -> impl Strategy<Value = Principal> {
    prop_oneof![
        Just(Principal::User { user_id: "ana".into(), groups: vec!["soporte".into()], role: PlatformRole::User }),
        Just(Principal::User { user_id: "ana".into(), groups: Vec::new(), role: PlatformRole::Admin }),
        Just(Principal::System { task_id: None }),
    ]
}

fn ctx(ceiling: Operations) -> ConnectionContext<'static> {
    static PATH: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    ConnectionContext {
        connection_id: "c",
        group_path: PATH.get_or_init(|| vec!["grupo".to_string()]),
        ceiling,
        now: NOW,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn adding_an_allow_never_removes_operations(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        extra in grant(),
        target in resource(),
    ) {
        let extra = Grant { effect: Effect::Allow, ..extra };
        let before = compile(&principal, &grants, ctx(Operations::all())).operations_at(&target);
        let mut with_extra = grants.clone();
        with_extra.push(extra);
        let after = compile(&principal, &with_extra, ctx(Operations::all())).operations_at(&target);
        prop_assert!(after.contains(before));
    }

    #[test]
    fn adding_a_deny_never_adds_operations(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        extra in grant(),
        target in resource(),
    ) {
        let extra = Grant { effect: Effect::Deny, ..extra };
        let before = compile(&principal, &grants, ctx(Operations::all())).operations_at(&target);
        let mut with_extra = grants.clone();
        with_extra.push(extra);
        let after = compile(&principal, &with_extra, ctx(Operations::all())).operations_at(&target);
        prop_assert!(before.contains(after));
    }

    #[test]
    fn result_never_exceeds_the_ceiling(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        ceiling in operations(),
        target in resource(),
    ) {
        let permissions = compile(&principal, &grants, ctx(ceiling));
        prop_assert!(ceiling.contains(permissions.operations_at(&target)));
        prop_assert!(ceiling.contains(permissions.operations_within(&target)));
    }

    #[test]
    fn exact_success_implies_any_within_success(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        target in resource(),
        wanted in operations(),
    ) {
        let permissions = compile(&principal, &grants, ctx(Operations::all()));
        if permissions.check(&Need::exact(target.clone(), wanted)).is_ok() {
            prop_assert!(permissions.check(&Need::within(target, wanted)).is_ok());
        }
    }

    #[test]
    fn finer_resource_never_has_fewer_operations_from_allows_alone(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        table in resource(),
    ) {
        let allows: Vec<Grant> = grants.into_iter().filter(|grant| grant.effect == Effect::Allow).collect();
        let permissions = compile(&principal, &allows, ctx(Operations::all()));
        let parent = Resource { table: None, ..table.clone() };
        prop_assert!(permissions.operations_at(&table).contains(permissions.operations_at(&parent)));
    }

    #[test]
    fn denial_names_only_operations_that_were_requested(
        principal in principal(),
        grants in proptest::collection::vec(grant(), 0..6),
        target in resource(),
        wanted in operations(),
    ) {
        let permissions = compile(&principal, &grants, ctx(Operations::all()));
        if let Err(denial) = permissions.check(&Need::exact(target, wanted)) {
            prop_assert!(!denial.missing.is_empty());
            prop_assert!(wanted.contains(denial.missing));
        }
    }
}
