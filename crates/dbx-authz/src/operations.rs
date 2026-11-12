use serde::{Deserialize, Deserializer, Serialize, Serializer};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
    pub struct Operations: u32 {
        const SELECT = 1 << 0;
        const INSERT = 1 << 1;
        const UPDATE = 1 << 2;
        const DELETE = 1 << 3;
        const TRUNCATE = 1 << 4;
        const CREATE = 1 << 5;
        const ALTER = 1 << 6;
        const DROP = 1 << 7;
        const GRANT = 1 << 8;
        const EXECUTE = 1 << 9;
        const EXPORT = 1 << 10;
        const IMPORT = 1 << 11;
        const UNCLASSIFIED = 1 << 12;
    }
}

impl Operations {
    pub const READ_ONLY_CEILING: Self = Self::SELECT.union(Self::EXPORT);

    pub const WRITES: Self = Self::all().difference(Self::READ_ONLY_CEILING);

    pub fn from_stored(bits: i64) -> Self {
        Self::from_bits_truncate(u32::try_from(bits & i64::from(u32::MAX)).unwrap_or_default())
    }

    pub fn to_stored(self) -> i64 {
        i64::from(self.bits())
    }

    pub fn names(self) -> Vec<&'static str> {
        self.iter_names().map(|(name, _)| name).collect()
    }

    pub fn has_write(self) -> bool {
        self.intersects(Self::WRITES)
    }
}

impl Serialize for Operations {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for Operations {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_bits_truncate(u32::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinRole {
    Reader,
    Analyst,
    Editor,
    FullEditor,
    Developer,
    Owner,
}

impl BuiltinRole {
    pub const ALL: [Self; 6] =
        [Self::Reader, Self::Analyst, Self::Editor, Self::FullEditor, Self::Developer, Self::Owner];

    pub fn operations(self) -> Operations {
        match self {
            Self::Reader => Operations::SELECT,
            Self::Analyst => Operations::SELECT | Operations::EXPORT,
            Self::Editor => Self::Analyst.operations() | Operations::INSERT | Operations::UPDATE,
            Self::FullEditor => Self::Editor.operations() | Operations::DELETE | Operations::IMPORT,
            Self::Developer => {
                Self::FullEditor.operations()
                    | Operations::TRUNCATE
                    | Operations::CREATE
                    | Operations::ALTER
                    | Operations::DROP
                    | Operations::EXECUTE
            }
            Self::Owner => Operations::all(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BuiltinRole, Operations};

    #[test]
    fn stored_bits_round_trip_and_unknown_bits_are_ignored() {
        let ops = Operations::SELECT | Operations::DELETE;
        assert_eq!(Operations::from_stored(ops.to_stored()), ops);
        assert_eq!(Operations::from_stored(ops.to_stored() | (1 << 20)), ops);
        assert_eq!(Operations::from_stored(-1), Operations::all());
    }

    #[test]
    fn serde_uses_integer_bits_and_truncates_unknown_bits() {
        let json = serde_json::to_string(&(Operations::SELECT | Operations::UPDATE)).unwrap();
        assert_eq!(json, "5");
        let parsed: Operations = serde_json::from_str("1048581").unwrap();
        assert_eq!(parsed, Operations::SELECT | Operations::UPDATE);
    }

    #[test]
    fn builtin_roles_are_strictly_growing() {
        for pair in BuiltinRole::ALL.windows(2) {
            let (lower, higher) = (pair[0].operations(), pair[1].operations());
            assert!(higher.contains(lower) && higher != lower, "{:?} must extend {:?}", pair[1], pair[0]);
        }
        assert_eq!(BuiltinRole::Owner.operations(), Operations::all());
    }

    #[test]
    fn writes_exclude_read_and_export_only() {
        assert!(!Operations::READ_ONLY_CEILING.has_write());
        assert!(Operations::UNCLASSIFIED.has_write());
        assert!(Operations::IMPORT.has_write());
        assert_eq!(Operations::WRITES | Operations::READ_ONLY_CEILING, Operations::all());
    }
}
