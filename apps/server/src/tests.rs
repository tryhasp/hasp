mod persistence;

macro_rules! suite {
    ($kind:ident, $store:ty) => {
        #[path = "tests"]
        #[expect(
            clippy::duplicate_mod,
            reason = "the same suite runs once per store implementation"
        )]
        mod $kind {
            type Harness = crate::fixture::HarnessOf<$store>;

            mod admin;
            mod attachment;
            mod credential;
            mod departure;
            mod members;
            mod recovery;
            mod registration;
            mod repair;
            mod reregister;
            mod session;
            mod vault;
        }
    };
}

suite!(memory, crate::MemoryStore);
suite!(sqlite, crate::SqliteStore);
