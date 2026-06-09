use crate::rbac::traits::{Permission, Subject};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestSubject(pub String);

impl Subject for TestSubject {
    fn subject_id(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestPerm {
    Read,
    Write,
    Delete,
    Admin,
}

impl Permission for TestPerm {
    fn name(&self) -> &str {
        match self {
            TestPerm::Read => "read",
            TestPerm::Write => "write",
            TestPerm::Delete => "delete",
            TestPerm::Admin => "admin",
        }
    }

    fn domain(&self) -> &'static str {
        match self {
            TestPerm::Read => "test",
            TestPerm::Write => "test",
            TestPerm::Delete => "test",
            TestPerm::Admin => "test",
        }
    }
}
