use std::fmt;

#[derive(Debug)]
pub struct Error {
    cause: Box<dyn std::error::Error>,
    task: String,
    round: i32,
    victim: Option<PartyID>,
    culprits: Vec<PartyID>,
}

impl Error {
    pub fn new(cause: Box<dyn std::error::Error>, task: String, round: i32, victim: Option<PartyID>, culprits: Vec<PartyID>) -> Self {
        Error { cause, task, round, victim, culprits }
    }

    pub fn cause(&self) -> &dyn std::error::Error {
        &*self.cause
    }

    pub fn task(&self) -> &str {
        &self.task
    }

    pub fn round(&self) -> i32 {
        self.round
    }

    pub fn victim(&self) -> Option<&PartyID> {
        self.victim.as_ref()
    }

    pub fn culprits(&self) -> &[PartyID] {
        &self.culprits
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.culprits.is_empty() {
            write!(f, "task {}, party {:?}, round {}: {}", self.task, self.victim, self.round, self.cause)
        } else {
            write!(f, "task {}, party {:?}, round {}, culprits {:?}: {}", self.task, self.victim, self.round, self.culprits, self.cause)
        }
    }
}

impl std::error::Error for Error {}
#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Test error")
        }
    }

    impl StdError for TestError {}

    #[test]
    fn test_error_creation() {
        let cause = Box::new(TestError);
        let task = "test_task".to_string();
        let round = 1;
        let victim = None;
        let culprits = vec![];
        let error = Error::new(cause, task.clone(), round, victim.clone(), culprits.clone());

        assert_eq!(error.task(), task);
        assert_eq!(error.round(), round);
        assert_eq!(error.victim(), victim.as_ref());
        assert_eq!(error.culprits(), culprits.as_slice());
    }
}
