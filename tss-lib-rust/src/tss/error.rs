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
