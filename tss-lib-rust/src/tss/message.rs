use prost::Message;
use std::fmt;

pub trait MessageContent: Message + fmt::Debug {
    fn validate_basic(&self) -> bool;
}

pub struct MessageWrapper {
    is_broadcast: bool,
    is_to_old_committee: bool,
    is_to_old_and_new_committees: bool,
    from: PartyID,
    to: Vec<PartyID>,
    message: Box<dyn MessageContent>,
}

impl MessageWrapper {
    pub fn new(is_broadcast: bool, is_to_old_committee: bool, is_to_old_and_new_committees: bool, from: PartyID, to: Vec<PartyID>, message: Box<dyn MessageContent>) -> Self {
        MessageWrapper {
            is_broadcast,
            is_to_old_committee,
            is_to_old_and_new_committees,
            from,
            to,
            message,
        }
    }
}

pub struct ParsedMessage {
    routing: MessageRouting,
    content: Box<dyn MessageContent>,
    wire: MessageWrapper,
}

impl ParsedMessage {
    pub fn new(routing: MessageRouting, content: Box<dyn MessageContent>, wire: MessageWrapper) -> Self {
        ParsedMessage { routing, content, wire }
    }
}

pub struct MessageRouting {
    from: PartyID,
    to: Vec<PartyID>,
    is_broadcast: bool,
    is_to_old_committee: bool,
    is_to_old_and_new_committees: bool,
}

impl MessageRouting {
    pub fn new(from: PartyID, to: Vec<PartyID>, is_broadcast: bool, is_to_old_committee: bool, is_to_old_and_new_committees: bool) -> Self {
        MessageRouting {
            from,
            to,
            is_broadcast,
            is_to_old_committee,
            is_to_old_and_new_committees,
        }
    }
}
