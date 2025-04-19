use prost::Message;
use std::fmt;
use num_bigint::BigInt;

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
#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[derive(Message, Debug)]
    struct TestMessage {
        #[prost(string, tag = "1")]
        content: String,
    }

    impl MessageContent for TestMessage {
        fn validate_basic(&self) -> bool {
            !self.content.is_empty()
        }
    }

    #[test]
    fn test_message_wrapper_creation() {
        let from = PartyID::new("id".to_string(), "moniker".to_string(), BigInt::from(1));
        let to = vec![PartyID::new("id2".to_string(), "moniker2".to_string(), BigInt::from(2))];
        let message = Box::new(TestMessage { content: "test".to_string() });
        let wrapper = MessageWrapper::new(false, false, false, from.clone(), to.clone(), message);

        assert_eq!(wrapper.from.id, from.id);
        assert_eq!(wrapper.to.len(), to.len());
    }
}
use crate::tss::party_id::PartyID;
