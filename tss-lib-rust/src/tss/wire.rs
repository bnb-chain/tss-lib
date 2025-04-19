use prost::Message;
use prost_types::Any;

pub fn parse_wire_message(wire_bytes: &[u8], from: &PartyID, is_broadcast: bool) -> Result<ParsedMessage, Box<dyn std::error::Error>> {
    let wire: MessageWrapper = Message::decode(wire_bytes)?;
    let content: Box<dyn MessageContent> = Box::new(wire.message.unwrap());
    let routing = MessageRouting::new(from.clone(), wire.to, is_broadcast, wire.is_to_old_committee, wire.is_to_old_and_new_committees);
    Ok(ParsedMessage::new(routing, content, wire))
}
use crate::tss::message::{MessageContent, MessageRouting, ParsedMessage};
use crate::tss::message_pb::MessageWrapper;
use crate::tss::party_id::PartyID;
