use prost::Message;
use prost_types::Any;
use crate::tss::message::{MessageContent, MessageRouting, ParsedMessage, MessageWrapper};
use crate::tss::party_id::PartyID;
use crate::tss::message_pb as pb;

fn pb_party_id_to_internal(pb_id: &pb::PartyID) -> PartyID {
    use num_bigint::BigInt;
    PartyID::new(
        pb_id.id.clone(),
        pb_id.moniker.clone(),
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &pb_id.key),
    )
}

fn pb_message_wrapper_to_internal(pb_wrap: &pb::MessageWrapper) -> MessageWrapper {
    let from = pb_party_id_to_internal(pb_wrap.from.as_ref().unwrap());
    let to = pb_wrap.to.iter().map(pb_party_id_to_internal).collect();
    // For now, message is None (prost_types::Any cannot be converted generically)
    // In a real implementation, you would match type_url and decode the correct type
    let message: Box<dyn MessageContent> = panic!("prost_types::Any to MessageContent conversion not implemented");
    MessageWrapper::new(
        pb_wrap.is_broadcast,
        pb_wrap.is_to_old_committee,
        pb_wrap.is_to_old_and_new_committees,
        from,
        to,
        message,
    )
}

pub fn parse_wire_message(wire_bytes: &[u8], from: &PartyID, is_broadcast: bool) -> Result<ParsedMessage, Box<dyn std::error::Error>> {
    let pb_wire: pb::MessageWrapper = Message::decode(wire_bytes)?;
    let internal_wire = pb_message_wrapper_to_internal(&pb_wire);
    let routing = MessageRouting::new(
        from.clone(),
        internal_wire.to().clone(),
        is_broadcast,
        internal_wire.is_to_old_committee(),
        internal_wire.is_to_old_and_new_committees(),
    );
    // For now, content is not implemented
    let content: Box<dyn MessageContent> = panic!("prost_types::Any to MessageContent conversion not implemented");
    Ok(ParsedMessage::new(routing, content, internal_wire))
}
