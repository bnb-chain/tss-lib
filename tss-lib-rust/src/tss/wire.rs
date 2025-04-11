// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/wire.go

use crate::tss::{
    message::{ParsedMessage, ParsedMessageImpl, MessageRoutingInfo, MessageContent},
    party_id::PartyID,
};
use prost::Message as ProstMessage;
use prost_types::Any;
use anyhow::{Result, anyhow, Context};

// TODO: This function likely needs access to a registry or map to know *which*
// concrete MessageContent type corresponds to the type_url in the Any message.
// Without it, we can only parse into the generic `ParsedMessageImpl` containing `Any`.
// The caller would then need to try decoding the `Any` into the expected type.

/// Parses a message received from the wire (as bytes).
///
/// # Arguments
/// * `wire_bytes` - The raw bytes received, expected to be an encoded `prost_types::Any` message.
/// * `from` - The `PartyID` of the sender.
/// * `is_broadcast` - Whether the message was received via broadcast.
///
/// # Returns
/// A `ParsedMessage` trait object containing the routing info and the `Any` encoded content.
pub fn parse_wire_message(
    wire_bytes: &[u8],
    from: PartyID, // Taking ownership might be better depending on usage
    is_broadcast: bool,
) -> Result<Box<dyn ParsedMessage>> { // Return a boxed trait object
    // Assume wire_bytes is the encoded `Any` message directly
    let any_msg = Any::decode(wire_bytes)
        .context("Failed to decode wire bytes into prost_types::Any")?;

    // Construct the routing info
    // TODO: Determine `to`, `is_to_old_committee`, etc. from the message type or context if needed.
    // The Go version gets these from the `MessageWrapper`, which we aren't using directly here.
    // For now, assume it's not targeted specifically (None for `to`) unless broadcast is false,
    // and default resharing flags to false.
    let routing = MessageRoutingInfo {
        from,
        to: if is_broadcast { None } else { Some(vec![]) }, // Need target if not broadcast!
        is_broadcast,
        is_to_old_committee: false, // Default, adjust if wrapper info available
        is_to_old_and_new_committees: false, // Default
    };

    // Create the ParsedMessageImpl containing the Any message
    let parsed_msg = ParsedMessageImpl::new(routing, any_msg);

    // We can return the concrete type boxed as the trait object
    Ok(Box::new(parsed_msg))
}

// The `parseWrappedMessage` in Go seems tightly coupled to the `MessageWrapper` protobuf struct.
// If we are not using that exact wrapper struct on the wire (i.e., sending only the `Any` part),
// then `parse_wire_message` above is the more direct equivalent.

// If we *were* using a Rust equivalent of MessageWrapper:
/*
use crate::proto::tss::MessageWrapper; // Assuming proto definitions exist

pub fn parse_wrapped_message(
    wrapper: &MessageWrapper,
    from_party: PartyID, // Explicitly pass parsed PartyID
) -> Result<Box<dyn ParsedMessage>> {
    let any_msg = wrapper.message.clone().ok_or_else(|| anyhow!("MessageWrapper missing Any message content"))?;

    // Reconstruct routing info from wrapper
    let to_parties = wrapper.to.iter().map(|p| PartyID {
        // Reconstruct PartyID from wrapper's version
        id: p.id.clone(),
        moniker: p.moniker.clone(),
        key: BigInt::from_bytes_be(Sign::Plus, &p.key),
        index: -1, // Index might not be known here, needs resolving
    }).collect::<Vec<_>>();

    let routing = MessageRoutingInfo {
        from: from_party,
        to: if to_parties.is_empty() { None } else { Some(to_parties) },
        is_broadcast: wrapper.is_broadcast,
        is_to_old_committee: wrapper.is_to_old_committee,
        is_to_old_and_new_committees: wrapper.is_to_old_and_new_committees,
    };

    let parsed_msg = ParsedMessageImpl::new(routing, any_msg);
    Ok(Box::new(parsed_msg))
}
*/ 