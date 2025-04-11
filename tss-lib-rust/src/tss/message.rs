// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Translation of tss-lib-go/tss/message.go

use crate::tss::party_id::PartyID;
use std::fmt;
use prost::Message as ProstMessage;
use prost_types::Any;
use anyhow::{Result, anyhow};

// --- Traits defining message components ---

/// Represents the content of a TSS message (the actual data being sent).
/// Must be a Prost-encodable message and have basic validation.
pub trait MessageContent: ProstMessage + Clone + Default + Send + Sync + 'static {
    /// Performs basic validation on the message content.
    fn validate_basic(&self) -> bool;
    /// Returns the Protobuf type URL (e.g., "type.googleapis.com/my.package.MyMessage").
    /// This is often derived automatically or needs a helper.
    fn type_url(&self) -> String;
}

/// Represents the routing information and metadata for a TSS message.
pub trait MessageRouting {
    fn from(&self) -> &PartyID;
    fn to(&self) -> Option<&[PartyID]>; // None means broadcast
    fn is_broadcast(&self) -> bool;
    fn is_to_old_committee(&self) -> bool;
    fn is_to_old_and_new_committees(&self) -> bool;
}

/// Represents a full TSS message, including routing and content.
pub trait TssMessage: MessageRouting + fmt::Debug + Send + Sync + 'static {
    /// Returns the type name/URL of the inner message content.
    fn type_url(&self) -> String;

    /// Provides access to the underlying `MessageContent`.
    fn content_any(&self) -> Result<Any>;

    /// Returns the fully encoded bytes ready for wire transport *and* routing info.
    /// The bytes should typically be the encoded `Any` message content.
    fn wire_bytes(&self) -> Result<(Vec<u8>, MessageRoutingInfo)>;

    /// Provides a string representation for logging/debugging.
    fn to_string(&self) -> String;
}

/// Represents a message that has been received and parsed, including its content.
pub trait ParsedMessage: TssMessage {
    // We need a way to get the typed content back. This is tricky without generics or `dyn Any`.
    // Option 1: Generics (Makes Party trait generic?)
    // Option 2: `dyn Any` (Requires downcasting, less type-safe)
    // Option 3: Specific methods for each message type (Verbose)
    // Option 4: Use an enum for MessageContent types

    // Let's try using Any for now, assuming the receiver knows what type to expect.
    fn content_any_ref(&self) -> &Any;

    /// Validates the basic structure and content of the parsed message.
    fn validate_basic(&self) -> bool;
}


// --- Concrete Implementations ---

/// Concrete routing information struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRoutingInfo {
    pub from: PartyID,
    pub to: Option<Vec<PartyID>>, // None = broadcast
    pub is_broadcast: bool,
    pub is_to_old_committee: bool,
    pub is_to_old_and_new_committees: bool,
}

impl MessageRouting for MessageRoutingInfo {
    fn from(&self) -> &PartyID { &self.from }
    fn to(&self) -> Option<&[PartyID]> { self.to.as_deref() }
    fn is_broadcast(&self) -> bool { self.is_broadcast }
    fn is_to_old_committee(&self) -> bool { self.is_to_old_committee }
    fn is_to_old_and_new_committees(&self) -> bool { self.is_to_old_and_new_committees }
}

/// Concrete implementation of a parsed TSS message.
#[derive(Debug, Clone)]
pub struct ParsedMessageImpl {
    routing: MessageRoutingInfo,
    // Store the content as `prost_types::Any` after parsing
    content_any: Any,
}

impl ParsedMessageImpl {
    /// Creates a new `ParsedMessageImpl` from routing info and already encoded `Any` content.
    /// Typically used after receiving and parsing a message from the wire.
    pub fn new(routing: MessageRoutingInfo, content_any: Any) -> Self {
        Self { routing, content_any }
    }

    /// Creates a `ParsedMessageImpl` by encoding the `MessageContent` into an `Any`.
    /// Typically used when *creating* a message to be sent.
    pub fn from_content<C: MessageContent>(routing: MessageRoutingInfo, content: &C) -> Result<Self> {
        let any = Any {
            type_url: content.type_url(),
            value: content.encode_to_vec(),
        };
        Ok(Self { routing, content_any: any })
    }

    /// Tries to decode the inner `Any` message into a specific `MessageContent` type.
    pub fn M<T: MessageContent + Default>(&self) -> Result<T> {
        if self.content_any.type_url != T::default().type_url() {
            return Err(anyhow!("Type URL mismatch: expected {}, got {}",
                 T::default().type_url(), self.content_any.type_url));
        }
        T::decode(self.content_any.value.as_slice())
            .map_err(|e| anyhow!("Failed to decode message content: {}", e))
    }
}

impl MessageRouting for ParsedMessageImpl {
    fn from(&self) -> &PartyID { self.routing.from() }
    fn to(&self) -> Option<&[PartyID]> { self.routing.to() }
    fn is_broadcast(&self) -> bool { self.routing.is_broadcast() }
    fn is_to_old_committee(&self) -> bool { self.routing.is_to_old_committee() }
    fn is_to_old_and_new_committees(&self) -> bool { self.routing.is_to_old_and_new_committees() }
}

impl TssMessage for ParsedMessageImpl {
    fn type_url(&self) -> String {
        self.content_any.type_url.clone()
    }

    fn content_any(&self) -> Result<Any> {
        Ok(self.content_any.clone())
    }

    fn wire_bytes(&self) -> Result<(Vec<u8>, MessageRoutingInfo)> {
        let bytes = self.content_any.encode_to_vec();
        Ok((bytes, self.routing.clone()))
    }

    fn to_string(&self) -> String {
        let to_str = match self.routing.to() {
            Some(parties) => format!("{:?}", parties),
            None => "all".to_string(),
        };
        let mut extra_str = "";
        if self.is_to_old_committee() {
            extra_str = " (To Old Committee)";
        } else if self.is_to_old_and_new_committees() {
             extra_str = " (To Old+New Committees)";
        }
        format!(
            "Type: {}, From: {}, To: {}{}",
            self.type_url(),
            self.routing.from().to_string(),
            to_str,
            extra_str
        )
    }
}

impl ParsedMessage for ParsedMessageImpl {
    fn content_any_ref(&self) -> &Any {
        &self.content_any
    }

    fn validate_basic(&self) -> bool {
        // Validation should ideally happen *after* decoding to the specific type.
        // We can't validate the `Any` directly without knowing the type.
        // This suggests `validate_basic` might belong on `MessageContent` only,
        // or ParsedMessage needs to be generic over the content type.
        // For now, assume basic routing validation happened elsewhere.
        true
    }
} 