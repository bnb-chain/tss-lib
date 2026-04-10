use prost::Message;
use prost_types::Any;

#[derive(Message)]
pub struct MessageWrapper {
    #[prost(bool, tag = "1")]
    pub is_broadcast: bool,
    #[prost(bool, tag = "2")]
    pub is_to_old_committee: bool,
    #[prost(bool, tag = "5")]
    pub is_to_old_and_new_committees: bool,
    #[prost(message, optional, tag = "3")]
    pub from: Option<PartyID>,
    #[prost(message, repeated, tag = "4")]
    pub to: Vec<PartyID>,
    #[prost(message, optional, tag = "10")]
    pub message: Option<Any>,
}

#[derive(Message)]
pub struct PartyID {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub moniker: String,
    #[prost(bytes, tag = "3")]
    pub key: Vec<u8>,
}
