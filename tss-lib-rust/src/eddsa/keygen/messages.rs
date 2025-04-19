// EDDSA Keygen protocol messages (ported from eddsa-keygen.pb.go)
// Use prost for protobuf compatibility and serde for serialization

use prost::Message;
use serde::{Serialize, Deserialize};

#[derive(Clone, PartialEq, Message, Serialize, Deserialize, Debug)]
pub struct KGRound1Message {
    #[prost(bytes, tag = "1")]
    pub commitment: Vec<u8>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize, Debug)]
pub struct KGRound2Message1 {
    #[prost(bytes, tag = "1")]
    pub share: Vec<u8>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize, Debug)]
pub struct KGRound2Message2 {
    #[prost(bytes, repeated, tag = "1")]
    pub de_commitment: Vec<Vec<u8>>,
    #[prost(bytes, tag = "2")]
    pub proof_alpha_x: Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub proof_alpha_y: Vec<u8>,
    #[prost(bytes, tag = "4")]
    pub proof_t: Vec<u8>,
}
