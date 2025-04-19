use prost::Message;
use std::fmt;

pub trait MessageContent: Message + fmt::Debug {
