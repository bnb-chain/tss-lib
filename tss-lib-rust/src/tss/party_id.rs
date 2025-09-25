use num_bigint::BigInt;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct PartyID {
    id: String,
    moniker: String,
    key: BigInt,
    index: i32,
}

impl PartyID {
    pub fn new(id: String, moniker: String, key: BigInt) -> Self {
        PartyID {
            id,
            moniker,
            key,
            index: -1,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for PartyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format key as hex for readability
        let key_hex = self.key.to_str_radix(16);
        write!(f, "party(id:{}, moniker:{}, key:{})", self.id, self.moniker, key_hex)
    }
}
