use num_bigint::BigInt;

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
