// EDDSA Keygen protocol module (scaffolded to match Go structure)

// TODO: Implement LocalParty, rounds, messages, and tests

pub mod error;
pub mod local_party;
pub mod rounds;
pub mod messages;
pub mod params;
pub mod party_base;
pub mod round_1;
pub mod round_2;
pub mod round_3;
pub mod save_data;
pub mod test_utils;

// Re-export key types for easier access
pub use error::TssError;
pub use params::Parameters;
pub use party_base::BaseParty;

// Define keygen-specific traits/structs here if needed later,
// e.g., KeygenRound trait
