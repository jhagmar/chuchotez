//! Wire objects and pure transforms.
//!
//! Layout version is the module: [`v1`] today, a sibling `v2` later. Each
//! layout has its own `Engine` contract. Types inside [`v1`] use ordinary names
//! (`Ticket`, `Engine`).

pub mod v1;

mod bytes32;
mod policy;
mod rng;

pub use policy::Policy;
pub use rng::{RANDOM32_LEN, Random32, Random32Bytes, Rng};
