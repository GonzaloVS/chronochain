//use crate::timestamp::TrustedTimestamp;

// pub struct TimestampChain {
//     pub chain: Vec<TrustedTimestamp>,
// }

// impl TimestampChain {
//     pub fn new() -> Self {
//         Self { chain: vec![] }
//     }
//
//     pub fn add(&mut self, stamp: TrustedTimestamp) {
//         self.chain.push(stamp);
//     }
//
//     pub fn verify_all(&self) -> bool {
//         self.chain.iter().all(|s| s.verify().is_ok())
//     }
// }
