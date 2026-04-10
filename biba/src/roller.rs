//! Cycle through ClientHello profiles until one works (uTLS `Roller` — core logic without I/O).

use crate::parrot::ClientHelloId;
use rand::seq::SliceRandom;
use rand::thread_rng;

/// Default IDs tried by [`Roller::new`] (uTLS `NewRoller`).
pub fn default_hello_ids() -> Vec<ClientHelloId> {
    vec![
        ClientHelloId::Chrome70,
        ClientHelloId::Firefox65,
        ClientHelloId::HelloRandomized,
    ]
}

/// Remembers a working profile and prioritizes it on subsequent attempts (uTLS `Roller`).
#[derive(Clone, Debug)]
pub struct Roller {
    pub hello_ids: Vec<ClientHelloId>,
    pub working: Option<ClientHelloId>,
}

impl Roller {
    pub fn new(hello_ids: Vec<ClientHelloId>) -> Self {
        Self {
            hello_ids,
            working: None,
        }
    }

    /// Build try order: shuffle, then move `working` to front if set.
    pub fn ordered_ids(&self) -> Vec<ClientHelloId> {
        let mut ids = self.hello_ids.clone();
        ids.shuffle(&mut thread_rng());
        if let Some(ref w) = self.working {
            if let Some(i) = ids.iter().position(|x| x == w) {
                ids.swap(0, i);
            } else {
                ids.insert(0, w.clone());
            }
        }
        ids
    }

    /// Call after a successful handshake with the ID that worked.
    pub fn set_working(&mut self, id: ClientHelloId) {
        self.working = Some(id);
    }
}

impl Default for Roller {
    fn default() -> Self {
        Self::new(default_hello_ids())
    }
}
