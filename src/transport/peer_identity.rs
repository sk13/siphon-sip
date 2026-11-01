//! What the TLS handshake learned about the peer of an inbound connection (its client certificate), by connection id, for
//! the script (`request.tls_peer_cn`, `request.tls_peer_dns`). Filled once the handshake completes and dropped when the
//! connection ends.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The names in a client certificate that chained to `client_ca`.
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity {
    pub common_name: Option<String>,
    pub dns: Vec<String>,
}

fn peers() -> &'static Mutex<HashMap<u64, PeerIdentity>> {
    static PEERS: OnceLock<Mutex<HashMap<u64, PeerIdentity>>> = OnceLock::new();
    PEERS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn remember(connection_id: u64, identity: PeerIdentity) {
    peers().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(connection_id, identity);
}

pub fn forget(connection_id: u64) {
    peers().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&connection_id);
}

pub fn lookup(connection_id: u64) -> Option<PeerIdentity> {
    peers().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&connection_id).cloned()
}

/// The identity in the peer's certificate chain of a completed server-side handshake: the first (end-entity) certificate.
pub fn from_certificates(certificates: Option<&[rustls_pki_types::CertificateDer<'_>]>) -> Option<PeerIdentity> {
    let end_entity = certificates?.first()?;
    let names = crate::transport::tls_client_auth::presented_names(end_entity.as_ref()).ok()?;
    Some(PeerIdentity { common_name: names.common_name, dns: names.dns })
}
