// Connection management — WebSocket + TLS + cert pinning
// TODO: Implement in next phase

pub struct ConnectionConfig {
    pub server_url: String,
    pub cert_pins: Vec<String>, // SHA256 hashes of expected TLS certificates
}
