//! IPsec ESP decryption — placeholder keyed off a static key table.

#[derive(Debug, Clone)]
pub struct EspKey {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub spi: u32,
    pub algo: EspAlgo,
    pub enc_key: Vec<u8>,
    pub auth_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspAlgo {
    Null,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Default, Clone)]
pub struct EspKeyTable {
    pub keys: Vec<EspKey>,
}

impl EspKeyTable {
    pub fn find(&self, src: std::net::IpAddr, dst: std::net::IpAddr, spi: u32) -> Option<&EspKey> {
        self.keys.iter().find(|k| k.src == src && k.dst == dst && k.spi == spi)
    }
}
