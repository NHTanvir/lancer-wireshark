//! WPA/WPA2/WPA3 4-way handshake helpers.
//! Decryption not wired into the MVP — we surface the PMK/PSK and let the
//! dissector flag handshake completion.

#[derive(Debug, Clone)]
pub struct WpaPsk {
    pub ssid: String,
    pub passphrase: String,
}

impl WpaPsk {
    pub fn pmk(&self) -> Vec<u8> {
        // PBKDF2-HMAC-SHA1, 4096 iterations, key length 32
        pbkdf2_hmac_sha1(self.passphrase.as_bytes(), self.ssid.as_bytes(), 4096, 32)
    }
}

fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iters: u32, key_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    use hmac::Mac;
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let mut out = Vec::with_capacity(key_len);
    let block_size = 20;
    let blocks = key_len.div_ceil(block_size);
    for i in 1..=blocks as u32 {
        let mut mac = HmacSha1::new_from_slice(password).unwrap();
        mac.update(salt);
        mac.update(&i.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut t = u.clone();
        for _ in 1..iters {
            let mut mac = HmacSha1::new_from_slice(password).unwrap();
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(key_len);
    out
}
