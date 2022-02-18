use umbral_pre::*;

// TODO: get umbral_pre to expose traits for implementation.
pub fn sk_to_bytes(sk: SecretKey) -> Vec<u8> {
    sk.to_secret_array().as_secret().to_vec()
}
