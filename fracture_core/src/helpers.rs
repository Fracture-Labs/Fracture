use umbral_pre::*;

// TODO: get umbral_pre to expose traits for implementation.
pub fn sk_to_bytes(sk: SecretKey) -> Vec<u8> {
    sk.to_secret_array().as_secret().to_vec()
}

pub fn pk_to_bytes(pk: PublicKey) -> Vec<u8> {
    pk.to_array().to_vec()
}

pub fn capsule_to_bytes(capsule: Capsule) -> Vec<u8> {
    capsule.to_array().to_vec()
}

pub fn verified_kfrag_to_bytes(kfrag: VerifiedKeyFrag) -> Vec<u8> {
    kfrag.to_array().to_vec()
}

// Helpers
// TODO (nkls): error handling + dedup with macro
pub fn public_key_from_str(s: &str) -> Result<PublicKey, &'static str> {
    match PublicKey::from_bytes(&hex::decode(s).unwrap()) {
        Ok(pk) => Ok(pk),
        Err(_) => Err("couldn't deserialize"),
    }
}

pub fn secret_key_from_str(s: &str) -> Result<SecretKey, &'static str> {
    match SecretKey::from_bytes(&hex::decode(s).unwrap()) {
        Ok(sk) => Ok(sk),
        Err(_) => Err("couldn't deserialize"),
    }
}

pub fn key_frag_from_str(s: &str) -> Result<KeyFrag, &'static str> {
    match KeyFrag::from_bytes(&hex::decode(s).unwrap()) {
        Ok(kfrag) => Ok(kfrag),
        Err(_) => Err("couldn't deserialize"),
    }
}

pub fn capsule_frag_from_str(s: &str) -> Result<CapsuleFrag, &'static str> {
    match CapsuleFrag::from_bytes(&hex::decode(s).unwrap()) {
        Ok(cfrag) => Ok(cfrag),
        Err(_) => Err("couldn't deserialize"),
    }
}
