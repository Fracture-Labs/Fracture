use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub(crate) struct EncryptRequest {
    pub sender_pk: String,
    pub plaintext: String,
}

#[derive(Serialize)]
pub(crate) struct EncryptReply {
  pub(crate) capsule_bytes: Vec<u8>,
  pub(crate) ciphertext: Vec<u8>
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deserializes_encrypt_payload() {
        let payload = r#"{
            "sender_pk": "0391898df04a71af98e55ead2bf401e985f39347a25df4012a1efb7e0144f254f3",
            "plaintext": "plaintext please don't read these bytes"
        }"#;

        serde_json::from_str::<EncryptRequest>(&payload).unwrap();
    }
}