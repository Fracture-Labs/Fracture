#[macro_use]
extern crate rocket;

use std::collections::HashMap;

use reqwest::Client;
use rocket::{serde::json::Json, Config};
use serde::{Deserialize, Serialize};

const D_THRESHOLD: usize = 1;
const D_SHARES: usize = 2;

const K_THRESHOLD: usize = 1;
const K_SHARES: usize = 2;

#[get("/")]
fn index() -> &'static str {
    "Hello Constitution, this is Fracture!"
}

#[post("/encrypt", data = "<data>")]
async fn encrypt(data: Json<Data>) {
    let (d_sk, d_pk) = fracture_core::commands::new_account();
    let (k_sk, k_pk) = fracture_core::commands::new_account();

    // Freddie encrypts the sensitive data and stores it on ipfs.
    let inner_encrypt_args = fracture_core::commands::InnerEncryptArgs {
        sender_pk: d_pk,
        plaintext: data.plaintext.as_bytes().to_vec(),
    };

    let (d_capsule, d_ciphertext) = fracture_core::commands::encrypt(inner_encrypt_args);

    let d_capsule_cid = fracture_core::ipfs_io::write(d_capsule.clone()).await;
    let d_ciphertext_cid = fracture_core::ipfs_io::write(d_ciphertext.clone()).await;

    // Freddie encrypts the secret key used for the data encryption.
    let encrypt_args = fracture_core::commands::InnerEncryptArgs {
        sender_pk: k_pk,
        plaintext: fracture_core::helpers::sk_to_bytes(d_sk),
    };

    let (k_capsule, k_ciphertext) = fracture_core::commands::encrypt(encrypt_args);

    // TODO: send k_capsule, k_ciphertext, k_pk, k_verifying_pk, get s_pk back.
    let mut data = HashMap::new();
    data.insert("k_capsule", "k_capsule");
    data.insert("k_ciphertext", "k_ciphertext");
    data.insert("k_pk", "k_pk");
    data.insert("k_verifying_pk", "k_verifying_pk");

    let s_pk = Client::new()
        .post("http://127.0.0.1:8001/set_k")
        .json(&data)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let (s_sk, s_pk) = fracture_core::commands::new_account();

    // Generate the k_kfrags with s_pk.
    let grant_args = fracture_core::cli::GrantArgs {
        sender_sk: k_sk,
        receiver_pk: s_pk,
        threshold: K_THRESHOLD,
        shares: K_SHARES,
    };

    let (k_verifying_pk, k_verified_kfrags) = fracture_core::commands::grant(grant_args);

    // TODO: send the k_kfrags to the trustees.
}

#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8000,
        ..Config::debug_default()
    };

    rocket::custom(&config).mount("/", routes![index, encrypt])
}

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    plaintext: String,
}

struct MemStore {}
