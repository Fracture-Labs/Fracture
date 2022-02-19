#[macro_use]
extern crate rocket;

use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;
use reqwest::Client;
use rocket::{serde::json::Json, Config, State};
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
async fn encrypt(data: Json<EncryptData>) {
    let (d_sk, d_pk) = fracture_core::commands::new_account();
    let (k_sk, k_pk) = fracture_core::commands::new_account();

    // Create the signer for the k_kfrags.
    let (k_signer, k_verifying_pk) = fracture_core::commands::new_signer();

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

    // Send k_capsule, k_ciphertext, k_pk, k_verifying_pk to kfraas, get s_pk back.
    let mut data = HashMap::new();
    data.insert("k_capsule", hex::encode(k_capsule));
    data.insert("k_ciphertext", hex::encode(k_ciphertext));
    data.insert(
        "k_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_pk)),
    );
    data.insert(
        "k_verifying_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_verifying_pk)),
    );

    let s_pk_string = Client::new()
        .post("http://127.0.0.1:8001/set_k")
        .json(&data)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Decode the hex encoded s_pk.
    let s_pk = fracture_core::helpers::public_key_from_str(&s_pk_string).unwrap();
    // println!("S_PK: {}", &s_pk);

    // Generate the k_kfrags with s_pk.
    let grant_args = fracture_core::cli::GrantArgs {
        sender_sk: k_sk,
        receiver_pk: s_pk,
        threshold: K_THRESHOLD,
        shares: K_SHARES,
    };

    let k_verified_kfrags = fracture_core::commands::grant_with_signer(&k_signer, grant_args);

    // TODO: send the k_kfrags to the trustees.
    let mut data = HashMap::new();
    data.insert("d_capsule_cid", d_capsule_cid);
    data.insert("d_ciphertext_cid", d_ciphertext_cid);
    data.insert(
        "k_kfrag",
        hex::encode(fracture_core::helpers::verified_kfrag_to_bytes(
            k_verified_kfrags[0].clone(),
        )),
    );
    data.insert(
        "k_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_pk)),
    );
    data.insert(
        "s_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(s_pk)),
    );
    data.insert(
        "k_verifying_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_verifying_pk)),
    );

    Client::new()
        .post("http://127.0.0.1:8002/set_k_kfrags")
        .json(&data)
        .send()
        .await
        .unwrap();
}

#[post("/set_k_kfrags", data = "<data>")]
async fn set_k_kfrags(data: Json<KfragData>, memstore: &State<MemStore>) {
    let mut memstore_wg = memstore.kv.write();
    memstore_wg.insert("d_capsule_cid".to_string(), data.d_capsule_cid.clone());
    memstore_wg.insert(
        "d_ciphertext_cid".to_string(),
        data.d_ciphertext_cid.clone(),
    );
    memstore_wg.insert("k_kfrag".to_string(), data.k_kfrag.clone());
    memstore_wg.insert("k_pk".to_string(), data.k_pk.clone());
    memstore_wg.insert("s_pk".to_string(), data.s_pk.clone());
    memstore_wg.insert("k_verifying_pk".to_string(), data.k_verifying_pk.clone());
}

#[get("/status")]
async fn status(memstore: &State<MemStore>) -> Json<StatusData> {
    let memstore_rg = memstore.kv.read();

    Json(StatusData {
        k_pk: memstore_rg.get("k_pk").unwrap().clone(),
        d_capsule_cid: memstore_rg.get("d_capsule_cid").unwrap().clone(),
        d_ciphertext_cid: memstore_rg.get("d_ciphertext_cid").unwrap().clone(),
    })
}

#[cfg(feature = "client")]
#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8000,
        ..Config::debug_default()
    };

    rocket::custom(&config)
        .manage(MemStore::new())
        .mount("/", routes![index, encrypt])
}

#[cfg(feature = "trustee")]
#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8002,
        ..Config::debug_default()
    };

    rocket::custom(&config)
        .manage(MemStore::new())
        .mount("/", routes![index, set_k_kfrags, status])
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptData {
    plaintext: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KfragData {
    d_capsule_cid: String,
    d_ciphertext_cid: String,
    k_kfrag: String,
    k_pk: String,
    s_pk: String,
    k_verifying_pk: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct StatusData {
    k_pk: String,
    d_capsule_cid: String,
    d_ciphertext_cid: String,
}

struct MemStore {
    kv: Arc<RwLock<HashMap<String, String>>>,
}

impl MemStore {
    fn new() -> Self {
        MemStore {
            kv: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
