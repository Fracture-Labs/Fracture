#[macro_use]
extern crate rocket;

use std::{collections::HashMap, sync::Arc};

use fracture_core::{commands::*, helpers::public_key_from_str};
use parking_lot::RwLock;
use rocket::{serde::json::Json, Config, State};
use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, SecretKey};

#[get("/")]
fn index() -> &'static str {
    "Hello Constitute, this is Fracture KFRAAS!"
}

#[post("/set_k", data = "<data>")]
fn set_k(data: Json<SetKData>, memstore: &State<MemStore>) -> String {
    let mut memstore_wg = memstore.kv.write();
    memstore_wg.insert("k_capsule".to_string(), data.k_capsule.clone());
    memstore_wg.insert("k_ciphertext".to_string(), data.k_ciphertext.clone());
    memstore_wg.insert("k_pk".to_string(), data.k_pk.clone());
    memstore_wg.insert("k_verifying_pk".to_string(), data.k_verifying_pk.clone());

    memstore_wg.get("s_pk").unwrap().clone()
}

#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8001,
        ..Config::debug_default()
    };

    // Set the kfraas' keys.
    let (s_sk, s_pk) = fracture_core::commands::new_account();
    let memstore = MemStore::new();
    memstore.kv.write().insert(
        "s_sk".to_string(),
        hex::encode(fracture_core::helpers::sk_to_bytes(s_sk)),
    );
    memstore.kv.write().insert(
        "s_pk".to_string(),
        hex::encode(fracture_core::helpers::pk_to_bytes(s_pk)),
    );

    rocket::custom(&config)
        .manage(memstore)
        .mount("/", routes![index, set_k])
}

#[derive(Serialize, Deserialize, Debug)]
struct SetKData {
    k_capsule: String,
    k_ciphertext: String,
    k_pk: String,
    k_verifying_pk: String,
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
