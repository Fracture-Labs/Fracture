#[macro_use]
extern crate rocket;

use std::{collections::HashMap, sync::Arc};

use fracture_core::{commands::*, helpers::public_key_from_str};
use parking_lot::RwLock;
use rocket::{serde::json::Json, Config, State};
use serde::{Deserialize, Serialize};
use umbral_pre::{DeserializableFromArray, PublicKey, SecretKey};

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

#[post("/set_cfrag", data = "<data>")]
async fn set_cfrag(data: Json<CfragData>, memstore: &State<MemStore>) {
    {
        let mut memstore_wg = memstore.kv.write();
        memstore_wg.insert("k_cfrag".to_string(), data.k_cfrag.clone());
        memstore_wg.insert("b_pk".to_string(), data.b_pk.clone());
    }

    // TODO: query DAO

    // Decrypt d_sk.
    let memstore_rg = memstore.kv.read();
    let inner_decrypt_args = fracture_core::commands::InnerDecryptArgs {
        capsule_bytes: hex::decode(memstore_rg.get("k_capsule").unwrap()).unwrap(),
        ciphertext: hex::decode(memstore_rg.get("k_ciphertext").unwrap()).unwrap(),
        cfrags: vec![fracture_core::helpers::capsule_frag_from_str(
            memstore_rg.get("k_cfrag").unwrap(),
        )
        .unwrap()],
        sender_pk: fracture_core::helpers::public_key_from_str(memstore_rg.get("k_pk").unwrap())
            .unwrap(),
        receiver_sk: fracture_core::helpers::secret_key_from_str(memstore_rg.get("s_sk").unwrap())
            .unwrap(),
        receiver_pk: fracture_core::helpers::public_key_from_str(memstore_rg.get("s_pk").unwrap())
            .unwrap(),
        verifying_pk: fracture_core::helpers::public_key_from_str(
            memstore_rg.get("k_verifying_pk").unwrap(),
        )
        .unwrap(),
    };

    // Decrypt the d_sk.
    let d_sk_bytes = fracture_core::commands::decrypt(inner_decrypt_args);
    let d_sk = SecretKey::from_bytes(d_sk_bytes.clone()).unwrap();

    println!("SECRET_KEY: {}", hex::encode(d_sk_bytes));

    // Generate the kfrags for the data.
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
        .mount("/", routes![index, set_k, set_cfrag])
}

#[derive(Serialize, Deserialize, Debug)]
struct SetKData {
    k_capsule: String,
    k_ciphertext: String,
    k_pk: String,
    k_verifying_pk: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CfragData {
    k_cfrag: String,
    b_pk: String,
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
