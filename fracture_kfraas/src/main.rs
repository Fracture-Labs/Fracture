#[macro_use]
extern crate rocket;

use std::{collections::HashMap, sync::Arc};

const D_THRESHOLD: usize = 1;
const D_SHARES: usize = 2;

use algonaut_client::algod::v2::Client as AlgoClient;
use fracture_core::{commands::*, helpers::public_key_from_str};
use parking_lot::RwLock;
use reqwest::Client;
use rocket::{serde::json::Json, Config, State};
use serde::{Deserialize, Serialize};
use umbral_pre::{DeserializableFromArray, PublicKey, SecretKey};

const ALGOD_URL: &str = "http://localhost:4001";
const ALGOD_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    memstore_wg.insert("wallet_address".to_string(), data.wallet_address.clone());
    memstore_wg.insert("app_id".to_string(), data.app_id.clone());

    memstore_wg.get("s_pk").unwrap().clone()
}

#[post("/set_cfrag", data = "<data>")]
async fn set_cfrag(data: Json<CfragData>, memstore: &State<MemStore>) {
    {
        let mut memstore_wg = memstore.kv.write();
        memstore_wg.insert("k_cfrag".to_string(), data.k_cfrag.clone());
        memstore_wg.insert("b_pk".to_string(), data.b_pk.clone());
    }
    let wallet_address = memstore.kv.read().get("wallet_address").unwrap().clone();
    let app_id = memstore.kv.read().get("app_id").unwrap().clone();

    let mut approved = true;
    let algo_client = AlgoClient::new(ALGOD_URL, ALGOD_TOKEN).unwrap();

    let account_state = algo_client.account_information(&wallet_address).await;
    match account_state {
        Ok(account) => {
            if let Some(apps_local_state) = account.apps_local_state {
                for state in apps_local_state {
                    if state.id.to_string() == app_id {
                        let mut approvals = 0u64;
                        let mut threshold = 0u64;
                        for tealkv in state.key_value {
                            // base64 encoded threshold
                            if tealkv.key == "VGhyZXNob2xk" {
                                threshold = tealkv.value.uint;
                            }
                            // base64 encoded approvals
                            if tealkv.key == "QXBwcm92ZWQ=" {
                                approvals = tealkv.value.uint;
                            }
                        }
                        if approvals >= threshold {
                            approved = true
                        }
                    }
                }
            } else {
                println!("Account does not have app local state")
            }
        }
        Err(err) => println!("error from blockchain: {}", err),
    }

    assert!(approved);

    // Decrypt d_sk.
    let inner_decrypt_args = {
        let memstore_rg = memstore.kv.read();
        fracture_core::commands::InnerDecryptArgs {
            capsule_bytes: hex::decode(memstore_rg.get("k_capsule").unwrap()).unwrap(),
            ciphertext: hex::decode(memstore_rg.get("k_ciphertext").unwrap()).unwrap(),
            cfrags: vec![fracture_core::helpers::capsule_frag_from_str(
                memstore_rg.get("k_cfrag").unwrap(),
            )
            .unwrap()],
            sender_pk: fracture_core::helpers::public_key_from_str(
                memstore_rg.get("k_pk").unwrap(),
            )
            .unwrap(),
            receiver_sk: fracture_core::helpers::secret_key_from_str(
                memstore_rg.get("s_sk").unwrap(),
            )
            .unwrap(),
            receiver_pk: fracture_core::helpers::public_key_from_str(
                memstore_rg.get("s_pk").unwrap(),
            )
            .unwrap(),
            verifying_pk: fracture_core::helpers::public_key_from_str(
                memstore_rg.get("k_verifying_pk").unwrap(),
            )
            .unwrap(),
        }
    };

    // Decrypt the d_sk.
    let d_sk_bytes = fracture_core::commands::decrypt(inner_decrypt_args);
    let d_sk = SecretKey::from_bytes(d_sk_bytes.clone()).unwrap();

    println!("SECRET_KEY: {}", hex::encode(d_sk_bytes));

    // Generate the kfrags for the data and send to trustees.
    let grant_args = fracture_core::cli::GrantArgs {
        sender_sk: d_sk,
        receiver_pk: fracture_core::helpers::public_key_from_str(
            memstore.kv.read().get("b_pk").unwrap(),
        )
        .unwrap(),
        threshold: D_THRESHOLD,
        shares: D_SHARES,
    };

    let (d_verifying_pk, d_verified_kfrags) = fracture_core::commands::grant(grant_args);

    // TODO: ideally we'd want to send one kfrag per trustees, that would then forward them. This implies
    // the D_SHARES should correspond to the number of trustees. For this POC, we're forwarding one
    // and assuming a perfect network.
    let mut data = HashMap::new();
    data.insert(
        "d_verifying_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(d_verifying_pk)),
    );
    data.insert(
        "d_kfrag",
        hex::encode(fracture_core::helpers::verified_kfrag_to_bytes(
            d_verified_kfrags[0].clone(),
        )),
    );

    Client::new()
        .post("http://127.0.0.1:8002/forward_d_kfrag")
        .json(&data)
        .send()
        .await
        .unwrap();
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
    wallet_address: String, // Freddie's Address string
    app_id: String,
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
