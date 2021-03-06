#[macro_use]
extern crate rocket;

use std::collections::HashMap;
#[cfg(not(feature = "proxy"))]
use std::sync::Arc;

#[cfg(not(feature = "proxy"))]
use parking_lot::RwLock;
use reqwest::Client;
#[cfg(not(feature = "proxy"))]
use rocket::State;
use rocket::{serde::json::Json, Config};
use serde::{Deserialize, Serialize};

#[get("/")]
fn index() -> &'static str {
    "Hello Constitution, this is Fracture!"
}

#[cfg(feature = "client")]
#[post("/encrypt", data = "<data>")]
async fn encrypt(data: Json<EncryptData>) {
    const K_THRESHOLD: usize = 1;
    const K_SHARES: usize = 2;

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
    let mut out_data = HashMap::new();
    out_data.insert("k_capsule", hex::encode(k_capsule.clone()));
    out_data.insert("k_ciphertext", hex::encode(k_ciphertext));
    out_data.insert(
        "k_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_pk)),
    );
    out_data.insert(
        "k_verifying_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_verifying_pk)),
    );
    out_data.insert("wallet_address", data.wallet_address.clone());
    out_data.insert("app_id", data.app_id.clone());

    let s_pk_string = Client::new()
        .post("http://127.0.0.1:8001/set_k")
        .json(&out_data)
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
    let mut out_data = HashMap::new();
    out_data.insert("d_capsule_cid", d_capsule_cid);
    out_data.insert("d_ciphertext_cid", d_ciphertext_cid);
    out_data.insert("k_capsule", hex::encode(k_capsule));
    out_data.insert(
        "d_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(d_pk)),
    );
    out_data.insert(
        "k_kfrag",
        hex::encode(fracture_core::helpers::verified_kfrag_to_bytes(
            k_verified_kfrags[0].clone(),
        )),
    );
    out_data.insert(
        "k_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_pk)),
    );
    out_data.insert(
        "s_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(s_pk)),
    );
    out_data.insert(
        "k_verifying_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(k_verifying_pk)),
    );
    out_data.insert("wallet_address", data.wallet_address.clone());
    out_data.insert("app_id", data.app_id.clone());

    Client::new()
        .post("http://127.0.0.1:8002/set_k_kfrags")
        .json(&out_data)
        .send()
        .await
        .unwrap();
}

#[cfg(feature = "client")]
#[post("/decrypt")]
async fn decrypt(memstore: &State<MemStore>) {
    // Create a new account for decryption.
    let (b_sk, b_pk) = fracture_core::commands::new_account();

    // Scope the write lock.
    {
        let mut memstore_wg = memstore.kv.write();
        memstore_wg.insert(
            "b_sk".to_string(),
            hex::encode(fracture_core::helpers::sk_to_bytes(b_sk)),
        );
        memstore_wg.insert(
            "b_pk".to_string(),
            hex::encode(fracture_core::helpers::pk_to_bytes(b_pk)),
        );
    }

    // Construct the json payload.
    let mut data = HashMap::new();
    data.insert(
        "b_pk",
        hex::encode(fracture_core::helpers::pk_to_bytes(b_pk)),
    );

    // Send request to trustee, changing decrypt state.
    Client::new()
        .post("http://127.0.0.1:8002/set_decrypt")
        .json(&data)
        .send()
        .await
        .unwrap();
}

#[cfg(feature = "client")]
#[post("/decrypt_w_cfrag", data = "<data>")]
async fn decrypt_w_cfrag(data: Json<DecryptWCfragData>, memstore: &State<MemStore>) {
    let decrypt_args = fracture_core::cli::DecryptArgs {
        capsule_cid: data.d_capsule_cid.clone(),
        ciphertext_cid: data.d_ciphertext_cid.clone(),
        cfrags: vec![fracture_core::helpers::capsule_frag_from_str(&data.d_cfrag).unwrap()],
        sender_pk: fracture_core::helpers::public_key_from_str(&data.d_pk).unwrap(),
        receiver_sk: fracture_core::helpers::secret_key_from_str(
            memstore.kv.read().get("b_sk").unwrap(),
        )
        .unwrap(),
        receiver_pk: fracture_core::helpers::public_key_from_str(
            memstore.kv.read().get("b_pk").unwrap(),
        )
        .unwrap(),
        verifying_pk: fracture_core::helpers::public_key_from_str(&data.d_verifying_pk).unwrap(),
    };

    let inner_decrypt_args =
        fracture_core::commands::InnerDecryptArgs::from_decrypt_args(decrypt_args).await;
    let plaintext = fracture_core::commands::decrypt(inner_decrypt_args);

    // println!("PLAINTEXT: {}", String::from_utf8_lossy(&plaintext));

    memstore
        .kv
        .write()
        .insert("plaintext".to_string(), hex::encode(plaintext));
}

#[cfg(feature = "client")]
#[get("/plaintext")]
async fn plaintext(memstore: &State<MemStore>) -> Json<PlaintextData> {
    Json(PlaintextData {
        plaintext: memstore.kv.read().get("plaintext").unwrap().clone(),
    })
}

//
// Trustee endpoints
//

#[cfg(feature = "trustee")]
#[post("/set_decrypt", data = "<data>")]
async fn set_decrypt(data: Json<DecryptData>, memstore: &State<MemStore>) {
    let mut memstore_wg = memstore.kv.write();
    memstore_wg.insert("can_decrypt".to_string(), "true".to_string());
    memstore_wg.insert("b_pk".to_string(), data.b_pk.clone());
}

#[cfg(feature = "trustee")]
#[post("/set_k_kfrags", data = "<data>")]
async fn set_k_kfrags(data: Json<KfragData>, memstore: &State<MemStore>) {
    let mut memstore_wg = memstore.kv.write();
    memstore_wg.insert("d_capsule_cid".to_string(), data.d_capsule_cid.clone());
    memstore_wg.insert(
        "d_ciphertext_cid".to_string(),
        data.d_ciphertext_cid.clone(),
    );
    memstore_wg.insert("d_pk".to_string(), data.d_pk.clone());
    memstore_wg.insert("k_capsule".to_string(), data.k_capsule.clone());
    memstore_wg.insert("k_kfrag".to_string(), data.k_kfrag.clone());
    memstore_wg.insert("k_pk".to_string(), data.k_pk.clone());
    memstore_wg.insert("s_pk".to_string(), data.s_pk.clone());
    memstore_wg.insert("k_verifying_pk".to_string(), data.k_verifying_pk.clone());
    memstore_wg.insert("wallet_address".to_string(), data.wallet_address.clone());
    memstore_wg.insert("app_id".to_string(), data.app_id.clone());
}

#[cfg(feature = "trustee")]
#[get("/status")]
async fn status(memstore: &State<MemStore>) -> Json<StatusData> {
    let memstore_rg = memstore.kv.read();

    Json(StatusData {
        k_pk: memstore_rg.get("k_pk").unwrap().clone(),
        d_capsule_cid: memstore_rg.get("d_capsule_cid").unwrap().clone(),
        d_ciphertext_cid: memstore_rg.get("d_ciphertext_cid").unwrap().clone(),
        can_decrypt: memstore_rg.get("can_decrypt").unwrap().clone(),
        wallet_address: memstore_rg.get("wallet_address").unwrap().clone(),
        app_id: memstore_rg.get("app_id").unwrap().clone(),
    })
}

#[cfg(feature = "trustee")]
#[post("/send_cfrag")]
async fn send_cfrag(memstore: &State<MemStore>) {
    // Generate cfrag and scope the read lock.
    let inner_pre_args = {
        let memstore_rg = memstore.kv.read();
        fracture_core::commands::InnerPreArgs {
            capsule_bytes: hex::decode(memstore_rg.get("k_capsule").unwrap()).unwrap(),
            kfrag: fracture_core::helpers::key_frag_from_str(memstore_rg.get("k_kfrag").unwrap())
                .unwrap(),
            sender_pk: fracture_core::helpers::public_key_from_str(
                memstore_rg.get("k_pk").unwrap(),
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

    let verified_k_cfrag = fracture_core::commands::pre(inner_pre_args);

    // Send the k_cfrag to the kfraas.
    let mut data = HashMap::new();
    data.insert(
        "k_cfrag",
        hex::encode(fracture_core::helpers::verified_cfrag_to_bytes(
            verified_k_cfrag,
        )),
    );
    data.insert("b_pk", memstore.kv.read().get("b_pk").unwrap().clone());

    Client::new()
        .post("http://127.0.0.1:8001/set_cfrag")
        .json(&data)
        .send()
        .await
        .unwrap();
}

#[cfg(feature = "trustee")]
#[post("/forward_d_kfrag", data = "<data>")]
async fn forward_d_kfrag(data: Json<ForwardKfragData>, memstore: &State<MemStore>) {
    // Add the cid to the data to be forwarded to the proxies.

    let out_data = {
        let memstore_rg = memstore.kv.read();

        let mut out_data = HashMap::new();
        out_data.insert(
            "d_capsule_cid",
            memstore_rg.get("d_capsule_cid").unwrap().clone(),
        );
        out_data.insert(
            "d_ciphertext_cid",
            memstore_rg.get("d_ciphertext_cid").unwrap().clone(),
        );
        out_data.insert("d_pk", memstore_rg.get("d_pk").unwrap().clone());
        out_data.insert("d_verifying_pk", data.d_verifying_pk.clone());
        out_data.insert("d_kfrag", data.d_kfrag.clone());
        out_data.insert("b_pk", memstore_rg.get("b_pk").unwrap().clone());

        out_data
    };

    // Send the data to the proxies.
    Client::new()
        .post("http://127.0.0.1:8003/set_d_cfrag")
        .json(&out_data)
        .send()
        .await
        .unwrap();
}

//
// Proxy
//

#[cfg(feature = "proxy")]
#[post("/set_d_cfrag", data = "<data>")]
async fn set_d_cfrag(data: Json<SetCfragData>) {
    // TODO: store the d_kfrag, check the threshold, if all fragements have been received, generate
    // cfrags and forward them to Bob (in this case Freddie).

    let pre_args = fracture_core::cli::PreArgs {
        capsule_cid: data.d_capsule_cid.clone(),
        kfrag: fracture_core::helpers::key_frag_from_str(&data.d_kfrag).unwrap(),
        sender_pk: fracture_core::helpers::public_key_from_str(&data.d_pk).unwrap(),
        receiver_pk: fracture_core::helpers::public_key_from_str(&data.b_pk).unwrap(),
        verifying_pk: fracture_core::helpers::public_key_from_str(&data.d_verifying_pk).unwrap(),
    };

    let inner_pre_args = fracture_core::commands::InnerPreArgs::from_pre_args(pre_args).await;
    let d_verified_cfrag = fracture_core::commands::pre(inner_pre_args);

    // Send the cfrag to the decryptor, in this case Freddie.
    let mut out_data = HashMap::new();
    out_data.insert("d_capsule_cid", data.d_capsule_cid.clone());
    out_data.insert("d_ciphertext_cid", data.d_ciphertext_cid.clone());
    out_data.insert("d_pk", data.d_pk.clone());
    out_data.insert("d_verifying_pk", data.d_verifying_pk.clone());
    out_data.insert(
        "d_cfrag",
        hex::encode(fracture_core::helpers::verified_cfrag_to_bytes(
            d_verified_cfrag,
        )),
    );
    Client::new()
        .post("http://127.0.0.1:8000/decrypt_w_cfrag")
        .json(&out_data)
        .send()
        .await
        .unwrap();
}

#[cfg(feature = "client")]
#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8000,
        ..Config::debug_default()
    };

    rocket::custom(&config).manage(MemStore::new()).mount(
        "/",
        routes![index, encrypt, decrypt, decrypt_w_cfrag, plaintext],
    )
}

#[cfg(feature = "trustee")]
#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8002,
        ..Config::debug_default()
    };

    let memstore = MemStore::new();
    memstore
        .kv
        .write()
        .insert("can_decrypt".to_string(), "false".to_string());

    rocket::custom(&config).manage(memstore).mount(
        "/",
        routes![
            index,
            set_k_kfrags,
            status,
            set_decrypt,
            send_cfrag,
            forward_d_kfrag
        ],
    )
}

#[cfg(feature = "proxy")]
#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8003,
        ..Config::debug_default()
    };

    rocket::custom(&config).mount("/", routes![index, set_d_cfrag])
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptData {
    plaintext: String,
    wallet_address: String,
    app_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KfragData {
    d_capsule_cid: String,
    d_ciphertext_cid: String,
    d_pk: String,
    k_capsule: String,
    k_kfrag: String,
    k_pk: String,
    s_pk: String,
    k_verifying_pk: String,
    wallet_address: String,
    app_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct StatusData {
    k_pk: String,
    d_capsule_cid: String,
    d_ciphertext_cid: String,
    can_decrypt: String,
    wallet_address: String,
    app_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptData {
    b_pk: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ForwardKfragData {
    d_verifying_pk: String,
    d_kfrag: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SetCfragData {
    d_capsule_cid: String,
    // TODO: this should probably not get sent to the proxies here but rather straight to
    // bob.
    d_ciphertext_cid: String,
    d_pk: String,
    d_verifying_pk: String,
    d_kfrag: String,
    b_pk: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptWCfragData {
    d_capsule_cid: String,
    d_ciphertext_cid: String,
    d_pk: String,
    d_verifying_pk: String,
    d_cfrag: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PlaintextData {
    plaintext: String,
}

#[cfg(not(feature = "proxy"))]
struct MemStore {
    kv: Arc<RwLock<HashMap<String, String>>>,
}

#[cfg(not(feature = "proxy"))]
impl MemStore {
    fn new() -> Self {
        MemStore {
            kv: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
