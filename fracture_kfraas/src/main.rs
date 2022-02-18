#[macro_use]
extern crate rocket;

use fracture_core::{cli::public_key_from_str, commands::*};
use rocket::{serde::json::Json, Config};
use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, SecretKey};

#[get("/")]
fn index() -> &'static str {
    "Hello Constitution, this is Fracture KFRAAS!"
}

#[post("/set_k", data = "<data>")]
fn set_k(data: Json<SetKData>) -> String {
    String::from("Dude, this is the s_pk!")
}

#[launch]
fn rocket() -> _ {
    let config = Config {
        port: 8001,
        ..Config::debug_default()
    };

    rocket::custom(&config).mount("/", routes![index, set_k])
}

#[derive(Serialize, Deserialize, Debug)]
struct SetKData {
    k_capsule: String,
    k_ciphertext: String,
    k_pk: String,
    k_verifying_pk: String,
}
