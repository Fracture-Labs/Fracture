use fracture_core::{cli::public_key_from_str, commands::*};
use umbral_pre::{PublicKey, SecretKey};
use warp::{http::Response, hyper::Body, Filter};

mod endpoints;
use endpoints::encrypt::{EncryptReply, EncryptRequest};

struct KeyPair((SecretKey, PublicKey));

impl warp::Reply for KeyPair {
    fn into_response(self) -> Response<Body> {
        Response::default()
    }
}

#[tokio::main]
async fn main() {
    // let account = warp::post()
    //     .and(warp::path("account"))
    //     .map(|| new_account());

    let encrypt = warp::post()
        .and(warp::path("encrypt"))
        .and(warp::body::json())
        .map(|encrypt_request: EncryptRequest| {
            let sender_pk = public_key_from_str(&encrypt_request.sender_pk).unwrap();
            let (capsule_bytes, ciphertext) = encrypt(InnerEncryptArgs {
                sender_pk,
                plaintext: encrypt_request.plaintext.as_bytes().to_vec(),
            });
            warp::reply::json(&EncryptReply {
                capsule_bytes,
                ciphertext,
            })
        });

    // let grant = warp::post()
    //     .and(warp::path("grant"))
    //     .map(|grant_args| grant(grant_args));
    // let pre = warp::post()
    //     .and(warp::path("pre"))
    //     .map(|pre_args| pre(pre_args));
    // let decrypt = warp::post()
    //     .and(warp::path("decrypt"))
    //     .map(|decrypt_args| decrypt(decrypt_args));

    warp::serve(encrypt).run(([127, 0, 0, 1], 3030)).await;
}
