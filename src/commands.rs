use umbral_pre::*;

use crate::cli::{DecryptArgs, EncryptArgs, GrantArgs, PreArgs};

pub fn new_account() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random();
    let pk = sk.public_key();

    println!("private key: {:x}", sk.to_secret_array().as_secret());
    println!("public key: {:x}", pk.to_array());

    (sk, pk)
}

pub fn encrypt(encrypt_args: EncryptArgs) -> (Capsule, Box<[u8]>) {
    let (capsule, ciphertext) =
        umbral_pre::encrypt(&encrypt_args.sender_pk, &encrypt_args.plaintext.as_bytes()).unwrap();

    println!("capsule: {:x}", capsule.to_array());
    println!("ciphertext: {}", hex::encode(ciphertext.clone()));

    (capsule, ciphertext)
}

pub fn grant(grant_args: GrantArgs) -> (PublicKey, Box<[VerifiedKeyFrag]>) {
    // Create a new signer, this can't be serialised for security reasons.
    let signer = umbral_pre::Signer::new(SecretKey::random());
    let verifying_pk = signer.verifying_key();

    println!("verifying public key: {:x}", verifying_pk.to_array());

    let verified_kfrags = generate_kfrags(
        &grant_args.sender_sk,
        &grant_args.receiver_pk,
        &signer,
        grant_args.threshold,
        grant_args.shares,
        true,
        true,
    );

    for verified_kfrag in verified_kfrags.into_iter() {
        println!("kfrag: {:x}", verified_kfrag.to_array())
    }

    (verifying_pk, verified_kfrags)
}

pub fn pre(pre_args: PreArgs) -> VerifiedCapsuleFrag {
    let verified_kfrag = pre_args
        .kfrag
        .verify(
            &pre_args.verifying_pk,
            Some(&pre_args.sender_pk),
            Some(&pre_args.receiver_pk),
        )
        .unwrap();
    let verified_cfrag = reencrypt(&pre_args.capsule, verified_kfrag);

    println!("cfrag: {:x}", verified_cfrag.to_array());

    verified_cfrag
}

pub fn decrypt(decrypt_args: DecryptArgs) -> Box<[u8]> {
    let verified_cfrags: Vec<VerifiedCapsuleFrag> = decrypt_args
        .cfrags
        .into_iter()
        .map(|cfrag| {
            cfrag
                .verify(
                    &decrypt_args.capsule,
                    &decrypt_args.verifying_pk,
                    &decrypt_args.sender_pk,
                    &decrypt_args.receiver_pk,
                )
                .unwrap()
        })
        .collect();

    let plaintext = decrypt_reencrypted(
        &decrypt_args.receiver_sk,
        &decrypt_args.sender_pk,
        &decrypt_args.capsule,
        verified_cfrags,
        // Todo (nkls): ciphertext should be retreived from ipfs and not necessarily hex encoded.
        &hex::decode(&decrypt_args.ciphertext).unwrap(),
    )
    .unwrap();

    println!("{:?}", plaintext);

    plaintext
}
