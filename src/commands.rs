use umbral_pre::*;

use crate::{
    cli::{DecryptArgs, EncryptArgs, GrantArgs, PreArgs},
    ipfs_io::{self, CIDv0},
};

pub fn new_account() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random();
    let pk = sk.public_key();

    println!("private key: {:x}", sk.to_secret_array().as_secret());
    println!("public key: {:x}", pk.to_array());

    (sk, pk)
}

pub async fn encrypt(encrypt_args: EncryptArgs) -> (CIDv0, CIDv0) {
    let (capsule, ciphertext) =
        umbral_pre::encrypt(&encrypt_args.sender_pk, &encrypt_args.plaintext.as_bytes()).unwrap();

    println!("capsule: {:x}", capsule.to_array());
    println!("ciphertext: {}", hex::encode(ciphertext.clone()));

    // Write to ipfs.
    let capsule_cid = ipfs_io::write(capsule.to_array().to_vec()).await;
    let ciphertext_cid = ipfs_io::write(ciphertext.to_vec()).await;

    (capsule_cid, ciphertext_cid)
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

pub async fn pre(pre_args: PreArgs) -> VerifiedCapsuleFrag {
    let verified_kfrag = pre_args
        .kfrag
        .verify(
            &pre_args.verifying_pk,
            Some(&pre_args.sender_pk),
            Some(&pre_args.receiver_pk),
        )
        .unwrap();

    // Read data from ipfs.
    let capsule = Capsule::from_bytes(ipfs_io::read(pre_args.capsule_cid).await).unwrap();

    // Generate the capsule fragments.
    let verified_cfrag = reencrypt(&capsule, verified_kfrag);

    println!("cfrag: {:x}", verified_cfrag.to_array());

    verified_cfrag
}

pub async fn decrypt(decrypt_args: DecryptArgs) -> Box<[u8]> {
    // Read capsule and ciphertext from ipfs.
    let capsule = Capsule::from_bytes(ipfs_io::read(decrypt_args.capsule_cid).await).unwrap();
    let ciphertext = ipfs_io::read(decrypt_args.ciphertext_cid).await;

    let verified_cfrags: Vec<VerifiedCapsuleFrag> = decrypt_args
        .cfrags
        .into_iter()
        .map(|cfrag| {
            cfrag
                .verify(
                    &capsule,
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
        &capsule,
        verified_cfrags,
        &ciphertext,
    )
    .unwrap();

    println!("{:?}", plaintext);

    plaintext
}
