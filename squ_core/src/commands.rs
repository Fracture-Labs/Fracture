use umbral_pre::*;

use crate::{
    cli::{DecryptArgs, EncryptArgs, GrantArgs, PreArgs},
    ipfs_io::{self},
};

pub fn new_account() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random();
    let pk = sk.public_key();

    println!("private key: {:x}", sk.to_secret_array().as_secret());
    println!("public key: {:x}", pk.to_array());

    (sk, pk)
}

pub fn encrypt(encrypt_args: EncryptArgs) -> (Vec<u8>, Vec<u8>) {
    let (capsule, ciphertext) =
        umbral_pre::encrypt(&encrypt_args.sender_pk, encrypt_args.plaintext.as_bytes()).unwrap();

    println!("capsule: {:x}", capsule.to_array());
    println!("ciphertext: {}", hex::encode(ciphertext.clone()));

    (capsule.to_array().to_vec(), ciphertext.to_vec())
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

    for verified_kfrag in verified_kfrags.iter() {
        println!("kfrag: {:x}", verified_kfrag.to_array())
    }

    (verifying_pk, verified_kfrags)
}

pub struct InnerPreArgs {
    pub capsule_bytes: Vec<u8>,
    pub kfrag: KeyFrag,
    pub sender_pk: PublicKey,
    pub receiver_pk: PublicKey,
    pub verifying_pk: PublicKey,
}

impl InnerPreArgs {
    pub async fn from_pre_args(pre_args: PreArgs) -> InnerPreArgs {
        let capsule_bytes = ipfs_io::read(pre_args.capsule_cid).await;

        InnerPreArgs {
            capsule_bytes,
            kfrag: pre_args.kfrag,
            sender_pk: pre_args.sender_pk,
            receiver_pk: pre_args.receiver_pk,
            verifying_pk: pre_args.verifying_pk,
        }
    }
}

pub fn pre(inner_pre_args: InnerPreArgs) -> VerifiedCapsuleFrag {
    let verified_kfrag = inner_pre_args
        .kfrag
        .verify(
            &inner_pre_args.verifying_pk,
            Some(&inner_pre_args.sender_pk),
            Some(&inner_pre_args.receiver_pk),
        )
        .unwrap();

    // Read data from ipfs.
    let capsule = Capsule::from_bytes(&inner_pre_args.capsule_bytes).unwrap();

    // Generate the capsule fragments.
    let verified_cfrag = reencrypt(&capsule, verified_kfrag);

    println!("cfrag: {:x}", verified_cfrag.to_array());

    verified_cfrag
}

pub struct InnerDecryptArgs {
    pub capsule_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub cfrags: Vec<CapsuleFrag>,
    pub sender_pk: PublicKey,
    pub receiver_sk: SecretKey,
    pub receiver_pk: PublicKey,
    pub verifying_pk: PublicKey,
}

impl InnerDecryptArgs {
    pub async fn from_decrypt_args(decrypt_args: DecryptArgs) -> InnerDecryptArgs {
        let capsule_bytes = ipfs_io::read(decrypt_args.capsule_cid).await;
        let ciphertext = ipfs_io::read(decrypt_args.ciphertext_cid).await;

        InnerDecryptArgs {
            capsule_bytes,
            ciphertext,
            cfrags: decrypt_args.cfrags,
            sender_pk: decrypt_args.sender_pk,
            receiver_sk: decrypt_args.receiver_sk,
            receiver_pk: decrypt_args.receiver_pk,
            verifying_pk: decrypt_args.verifying_pk,
        }
    }
}

pub fn decrypt(inner_decrypt_args: InnerDecryptArgs) -> Box<[u8]> {
    // Read capsule and ciphertext from ipfs.
    let capsule = Capsule::from_bytes(inner_decrypt_args.capsule_bytes).unwrap();

    let verified_cfrags: Vec<VerifiedCapsuleFrag> = inner_decrypt_args
        .cfrags
        .into_iter()
        .map(|cfrag| {
            cfrag
                .verify(
                    &capsule,
                    &inner_decrypt_args.verifying_pk,
                    &inner_decrypt_args.sender_pk,
                    &inner_decrypt_args.receiver_pk,
                )
                .unwrap()
        })
        .collect();

    let plaintext = decrypt_reencrypted(
        &inner_decrypt_args.receiver_sk,
        &inner_decrypt_args.sender_pk,
        &capsule,
        verified_cfrags,
        &inner_decrypt_args.ciphertext,
    )
    .unwrap();

    println!("{:?}", plaintext);

    plaintext
}
