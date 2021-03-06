use fracture_core::{cli::*, commands::*, ipfs_io};
use umbral_pre::{CapsuleFrag, DeserializableFromArray, KeyFrag, SerializableToArray};

#[tokio::test]
async fn encrypt_decrypt() {
    const PLAINTEXT: &str = "Threshold is cool!";
    const THRESHOLD: usize = 1;
    const SHARES: usize = 2;

    let (sender_sk, sender_pk) = new_account();
    let (receiver_sk, receiver_pk) = new_account();

    // Encrypt the data.
    let encrypt_args = EncryptArgs {
        sender_pk,
        plaintext: String::from(PLAINTEXT),
    };

    let inner_encrypt_args = InnerEncryptArgs::from_encrypt_args(encrypt_args);
    let (capsule_bytes, ciphertext_bytes) = encrypt(inner_encrypt_args);

    // Write to ipfs.
    let capsule_cid = ipfs_io::write(capsule_bytes).await;
    let ciphertext_cid = ipfs_io::write(ciphertext_bytes).await;

    // Create the key fragments and distribute them to each proxy.
    let grant_args = GrantArgs {
        sender_sk,
        receiver_pk,
        threshold: THRESHOLD,
        shares: SHARES,
    };

    let (verifying_pk, verified_kfrags) = grant(grant_args);

    // Verified kfrags become non-verified kfrags when serialised (i.e. when sent over the network
    // from the sender to the proxies).
    let kfrags: Vec<KeyFrag> = verified_kfrags
        .iter()
        .map(|verified_kfrag| KeyFrag::from_array(&verified_kfrag.to_array()).unwrap())
        .collect();

    // N proxies perform re-encryption (PRE).
    let mut verified_cfrags = vec![];
    for kfrag in kfrags.iter().take(SHARES) {
        let pre_args = PreArgs {
            capsule_cid: capsule_cid.clone(),
            kfrag: kfrag.clone(),
            sender_pk,
            receiver_pk,
            verifying_pk,
        };

        let inner_pre_args = InnerPreArgs::from_pre_args(pre_args).await;
        let verified_cfrag = pre(inner_pre_args);

        verified_cfrags.push(verified_cfrag);
    }

    // Verified cfrags become non-verified cfrags when serialised (i.e. when sent over the network
    // from the proxies to the receiver).
    let cfrags: Vec<CapsuleFrag> = verified_cfrags
        .into_iter()
        .map(|verified_cfrag| CapsuleFrag::from_array(&verified_cfrag.to_array()).unwrap())
        .collect();

    let decrypt_args = DecryptArgs {
        capsule_cid,
        ciphertext_cid,
        cfrags,
        sender_pk,
        receiver_sk,
        receiver_pk,
        verifying_pk,
    };

    let inner_decrypt_args = InnerDecryptArgs::from_decrypt_args(decrypt_args).await;
    let plaintext = decrypt(inner_decrypt_args);

    assert_eq!(*plaintext, *PLAINTEXT.as_bytes());
}
