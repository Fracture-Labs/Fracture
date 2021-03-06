use fracture_core::{
    cli::*,
    commands,
    ipfs_io::{self, CIDv0},
};
use umbral_pre::*;

#[tokio::test]
async fn e2e() {
    const PLAINTEXT: &str = "Threshold is cool!";

    const D_THRESHOLD: usize = 1;
    const D_SHARES: usize = 2;

    const K_THRESHOLD: usize = 1;
    const K_SHARES: usize = 2;

    // Web of trustees create keypairs and share the public key with Freddie.
    let mut trustee0 = Trustee {
        kp: commands::new_account(),
        capsule_cid: None,
        ciphertext_cid: None,
        k_capsule: None,
        k_kfrag: None,
        k_pk: None,
        s_pk: None,
        k_verifying_pk: None,
    };

    let mut trustee1 = Trustee {
        kp: commands::new_account(),
        capsule_cid: None,
        ciphertext_cid: None,
        k_capsule: None,
        k_kfrag: None,
        k_pk: None,
        s_pk: None,
        k_verifying_pk: None,
    };

    // Freddie generates two sets of keys.
    let mut freddie = Freddie {
        d_kp: Some(commands::new_account()),
        k_kp: Some(commands::new_account()),
        s_pk: None,
        // Trustees pks are shared with Freddie.
        t_pks: Some(vec![trustee0.kp.1, trustee1.kp.1]),
    };

    // FractureAAS generates a keypair...
    let mut fracture_aas = FractureAAS {
        kp: commands::new_account(),
        k_capsule: None,
        k_ciphertext: None,
        k_pk: None,
        k_verifying_pk: None,
        d_pk: None,
        t_pks: None,
        b_pk: None,
    };
    // ...and sends the public key to Freddie.
    freddie.s_pk = Some(fracture_aas.kp.1);

    // Freddie encrypts the sensitive data and stores it on ipfs.
    let inner_encrypt_args = commands::InnerEncryptArgs {
        sender_pk: freddie.d_kp.clone().unwrap().1,
        plaintext: PLAINTEXT.as_bytes().to_vec(),
    };

    let (d_capsule, d_ciphertext) = commands::encrypt(inner_encrypt_args);

    let d_capsule_cid = ipfs_io::write(d_capsule.clone()).await;
    let d_ciphertext_cid = ipfs_io::write(d_ciphertext.clone()).await;

    // The CIDs get sent to the trustees.
    trustee0.capsule_cid = Some(d_capsule_cid.clone());
    trustee1.capsule_cid = Some(d_capsule_cid.clone());

    trustee0.ciphertext_cid = Some(d_ciphertext_cid.clone());
    trustee1.ciphertext_cid = Some(d_ciphertext_cid.clone());

    trustee0.k_pk = Some(freddie.k_kp.clone().unwrap().1);
    trustee1.k_pk = Some(freddie.k_kp.clone().unwrap().1);

    trustee0.s_pk = freddie.s_pk.clone();
    trustee1.s_pk = freddie.s_pk.clone();

    // Freddie encrypts the secret key used for the data encryption.
    let encrypt_args = commands::InnerEncryptArgs {
        sender_pk: freddie.k_kp.clone().unwrap().1,
        plaintext: freddie
            .d_kp
            .clone()
            .unwrap()
            .0
            .to_secret_array()
            .as_secret()
            .to_vec(),
    };

    let (k_capsule, k_ciphertext) = commands::encrypt(encrypt_args);

    // The k_capsule and k_ciphertext get sent to the FractureAAS.
    fracture_aas.k_capsule = Some(k_capsule.clone());
    fracture_aas.k_ciphertext = Some(k_ciphertext);
    fracture_aas.k_pk = Some(freddie.k_kp.clone().unwrap().1);

    // Generate the k_kfrags with s_pk.
    let grant_args = GrantArgs {
        sender_sk: freddie.k_kp.clone().unwrap().0,
        receiver_pk: freddie.s_pk.clone().unwrap(),
        threshold: K_THRESHOLD,
        shares: K_SHARES,
    };

    let (k_verifying_pk, k_verified_kfrags) = commands::grant(grant_args);

    // Send the k_kfrags to the trustees with the k_verifying_pk.
    // We simulate the ser/de for the kfrags.
    trustee0.k_capsule = Some(k_capsule.clone());
    trustee1.k_capsule = Some(k_capsule);

    trustee0.k_kfrag = Some(KeyFrag::from_array(&k_verified_kfrags[0].to_array()).unwrap());
    trustee1.k_kfrag = Some(KeyFrag::from_array(&k_verified_kfrags[1].to_array()).unwrap());

    trustee1.k_verifying_pk = Some(k_verifying_pk);
    trustee0.k_verifying_pk = Some(k_verifying_pk);

    // Freddie sends a map of d_pk to t_pks to the FractureAAS...
    fracture_aas.d_pk = Some(freddie.d_kp.clone().unwrap().1);
    fracture_aas.t_pks = freddie.t_pks.clone();
    //... along with the k_verifying_pk.
    fracture_aas.k_verifying_pk = Some(k_verifying_pk);

    //
    // === Freddie is ready to reveal ===
    //

    // Note: at this point freddie only knows who his trustees are, nothing more.
    // drop(freddie);

    // Bob shares his pk with Freddie, freddie requests that his trustees generate the cfrags to
    // decrypt the d_sk.
    let (b_sk, b_pk) = commands::new_account();

    // The trustees notify the Fracture DAO to update the state of the FractureAAS to allow it to generate the
    // kfrags for the data based on bob's pk.

    // The trustees generate the cfrags to decrypt the d_sk.
    let inner_pre_args = commands::InnerPreArgs {
        capsule_bytes: trustee0.k_capsule.unwrap(),
        kfrag: trustee0.k_kfrag.clone().unwrap(),
        sender_pk: trustee0.k_pk.unwrap(),
        receiver_pk: trustee0.s_pk.unwrap(),
        verifying_pk: trustee0.k_verifying_pk.unwrap(),
    };

    let verified_cfrag = commands::pre(inner_pre_args);

    // The trustees send the cfrags to the FractureAAS and it decrypts the d_sk. They also send
    // bob's pk.
    fracture_aas.b_pk = Some(b_pk);
    let cfrag = CapsuleFrag::from_array(&verified_cfrag.to_array()).unwrap();

    let inner_decrypt_args = commands::InnerDecryptArgs {
        capsule_bytes: fracture_aas.k_capsule.unwrap(),
        ciphertext: fracture_aas.k_ciphertext.unwrap(),
        cfrags: vec![cfrag],
        sender_pk: fracture_aas.k_pk.unwrap(),
        receiver_sk: fracture_aas.kp.clone().0,
        receiver_pk: fracture_aas.kp.clone().1,
        verifying_pk: fracture_aas.k_verifying_pk.unwrap(),
    };

    // Decrypt the d_sk.
    let d_sk_bytes = commands::decrypt(inner_decrypt_args);
    let d_sk = SecretKey::from_bytes(d_sk_bytes).unwrap();

    // FractureAAS generates the kfrags for the data using the secret key and nukes the key.
    let grant_args = GrantArgs {
        sender_sk: d_sk,
        receiver_pk: fracture_aas.b_pk.unwrap(),
        threshold: D_THRESHOLD,
        shares: D_SHARES,
    };

    let (d_verifying_pk, d_verified_kfrags) = commands::grant(grant_args);

    // Send the kfrags to the proxies.
    let d_kfrag = KeyFrag::from_array(&d_verified_kfrags[0].to_array()).unwrap();

    // The proxies generate the cfrags to decrypt the plaintext.
    // Q: how do they get the capsule CID, the server can't be trusted with that data.
    let pre_args = PreArgs {
        capsule_cid: d_capsule_cid.clone(),
        kfrag: d_kfrag,
        sender_pk: fracture_aas.d_pk.clone().unwrap(),
        receiver_pk: b_pk,
        verifying_pk: d_verifying_pk,
    };

    let inner_pre_args = commands::InnerPreArgs::from_pre_args(pre_args).await;
    let d_verified_cfrag = commands::pre(inner_pre_args);

    // Bob decrypts the data from the cfrags.
    let d_cfrag = CapsuleFrag::from_array(&d_verified_cfrag.to_array()).unwrap();

    // Q: where does bob get freddie's public key from?
    let d_pk = fracture_aas.d_pk.unwrap();
    // Q: where does bob get the ciphertext CID from?
    // These issues go away if freddie's web of trust also decrypts the data. Otherwise the server
    // could encrypt false data with freddie's secret key, the only mitigation is the capsule
    // checks done by the proxies because they get the CID from freddie directly.
    let decrypt_args = DecryptArgs {
        capsule_cid: d_capsule_cid,
        ciphertext_cid: d_ciphertext_cid,
        cfrags: vec![d_cfrag],
        sender_pk: d_pk,
        receiver_sk: b_sk,
        receiver_pk: b_pk,
        verifying_pk: d_verifying_pk,
    };

    let inner_decrypt_args = commands::InnerDecryptArgs::from_decrypt_args(decrypt_args).await;
    let plaintext = commands::decrypt(inner_decrypt_args);

    assert_eq!(*plaintext, *PLAINTEXT.as_bytes());
}

struct Freddie {
    d_kp: Option<(SecretKey, PublicKey)>,
    k_kp: Option<(SecretKey, PublicKey)>,
    s_pk: Option<PublicKey>,
    t_pks: Option<Vec<PublicKey>>,
}

struct Trustee {
    kp: (SecretKey, PublicKey),
    capsule_cid: Option<CIDv0>,
    ciphertext_cid: Option<CIDv0>,
    k_capsule: Option<Vec<u8>>,
    k_kfrag: Option<KeyFrag>,
    k_pk: Option<PublicKey>,
    s_pk: Option<PublicKey>,
    k_verifying_pk: Option<PublicKey>,
}

struct FractureAAS {
    kp: (SecretKey, PublicKey),
    k_capsule: Option<Vec<u8>>,
    k_ciphertext: Option<Vec<u8>>,
    // This should be a map of d_pk to t_pks.
    d_pk: Option<PublicKey>,
    k_pk: Option<PublicKey>,
    k_verifying_pk: Option<PublicKey>,
    t_pks: Option<Vec<PublicKey>>,
    b_pk: Option<PublicKey>,
}
