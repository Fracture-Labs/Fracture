use umbral_pre::*;

pub struct ShareableData {
    pub capsule: Capsule,
    pub ciphertext: Box<[u8]>,
}

impl ShareableData {
    fn new(capsule: Capsule, ciphertext: Box<[u8]>) -> Self {
        Self {
            capsule,
            ciphertext,
        }
    }
}

pub struct Sender {
    sk: SecretKey,
    pk: PublicKey,
    signer: Signer,
    verifying_pk: PublicKey,
}

impl Sender {
    pub fn new() -> Self {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        let signer = Signer::new(SecretKey::random());
        let verifying_pk = signer.verifying_key();

        Self {
            sk,
            pk,
            signer,
            verifying_pk,
        }
    }

    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    pub fn verifying_pk(&self) -> PublicKey {
        self.verifying_pk
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> ShareableData {
        let (capsule, ciphertext) = encrypt(&self.pk, plaintext).unwrap();

        ShareableData::new(capsule, ciphertext)
    }

    pub fn verified_kfrags(
        &self,
        receiver_pk: &PublicKey,
        threshold: usize,
        shares: usize,
    ) -> Box<[VerifiedKeyFrag]> {
        const SIGN_DELEGATING_KEY: bool = true;
        const SIGN_RECEIVING_KEY: bool = true;

        generate_kfrags(
            &self.sk,
            receiver_pk,
            &self.signer,
            threshold,
            shares,
            SIGN_DELEGATING_KEY,
            SIGN_RECEIVING_KEY,
        )
    }
}

pub struct Receiver {
    sk: SecretKey,
    pk: PublicKey,
}

impl Receiver {
    pub fn new() -> Self {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        Self { sk, pk }
    }

    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    pub fn verify_and_decrypt(
        &self,
        shareable_data: ShareableData,
        cfrags: Vec<CapsuleFrag>,
        verifying_pk: &PublicKey,
        sender_pk: &PublicKey,
    ) -> Box<[u8]> {
        let verified_cfrags: Vec<VerifiedCapsuleFrag> = cfrags
            .into_iter()
            .map(|cfrag| {
                cfrag
                    .verify(&shareable_data.capsule, verifying_pk, sender_pk, &self.pk)
                    .unwrap()
            })
            .collect();

        decrypt_reencrypted(
            &self.sk,
            &sender_pk,
            &shareable_data.capsule,
            verified_cfrags,
            &shareable_data.ciphertext,
        )
        .unwrap()
    }
}

pub struct Ursula {
    capsule: Capsule,
    kfrag: KeyFrag,
    sender_pk: PublicKey,
    receiver_pk: PublicKey,
    verifying_pk: PublicKey,
}

impl Ursula {
    pub fn new(
        capsule: Capsule,
        kfrag: KeyFrag,
        sender_pk: PublicKey,
        receiver_pk: PublicKey,
        verifying_pk: PublicKey,
    ) -> Self {
        Self {
            capsule,
            kfrag,
            sender_pk,
            receiver_pk,
            verifying_pk,
        }
    }

    pub fn verify_and_reencrypt(&self) -> VerifiedCapsuleFrag {
        let verified_kfrag = self
            .kfrag
            .clone()
            .verify(
                &self.verifying_pk,
                Some(&self.sender_pk),
                Some(&self.receiver_pk),
            )
            .unwrap();

        reencrypt(&self.capsule, verified_kfrag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let plaintext = b"Hello world!";

        let sender = Sender::new();
        let receiver = Receiver::new();

        let shareable_data = sender.encrypt(plaintext);

        let threshold = 2;
        let shares = 3;
        let verified_kfrags = sender.verified_kfrags(&receiver.pk(), threshold, shares);

        // Simulate network ser/de Alice -> Ursulas.
        let kfrag0 = KeyFrag::from_array(&verified_kfrags[0].to_array()).unwrap();
        let kfrag1 = KeyFrag::from_array(&verified_kfrags[1].to_array()).unwrap();

        let ursula0 = Ursula::new(
            shareable_data.capsule,
            kfrag0,
            sender.pk(),
            receiver.pk(),
            sender.verifying_pk(),
        );

        let ursula1 = Ursula::new(
            shareable_data.capsule,
            kfrag1,
            sender.pk(),
            receiver.pk(),
            sender.verifying_pk(),
        );

        let verified_cfrag0 = ursula0.verify_and_reencrypt();
        let verified_cfrag1 = ursula1.verify_and_reencrypt();

        // Simulate network ser/de Ursulas -> Bob.
        let cfrag0 = CapsuleFrag::from_array(&verified_cfrag0.to_array()).unwrap();
        let cfrag1 = CapsuleFrag::from_array(&verified_cfrag1.to_array()).unwrap();

        let bytes = receiver.verify_and_decrypt(
            shareable_data,
            vec![cfrag0, cfrag1],
            &sender.verifying_pk(),
            &sender.pk(),
        );

        assert_eq!(&bytes as &[u8], plaintext);
    }
}
