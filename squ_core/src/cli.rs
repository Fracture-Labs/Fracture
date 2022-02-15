use clap::{Parser, Subcommand};
use umbral_pre::*;

use crate::ipfs_io::CIDv0;

#[derive(Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Commands {
    Account,
    Encrypt(EncryptArgs),
    Grant(GrantArgs),
    Pre(PreArgs),
    Decrypt(DecryptArgs),
}

#[derive(clap::Args)]
pub struct EncryptArgs {
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub sender_pk: PublicKey,
    #[clap(long)]
    pub plaintext: String,
}

#[derive(clap::Args)]
pub struct GrantArgs {
    #[clap(long, parse(try_from_str = secret_key_from_str))]
    pub sender_sk: SecretKey,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub receiver_pk: PublicKey,
    #[clap(long)]
    pub threshold: usize,
    #[clap(long)]
    pub shares: usize,
}

#[derive(clap::Args)]
pub struct PreArgs {
    #[clap(long)]
    pub capsule_cid: CIDv0,
    #[clap(long, parse(try_from_str = key_frag_from_str))]
    pub kfrag: KeyFrag,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub sender_pk: PublicKey,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub receiver_pk: PublicKey,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub verifying_pk: PublicKey,
}

#[derive(clap::Args)]
pub struct DecryptArgs {
    #[clap(long)]
    pub capsule_cid: CIDv0,
    #[clap(long)]
    pub ciphertext_cid: CIDv0,
    #[clap(long, parse(try_from_str = capsule_frag_from_str))]
    pub cfrags: Vec<CapsuleFrag>,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub sender_pk: PublicKey,
    #[clap(long, parse(try_from_str = secret_key_from_str))]
    pub receiver_sk: SecretKey,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub receiver_pk: PublicKey,
    #[clap(long, parse(try_from_str = public_key_from_str))]
    pub verifying_pk: PublicKey,
}

// Helpers
// TODO (nkls): error handling + dedup with macro
fn public_key_from_str(s: &str) -> Result<PublicKey, &'static str> {
    match PublicKey::from_bytes(&hex::decode(s).unwrap()) {
        Ok(pk) => Ok(pk),
        Err(_) => Err("couldn't deserialize"),
    }
}

fn secret_key_from_str(s: &str) -> Result<SecretKey, &'static str> {
    match SecretKey::from_bytes(&hex::decode(s).unwrap()) {
        Ok(sk) => Ok(sk),
        Err(_) => Err("couldn't deserialize"),
    }
}

fn key_frag_from_str(s: &str) -> Result<KeyFrag, &'static str> {
    match KeyFrag::from_bytes(&hex::decode(s).unwrap()) {
        Ok(kfrag) => Ok(kfrag),
        Err(_) => Err("couldn't deserialize"),
    }
}

fn capsule_frag_from_str(s: &str) -> Result<CapsuleFrag, &'static str> {
    match CapsuleFrag::from_bytes(&hex::decode(s).unwrap()) {
        Ok(cfrag) => Ok(cfrag),
        Err(_) => Err("couldn't deserialize"),
    }
}
