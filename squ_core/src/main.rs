use clap::Parser;
use squ_core::{
    cli::{Cli, Commands::*},
    commands::{InnerPreArgs, *},
};

#[tokio::main]
async fn main() {
    match Cli::parse().command {
        Account => {
            new_account();
        }
        Encrypt(encrypt_args) => {
            let inner_encrypt_args = InnerEncryptArgs::from_encrypt_args(encrypt_args);
            encrypt(inner_encrypt_args);
        }
        Grant(grant_args) => {
            grant(grant_args);
        }
        Pre(pre_args) => {
            let inner_pre_args = InnerPreArgs::from_pre_args(pre_args).await;
            pre(inner_pre_args);
        }
        Decrypt(decrypt_args) => {
            let inner_decrypt_args = InnerDecryptArgs::from_decrypt_args(decrypt_args).await;
            decrypt(inner_decrypt_args);
        }
    }
}
