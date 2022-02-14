use clap::Parser;
use umbral_ipfs::{
    cli::{Cli, Commands::*},
    commands::*,
};

#[tokio::main]
async fn main() {
    match Cli::parse().command {
        Account => {
            new_account();
        }
        Encrypt(encrypt_args) => {
            encrypt(encrypt_args).await;
        }
        Grant(grant_args) => {
            grant(grant_args);
        }
        Pre(pre_args) => {
            pre(pre_args).await;
        }
        Decrypt(decrypt_args) => {
            decrypt(decrypt_args).await;
        }
    }
}
