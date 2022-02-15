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
            encrypt(encrypt_args).await;
        }
        Grant(grant_args) => {
            grant(grant_args);
        }
        Pre(pre_args) => {
            let inner_pre_args = InnerPreArgs::from_pre_args(pre_args).await;
            pre(inner_pre_args).await;
        }
        Decrypt(decrypt_args) => {
            decrypt(decrypt_args).await;
        }
    }
}
