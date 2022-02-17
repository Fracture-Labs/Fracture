use std::io::Cursor;

use futures::TryStreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};

pub type CIDv0 = String;

pub async fn write(bytes: Vec<u8>) -> CIDv0 {
    let client = IpfsClient::default();
    let data = Cursor::new(bytes);

    match client.add(data).await {
        Ok(res) => res.hash,
        Err(e) => panic!("error adding file: {}", e),
    }
}

pub async fn read(cid: CIDv0) -> Vec<u8> {
    let client = IpfsClient::default();

    match client
        .cat(&cid)
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
    {
        Ok(res) => res,
        Err(e) => panic!("error getting CID: {}", e),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn writes_to_ipfs() {
        let res = write("hello world".as_bytes().to_vec()).await;
        assert_eq!("Qmf412jQZiuVUtdgnB36FXFX7xg5V6KEbSJ4dpQuhkLyfD", res)
    }

    #[tokio::test]
    async fn reads_from_ipfs() {
        let content = read("Qmf412jQZiuVUtdgnB36FXFX7xg5V6KEbSJ4dpQuhkLyfD".to_string()).await;
        assert_eq!("hello world", String::from_utf8(content).as_ref().unwrap());
    }
}
