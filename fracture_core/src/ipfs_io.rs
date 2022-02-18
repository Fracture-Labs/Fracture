use reqwest::{multipart::Part, Client};
use serde::{Deserialize, Serialize};

pub type CIDv0 = String;

#[derive(Serialize, Deserialize)]
pub struct AddResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hash")]
    hash: CIDv0,
    #[serde(rename = "Size")]
    size: String,
}

pub async fn write(bytes: Vec<u8>) -> CIDv0 {
    let form = reqwest::multipart::Form::new().part("arg", Part::bytes(bytes));

    let data = Client::new()
        .post("http://127.0.0.1:5001/api/v0/add")
        // .header("Content-Type", "multipart/form-data")
        .multipart(form)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let add_response: AddResponse = serde_json::from_str(&data).unwrap();

    add_response.hash
}

pub async fn read(cid: CIDv0) -> Vec<u8> {
    Client::new()
        .post(format!("http://127.0.0.1:5001/api/v0/cat?arg={}", cid))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec()
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
