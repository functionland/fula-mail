//! Pinning service client - stores encrypted mail blobs via the existing pinning infrastructure.
//!
//! Uses the same remote pinning service that FxFiles/FxMail uses for file uploads.
//! The pinning service stores CIDs which are then replicated to RK3588 devices via IPFS cluster.

use anyhow::Result;
use reqwest::Client;

use crate::config::Config;

#[derive(Clone)]
pub struct PinningClient {
    client: Client,
    base_url: String,
    system_key: String,
}

impl PinningClient {
    pub fn new(config: &Config) -> Self {
        Self {
            client: Client::new(),
            base_url: config.pinning_service_url.clone(),
            system_key: config.pinning_system_key.clone(),
        }
    }

    /// Store an encrypted blob and pin it via the pinning service.
    /// Returns the CID of the stored content.
    ///
    /// This follows the same path as file uploads:
    /// encrypted blob -> IPFS -> pin request -> IPFS cluster replicates to devices
    pub async fn store_and_pin(&self, data: &[u8], name: &str, user_token: &str) -> Result<String> {
        // Step 1: Add block to IPFS via the pinning service's IPFS endpoint
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()));

        let resp = self.client
            .post(format!("{}/api/v0/add", self.base_url))
            .bearer_auth(user_token)
            .multipart(form)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Pinning service add failed ({}): {}", status, body);
        }

        let result: serde_json::Value = resp.json().await?;
        let cid = result["Hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No CID in pinning response"))?
            .to_string();

        // Step 2: Pin the CID (ensures replication to IPFS cluster followers)
        self.pin_cid(&cid, name, user_token).await?;

        Ok(cid)
    }

    /// Pin a CID with a given name. The pinning service distributes this to IPFS cluster
    /// which replicates to RK3588 devices.
    pub async fn pin_cid(&self, cid: &str, name: &str, user_token: &str) -> Result<()> {
        let body = serde_json::json!({
            "cid": cid,
            "name": name,
        });

        let resp = self.client
            .post(format!("{}/pins", self.base_url))
            .bearer_auth(user_token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Pin request failed ({}): {} - CID: {}", status, body, cid);
        }

        Ok(())
    }
}
