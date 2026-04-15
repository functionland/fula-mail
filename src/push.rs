//! Push notification delivery for new mail arrival (Path A trigger).
//!
//! When inbound mail is queued for Path A pickup, the client needs to know
//! there's mail to fetch before the TTL expires. Push notifications solve this.
//!
//! Currently supports:
//! - **FCM** (Firebase Cloud Messaging) HTTP v1 API — Android and cross-platform
//! - **APNs** (Apple Push Notification service) — placeholder for future implementation

use anyhow::Result;
use serde::Deserialize;

/// FCM push notification client using HTTP v1 API.
/// Requires a Google service account key JSON file.
pub struct PushClient {
    http: reqwest::Client,
    fcm: Option<FcmConfig>,
}

struct FcmConfig {
    project_id: String,
    client_email: String,
    private_key: String,
    /// Cached access token + expiry
    token: tokio::sync::RwLock<Option<CachedToken>>,
}

struct CachedToken {
    access_token: String,
    expires_at: std::time::Instant,
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    project_id: String,
    client_email: String,
    private_key: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl PushClient {
    pub fn new(fcm_key_path: Option<&std::path::Path>) -> Self {
        let fcm = fcm_key_path.and_then(|path| {
            match std::fs::read_to_string(path) {
                Ok(json) => {
                    match serde_json::from_str::<ServiceAccountKey>(&json) {
                        Ok(key) => {
                            tracing::info!("FCM push notifications enabled (project: {})", key.project_id);
                            Some(FcmConfig {
                                project_id: key.project_id,
                                client_email: key.client_email,
                                private_key: key.private_key,
                                token: tokio::sync::RwLock::new(None),
                            })
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse FCM service account key: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read FCM key file {:?}: {}", path, e);
                    None
                }
            }
        });

        Self {
            http: reqwest::Client::new(),
            fcm,
        }
    }

    /// Send a push notification for new mail arrival.
    /// The notification contains the queue_id so the client can fetch the message.
    pub async fn notify_new_mail(
        &self,
        push_token: &str,
        platform: &str,
        queue_id: &str,
        sender: &str,
        subject: Option<&str>,
    ) -> Result<()> {
        match platform {
            "fcm" | "android" => self.send_fcm(push_token, queue_id, sender, subject).await,
            "apns" | "ios" => {
                tracing::warn!("APNs push not yet implemented, skipping notification for queue_id={}", queue_id);
                Ok(())
            }
            _ => {
                tracing::warn!("Unknown push platform '{}', skipping", platform);
                Ok(())
            }
        }
    }

    async fn send_fcm(
        &self,
        device_token: &str,
        queue_id: &str,
        sender: &str,
        subject: Option<&str>,
    ) -> Result<()> {
        let fcm = match &self.fcm {
            Some(f) => f,
            None => {
                tracing::debug!("FCM not configured, skipping push");
                return Ok(());
            }
        };

        let access_token = self.get_fcm_access_token(fcm).await?;

        let body = serde_json::json!({
            "message": {
                "token": device_token,
                "data": {
                    "type": "new_mail",
                    "queue_id": queue_id,
                    "sender": sender,
                    "subject": subject.unwrap_or(""),
                },
                "notification": {
                    "title": format!("New mail from {}", sender),
                    "body": subject.unwrap_or("New message received"),
                },
                "android": {
                    "priority": "high",
                },
            }
        });

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            fcm.project_id
        );

        let resp = self.http
            .post(&url)
            .bearer_auth(&access_token)
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            tracing::debug!("FCM push sent for queue_id={}", queue_id);
            Ok(())
        } else {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            // Don't fail the mail flow for push errors — log and continue
            tracing::warn!("FCM push failed ({}): {}", status, err_body);
            Ok(())
        }
    }

    /// Get a valid FCM access token, refreshing if expired.
    async fn get_fcm_access_token(&self, fcm: &FcmConfig) -> Result<String> {
        // Check cached token
        {
            let cached = fcm.token.read().await;
            if let Some(ref token) = *cached {
                if token.expires_at > std::time::Instant::now() {
                    return Ok(token.access_token.clone());
                }
            }
        }

        // Generate new token
        let now = chrono::Utc::now();
        let claims = serde_json::json!({
            "iss": fcm.client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now.timestamp(),
            "exp": now.timestamp() + 3600,
        });

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(fcm.private_key.as_bytes())?;
        let jwt = jsonwebtoken::encode(&header, &claims, &key)?;

        let resp = self.http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("FCM token exchange failed: {}", body);
        }

        let token_resp: TokenResponse = resp.json().await?;
        let access_token = token_resp.access_token.clone();

        // Cache the token (expire 5 min early to avoid edge cases)
        let mut cached = fcm.token.write().await;
        *cached = Some(CachedToken {
            access_token: token_resp.access_token,
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in.saturating_sub(300)),
        });

        Ok(access_token)
    }
}
