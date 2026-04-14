//! DNS verification and DKIM key management for custom domains.

use anyhow::Result;
use rsa::{pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, RsaPrivateKey};

use crate::handlers::DnsRecords;

/// Generate a 2048-bit RSA keypair for DKIM signing.
pub fn generate_dkim_keypair() -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = private_key.to_public_key();

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
        .to_string();

    let public_der = public_key.to_public_key_der()?;
    let public_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_der.as_bytes(),
    );

    Ok((private_pem, public_b64))
}

/// Generate the DNS records a user needs to add for their custom domain.
pub fn required_dns_records(
    domain: &str,
    mx_hostname: &str,
    dkim_public_b64: &str,
    dkim_selector: &str,
) -> DnsRecords {
    DnsRecords {
        mx: format!("{domain}. IN MX 10 {mx_hostname}."),
        spf: format!("{domain}. IN TXT \"v=spf1 include:{mx_hostname} -all\""),
        dkim: format!(
            "{dkim_selector}._domainkey.{domain}. IN TXT \"v=DKIM1; k=rsa; p={dkim_public_b64}\""
        ),
        dmarc: format!(
            "_dmarc.{domain}. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\""
        ),
    }
}

pub struct DnsVerification {
    pub mx: bool,
    pub spf: bool,
    pub dkim: bool,
    pub dmarc: bool,
}

/// Verify that a domain has the required DNS records configured.
pub async fn verify_domain_dns(
    domain: &str,
    expected_mx: &str,
    _expected_dkim_pubkey: &str,
    dkim_selector: &str,
) -> Result<DnsVerification> {
    use trust_dns_resolver::TokioAsyncResolver;
    use trust_dns_resolver::config::*;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Check MX
    let mx_verified = match resolver.mx_lookup(domain).await {
        Ok(mx) => mx.iter().any(|r| {
            r.exchange().to_string().trim_end_matches('.') == expected_mx.trim_end_matches('.')
        }),
        Err(_) => false,
    };

    // Check SPF (TXT record on domain)
    let spf_verified = match resolver.txt_lookup(domain).await {
        Ok(txt) => txt.iter().any(|r| {
            let text = r.to_string();
            text.contains("v=spf1") && text.contains(expected_mx)
        }),
        Err(_) => false,
    };

    // Check DKIM (TXT record on selector._domainkey.domain)
    let dkim_name = format!("{dkim_selector}._domainkey.{domain}");
    let dkim_verified = match resolver.txt_lookup(&dkim_name).await {
        Ok(txt) => txt.iter().any(|r| {
            let text = r.to_string();
            text.contains("v=DKIM1")
        }),
        Err(_) => false,
    };

    // Check DMARC (TXT record on _dmarc.domain)
    let dmarc_name = format!("_dmarc.{domain}");
    let dmarc_verified = match resolver.txt_lookup(&dmarc_name).await {
        Ok(txt) => txt.iter().any(|r| r.to_string().contains("v=DMARC1")),
        Err(_) => false,
    };

    Ok(DnsVerification {
        mx: mx_verified,
        spf: spf_verified,
        dkim: dkim_verified,
        dmarc: dmarc_verified,
    })
}
