# Fula Mail

Decentralized email gateway — SMTP interoperability with Fula's encrypted IPFS storage.

## Architecture

- **Inbound**: SMTP receive → encrypt (Path A: client-side, Path B: gateway fallback) → pin to IPFS
- **Outbound**: client submits → DKIM sign → SMTP relay (fire-and-forget, no plaintext stored)
- **Standard clients**: IMAP/JMAP via Stalwart (Path B encryption)
- **No private key custody**: gateway only uses public keys extracted from on-chain peer IDs

## Quick Start

```bash
cp .env.example .env
# Edit .env with your PostgreSQL credentials and JWT secret
docker-compose --profile dev up -d
```

## Custom Domain Setup

1. Register domain via API: `POST /api/v1/domains`
2. Get required DNS records: `GET /api/v1/domains/{domain}/dns-records`
3. Add DNS records at your registrar
4. Verify: `POST /api/v1/domains/{domain}/verify`

## Database

Connects to the **shared PostgreSQL instance** used by pinning-service and fula-api. Email-specific tables (`mail_domains`, `mail_addresses`, `mail_inbound_queue`, `mail_delivery_log`) are created alongside existing tables — no data duplication.
