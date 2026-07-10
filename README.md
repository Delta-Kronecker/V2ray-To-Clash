# V2Ray to Clash Converter

Convert v2ray/vless/trojan subscription links to Clash config automatically via GitHub Actions.

## Usage

1. **Fork** this repository
2. **[Open a new Issue](../../issues/new?template=convert.yml)** and paste your subscription URL
3. Wait for the bot to reply with your Clash config link
4. Copy the raw link and import it in Clash

[![Convert](https://img.shields.io/badge/Convert-Subscription_to_Clash-blue?style=for-the-badge)](../../issues/new?template=convert.yml)

## Supported Protocols

- vmess
- vless
- trojan
- shadowsocks (ss://)

## How It Works

1. You open an Issue with your subscription URL
2. The workflow fetches your subscription
3. Decodes the base64-encoded node list
4. Parses each URI and converts it to Clash proxy format
5. Generates `clash_config.yaml` and commits it to the repo
6. Bot replies on the Issue with the download link and closes it

## Clash Config Features

- **Global mode** with automatic proxy selection
- **Fake-IP DNS** for better performance
- **TCP concurrent** connections
- **Chrome fingerprint** for all clients
- Automatic best-proxy selection via url-test

## Files

| File | Description |
|------|-------------|
| `convert.py` | Python script that handles the conversion |
| `.github/workflows/convert.yml` | GitHub Actions workflow |
| `.github/ISSUE_TEMPLATE/convert.yml` | Issue template for subscription input |
| `clash_config.yaml` | Generated Clash config (output) |
