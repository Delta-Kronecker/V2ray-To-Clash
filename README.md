# V2Ray to Clash Converter

Convert v2ray/vless/trojan subscription links to Clash config automatically via GitHub Actions.

## Usage

1. **Fork** this repository
2. Go to **Actions** tab → **Convert V2Ray to Clash** → **Run workflow**
3. Paste your **v2ray subscription URL** and click **Run workflow**
4. Wait for the workflow to finish → download `clash_config.yaml` from the repository

## Supported Protocols

- vmess
- vless
- trojan
- shadowsocks (ss://)

## How It Works

1. The workflow fetches your subscription URL
2. Decodes the base64-encoded node list
3. Parses each URI and converts it to Clash proxy format
4. Generates `clash_config.yaml` with your Clash template
5. Commits the result to the repository

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
| `clash_config.yaml` | Generated Clash config (output) |
