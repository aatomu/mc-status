# mc-status

Minecraft dummy client, \
status request by http

## How to Use

Run this repository with cloudflare worker

## Search params

- `address`: Server IP \*required
- `port`: Server Port
- `version`: Minecraft stable version
- `type`: Return document type (`html`/`json`)

## Example

- Request by address \
  `https://mc-status.aatomu.workers.dev/?address=example.com`
- Request by address & port \
  `https://mc-status.aatomu.workers.dev/?address=example.com&port=25567`
- Request by address & version \
  `https://mc-status.aatomu.workers.dev/?address=example.com&version=1.21.4`
