# MC Stress Console

Minecraft-aware async flood tool. Web dashboard + CLI.

## Run

    .\start.ps1

Then open http://localhost:8000

## Methods

| method | what it does |
|---|---|
| status | handshake + status request, reads full JSON response. Server must serialize MOTD + base64 favicon per hit. Highest value per packet. |
| handshake | handshake packet only. Cheap, allocates connection state before the app layer. |
| login | handshake + Login Start. Forces the server into the login phase, RSA/encryption path, and holds the slot. Heaviest Java method. |
| connect | raw TCP connect/close. Volume baseline. |
| mixed | rotates status / handshake / login. |
| bedrock | Bedrock unconnected ping flood (UDP 19132). |
| udp | random payload UDP flood. |
| udpmix | rotates bedrock ping / random UDP. |

## Expected numbers from a Codespace

1,000-5,000 pps, 5-40 Mbit. Enough for small vanilla/Paper servers. Not enough for Hypixel.

## Tuning

- `login` + `hold 2` with `concurrency 400` is the best small-server killer: slots fill and real players get kicked.
- `status` + `concurrency 800` gives max pps.
- Duration 300+ before judging results. Servers absorb the first 30s.
- SRV records are auto-resolved so you hit the real node, not the proxy front.