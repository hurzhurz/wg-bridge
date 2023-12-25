# Wireguard Bridge
This is something like a relay server that can be used to connect multiple peers behind NAT, with dynamic IPs or different IP protocol versions.  
There is no Tunnel-in-Tunnel overhead and packets stay End-to-End encrypted. It also just needs to know public keys to function.

WARNING:  
This implementation is not very refinded.  
While the fordwarded data should be secure, it might be unreliable or could cause unknown other issues.  
Use at your own risk.

## Working Principle

This script opens a UDP socket and waits for Wireguard packets from any source.  
It forwards packets from one source to another depending on the sender/receiver index in the packet header.  
Sender/receiver pairs are learned from observing the Wireguard handshake.  
For authorization, who is allowed to use it and which peers are allowed to communicate with each other, the mac1 field of the packet header is checked against lists of given public keys.  
For the start of the handshake, when the exact destination is unknown, the initiation request is forwarded to all other sources who have also sent an initiation request for a public key of the same list (if there were already any).  
All other ongoing packets of the session are forwarded directly to the correct destination.

## Usage
Just run the script with one or more lists of public keys. Each list can contain 2 or more keys. For example:
```bash
python3 wg-bridge.py -h
usage: wg-bridge.py [-h] [--port PORT] --keys KEYS

Wireguard Bridge

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  Listen port (default 51820)
  --keys KEYS, -k KEYS  Comma-separated list of public keys that should be able to communicate with each other. Multiple lists are
                        possible and lists can overlap / have same keys.
```
```bash
# list with 3 keys
python3 wg-bridge.py --keys anVzdCBhbiBleGFtcGxlLCBkb24ndCB1c2UgdGhpcyE=,cmVhbGx5LCBpdCBpcyBwcmV0dHkgcG9pbnRsZXNzISE=,anVzdCB1c2UgeW91ciBvd24ga2V5cywgb2theT8/Pz8=
# 2 list with 2 keys each
python3 wg-bridge.py --keys anVzdCBhbiBleGFtcGxlLCBkb24ndCB1c2UgdGhpcyE=,cmVhbGx5LCBpdCBpcyBwcmV0dHkgcG9pbnRsZXNzISE= --keys anVzdCBhbiBleGFtcGxlLCBkb24ndCB1c2UgdGhpcyE=,anVzdCB1c2UgeW91ciBvd24ga2V5cywgb2theT8/Pz8=
```
### Wireguard Client Config
* Enable keepalive e.g. `PersistentKeepalive = 25`
* Set the `Endpoint` of each relevant peer, to IP and port the script listens on.  
  (Wireguard is able to use the same Endpoint address for multiple peers at the same time)

### Run script as docker container
Adjust and use the example docker-compose file or use it as reference.

### Run as systemd service
Edit script path and CLI parameters in example unit file (example.wg-bridge.service) and copy it to /etc/systemd/system/wg-bridge.service
```bash
systemctl daemon-reload
systemctl enable wg-bridge
systemctl start wg-bridge
```
