# Provisioning

Provisioning happens only over USB, only in **provision mode**, and requires a
physical button press. Assume the provisioning machine is clean or airgapped:
anything it sends (key, policy) is trusted.

## Entering provision mode

The BOOT button is GPIO0. Holding it **during reset** enters the ESP32 ROM
download mode (for flashing), not provision mode. Instead:

- **At boot:** press BOOT while the LED blinks white (the first 3 s after reset), or
- **At runtime:** hold BOOT for 5 s. The device reboots into provision mode.

The LED turns solid blue. WiFi and HTTPS stay off. After 10 minutes with no
commands, the device reboots back to signer mode.

## Commands

```sh
esp32signer info --port /dev/cu.usbmodemXXXX
esp32signer provision --port ... [options]   # every option is optional; only what you pass is changed
esp32signer wipe --port ... --yes            # physically erases the signer partition
esp32signer reboot --port ...
```

`provision` options:

| Option | Effect |
|---|---|
| `--generate-key [--key-backup-file F]` | Key generated on-device from the hardware TRNG. **Printed once**, so back it up offline. |
| `--import-key-file F` | Import a 0x-hex private key (or a `private_key=` line) |
| `--force-key` | Allow replacing an existing key |
| `--policy P.yaml` | Compiled locally, then validated and compiled again on the device; the sha256 hashes are compared |
| `--wifi-ssid S --wifi-pass P` | WPA2 network to join |
| `--hostname NAME` | mDNS name, default `signer` → `signer.local` |
| `--cert C --tls-key K` | PEM server cert and key; the device checks they match and warns if the SAN lacks `<hostname>.local` |
| `--api-token T` / `--rotate-api-token` | Bearer token, at least 32 characters. If the device has none, one is generated and printed once. The device stores only its sha256. |

The device refuses to serve until it has all of: key, policy, WiFi, TLS and an API token.

## TLS certificates

```sh
esp32signer gen-cert --hostname signer --ca-dir certs/ca --out-dir certs [--ip 192.168.1.50]
```

This creates a local P-256 CA (`certs/ca/ca.pem`, reused on later runs) and a
825-day server certificate for `signer.local`. You can either trust the CA
system-wide, or pass it to clients (`verify="certs/ca/ca.pem"` in
requests/web3, `NODE_EXTRA_CA_CERTS` in Node). Keep `certs/ca/ca.key` offline.

## mDNS / Bonjour

The device answers for `<hostname>.local` and advertises `_https._tcp`, with TXT
records `path=/`, `fw=` and `addr=<signer address>`:

```sh
dns-sd -B _https._tcp        # macOS
avahi-browse -rt _https._tcp # Linux (needs avahi / nss-mdns to resolve .local)
```

The first `.local` lookup can take a while. The client keeps a keep-alive
connection, so later requests skip both the lookup and the TLS handshake.

## Protocol (for writing other tools)

The host sends one JSON object per line: `{"id":1,"cmd":"info"}`. The device
replies on one line prefixed with `@@`: `@@{"id":1,"ok":true,"result":{...}}`.
Lines without the prefix are logs. Commands: `info`, `generate_key {force}`,
`import_key {private_key, force}`, `set_policy {policy_b64}`,
`set_wifi {ssid, password}`, `set_hostname {hostname}`,
`set_tls {cert_pem_b64, key_pem_b64}`, `set_api_token {token}`,
`wipe {confirm:true}`, `reboot`.

Open the port with DTR and RTS deasserted. On the S3's USB Serial/JTAG they
emulate the auto-reset circuit, so asserting them resets the chip.
