# Hardening (release build)

> ⚠️ Every step here **burns eFuses and is irreversible**. Do it on a board you
> have already tested end-to-end with the development build. A mistake can
> permanently brick the board, or lock the firmware forever.

The development build (`sdkconfig.defaults`) leaves flash unencrypted and USB
download mode fully open. Anyone with USB access can dump the key or flash
malicious firmware. `sdkconfig.release` closes those holes:

| Feature | Config | Effect |
|---|---|---|
| Secure Boot v2 (RSA-3072) | `CONFIG_SECURE_BOOT_V2_ENABLED` | Only firmware signed with your offline key boots |
| Flash encryption (release) | `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE` | Flash contents are AES-XTS encrypted with an eFuse key that software can't read |
| Secure download mode | `CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE` | The ROM loader can't read flash, RAM or eFuses |
| Encrypted NVS (HMAC) | `CONFIG_NVS_ENCRYPTION`, `..._USING_HMAC`, key ID 1 | The signer partition is encrypted with keys derived from an eFuse HMAC key, generated and burned on first boot |
| JTAG disabled | `CONFIG_SECURE_BOOT_ALLOW_JTAG=n` | No debugger access |

## ⚠️ Firmware updates after hardening

In release mode with an on-device flash encryption key, **you can't update the
firmware over USB any more**: the ROM loader can't encrypt writes, and there is
no OTA. You have two choices:

- **Freeze the firmware (simplest, most secure).** To upgrade, provision a new
  board and move funds.
- **Host-generated flash encryption key.** Before the first boot, burn a key
  you generated (`espefuse.py burn_key BLOCK_KEY0 flash_key.bin XTS_AES_128_KEY`)
  and keep it **offline**. Updates are then built, signed, pre-encrypted with
  `espsecure.py encrypt_flash_data`, and written raw. Anyone holding that file
  plus the board can decrypt a flash dump, so protect it like the signer key.

Either way, the device can still be **erased** over USB, which is a denial of
service and wipes the signer key. Back up the key, or keep funds recoverable.

## Steps

```sh
. ~/esp/esp-idf/export.sh
cd firmware

# 1. Secure boot signing key: generate OFFLINE and back it up. Losing it means
#    no signed updates ever; leaking it means anyone can sign firmware.
mkdir -p ../keys && chmod 700 ../keys
espsecure.py generate_signing_key --version 2 --scheme rsa3072 ../keys/secure_boot_signing_key.pem

# 2. Build the release image
idf.py -B build-release -D SDKCONFIG=build-release/sdkconfig \
       -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.release" build

# 3. Flash the bootloader, then the partition table and app.
#    With Secure Boot v2 the bootloader isn't included in `flash`.
idf.py -B build-release -p /dev/cu.usbmodemXXXX bootloader-flash
idf.py -B build-release -p /dev/cu.usbmodemXXXX flash

# 4. First boot. DO NOT UNPLUG: the bootloader generates the flash encryption
#    key, encrypts flash in place, burns the secure boot digest, enables secure
#    download mode and disables JTAG. The app then burns the NVS HMAC key.
idf.py -B build-release -p /dev/cu.usbmodemXXXX monitor

# 5. Verify
espefuse.py -p /dev/cu.usbmodemXXXX summary   # SECURE_BOOT_EN, SPI_BOOT_CRYPT_CNT, ENABLE_SECURITY_DOWNLOAD, DIS_PAD_JTAG ...

# 6. Provision as usual (provision mode is unchanged).
```

Steps 3–4 follow the ESP-IDF v5.5 "Secure Boot v2" and "Flash Encryption"
guides. Re-read them for your exact chip revision before burning anything.
Large bootloaders need the partition table at `0x10000`, which
`sdkconfig.defaults` already sets.

## Operational recommendations

- Power the signer from a **USB charger**, not the trading machine. In signer
  mode it only needs WiFi.
- Put it on a VLAN or SSID that only the bot can reach.
- Record the signer address, policy sha256 (`esp32signer info`) and the
  firmware build hash. Check `signer_status` from the bot at startup and alert
  if the policy hash changes.
