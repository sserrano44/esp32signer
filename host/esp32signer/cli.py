"""esp32signer command line tool.

USB (device must be in provision mode, solid blue LED):
    esp32signer info        --port /dev/cu.usbmodem1101
    esp32signer provision   --port ... [--generate-key | --import-key-file F] [--policy P.yaml]
                            [--wifi-ssid S --wifi-pass P] [--hostname signer]
                            [--cert signer.crt --tls-key signer.key] [--api-token T | --rotate-api-token]
    esp32signer wipe        --port ... --yes
    esp32signer reboot      --port ...

Offline:
    esp32signer gen-cert       --hostname signer --ca-dir certs/ca --out-dir certs [--ip 192.168.1.50]
    esp32signer compile-policy policies/x.yaml [-o x.json]
    esp32signer test-policy    policies/x.yaml txs.json [--self-address 0x...]

Network (signer mode):
    esp32signer status --url https://signer.local --ca certs/ca/ca.pem   (token from $SIGNER_TOKEN)
    esp32signer sign   --url ... tx.json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from pathlib import Path

from . import certs
from .policy_compiler import PolicyError, canonical_json, compile_policy, evaluate, policy_sha256


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _device(args):
    from .serial_proto import Device

    if not args.port:
        sys.exit("error: --port is required (e.g. /dev/cu.usbmodem1101)")
    return Device(args.port, verbose=args.verbose)


def _print_info(info: dict) -> None:
    print(json.dumps(info, indent=2))


def cmd_info(args) -> None:
    with _device(args) as d:
        _print_info(d.call("info"))


def cmd_provision(args) -> None:
    # Validate local inputs before touching the device.
    policy_json = None
    if args.policy:
        try:
            pol, warns = compile_policy(Path(args.policy).read_text())
        except PolicyError as e:
            sys.exit(f"policy error: {e}")
        for w in warns:
            print(f"warning: {w}", file=sys.stderr)
        policy_json = canonical_json(pol)
    if bool(args.cert) != bool(args.tls_key):
        sys.exit("error: --cert and --tls-key go together")
    if bool(args.wifi_ssid) != (args.wifi_pass is not None):
        sys.exit("error: --wifi-ssid and --wifi-pass go together (use --wifi-pass '' for open networks)")
    if args.generate_key and args.import_key_file:
        sys.exit("error: choose --generate-key or --import-key-file")
    if args.api_token and len(args.api_token) < 32:
        sys.exit("error: --api-token must be at least 32 characters")

    with _device(args) as d:
        info = d.call("info")
        print(f"device firmware {info.get('firmware')}, address {info.get('address', '(no key)')}")

        if args.generate_key:
            r = d.call("generate_key", force=args.force_key)
            print("\n" + "!" * 72)
            print("NEW SIGNER KEY. Back up this private key OFFLINE now; it is shown only once.")
            print(f"  address:     {r['address']}")
            print(f"  private key: {r['private_key']}")
            print("!" * 72 + "\n")
            if args.key_backup_file:
                fd = os.open(args.key_backup_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(f"address={r['address']}\nprivate_key={r['private_key']}\n")
                print(f"key backup written to {args.key_backup_file} (mode 600)")
        elif args.import_key_file:
            pk = Path(args.import_key_file).read_text().strip()
            if pk.startswith("private_key="):
                pk = pk.split("=", 1)[1]
            r = d.call("import_key", private_key=pk, force=args.force_key)
            print(f"imported key, address {r['address']}")

        if args.hostname:
            d.call("set_hostname", hostname=args.hostname)
            print(f"hostname set: {args.hostname}.local")
        if args.wifi_ssid:
            d.call("set_wifi", ssid=args.wifi_ssid, password=args.wifi_pass)
            print(f"wifi set: {args.wifi_ssid}")
        if args.cert:
            r = d.call("set_tls", cert_pem_b64=_b64(Path(args.cert).read_bytes()),
                       key_pem_b64=_b64(Path(args.tls_key).read_bytes()))
            print("tls certificate set" + (f" (WARNING: {r['warning']})" if r.get("warning") else ""))
        if policy_json is not None:
            r = d.call("set_policy", policy_b64=_b64(policy_json))
            expected = policy_sha256(json.loads(policy_json))
            if r["policy_sha256"] != expected:
                sys.exit(f"error: device policy hash {r['policy_sha256']} != local {expected}")
            print(f"policy set: sha256 {r['policy_sha256']} ({int(r['regex_instructions'])} regex instructions)")

        token = args.api_token
        if not token and (args.rotate_api_token or not info["provisioned"].get("api_token")):
            token = secrets.token_urlsafe(32)
            print("\nNEW API TOKEN (shown once; the device stores only its hash):")
            print(f"  {token}\n")
        if token:
            d.call("set_api_token", token=token)
            print("api token set")

        final = d.call("info")
        missing = [k for k, v in final["provisioned"].items() if not v]
        print("\nprovisioned:", ", ".join(k for k, v in final["provisioned"].items() if v) or "nothing")
        if missing:
            print("still missing:", ", ".join(missing))
        else:
            print(f"ready. Reboot (esp32signer reboot --port {args.port}) to start signing at "
                  f"https://{final['hostname']}.local/")


def cmd_wipe(args) -> None:
    if not args.yes:
        sys.exit("refusing to wipe without --yes (erases key, policy and all settings)")
    with _device(args) as d:
        d.call("wipe", confirm=True)
        print("device storage erased")


def cmd_reboot(args) -> None:
    with _device(args) as d:
        d.call("reboot")
        print("rebooting")


def cmd_gen_cert(args) -> None:
    paths = certs.make_server_cert(args.hostname, Path(args.out_dir), Path(args.ca_dir) if args.ca_dir else None,
                                   args.ip)
    for k, p in paths.items():
        print(f"{k:5s} {p}")
    if "ca" in paths:
        print(f"\nInstall {paths['ca']} as a trusted root on client machines, or pass it as --ca / verify=.")


def cmd_compile_policy(args) -> None:
    try:
        pol, warns = compile_policy(Path(args.policy).read_text())
    except PolicyError as e:
        sys.exit(f"policy error: {e}")
    for w in warns:
        print(f"warning: {w}", file=sys.stderr)
    data = canonical_json(pol)
    if args.output:
        Path(args.output).write_bytes(data)
    else:
        print(json.dumps(pol, indent=2))
    print(f"sha256 {policy_sha256(pol)}", file=sys.stderr)


def cmd_test_policy(args) -> None:
    try:
        pol, _ = compile_policy(Path(args.policy).read_text())
    except PolicyError as e:
        sys.exit(f"policy error: {e}")
    tx = json.loads(Path(args.tx).read_text())
    txs = tx if isinstance(tx, list) else [tx]
    bad = 0
    for i, t in enumerate(txs):
        ok, reason = evaluate(pol, t, args.self_address)
        bad += not ok
        print(f"[{i}] {'ALLOW' if ok else 'DENY '} {reason}")
    sys.exit(1 if bad else 0)


def _client(args):
    from .client import SignerClient

    token = args.token or os.environ.get("SIGNER_TOKEN")
    if not token:
        sys.exit("error: pass --token or set SIGNER_TOKEN")
    ca = args.ca if args.ca else (False if args.insecure else None)
    return SignerClient(args.url, token, ca=ca)


def cmd_status(args) -> None:
    print(json.dumps(_client(args).status(), indent=2))


def cmd_sign(args) -> None:
    from .client import SignerError

    tx = json.loads(Path(args.tx).read_text())
    try:
        print(_client(args).sign_transaction(tx))
    except SignerError as e:
        sys.exit(str(e))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="esp32signer", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true", help="show device log lines")
    sub = p.add_subparsers(dest="cmd", required=True)

    def usb(sp):
        sp.add_argument("--port", default=os.environ.get("SIGNER_PORT"), help="serial port (or $SIGNER_PORT)")
        return sp

    def net(sp):
        sp.add_argument("--url", default=os.environ.get("SIGNER_URL", "https://signer.local"))
        sp.add_argument("--token", help="API token (or $SIGNER_TOKEN)")
        sp.add_argument("--ca", default=os.environ.get("SIGNER_CA"), help="CA bundle to verify the device cert")
        sp.add_argument("--insecure", action="store_true", help="skip TLS verification (testing only)")
        return sp

    usb(sub.add_parser("info", help="show device provisioning state")).set_defaults(fn=cmd_info)

    sp = usb(sub.add_parser("provision", help="configure key, policy, wifi, tls, hostname, api token"))
    sp.add_argument("--generate-key", action="store_true", help="generate key on device (printed once for backup)")
    sp.add_argument("--key-backup-file", help="also write the generated key to this new file (mode 600)")
    sp.add_argument("--import-key-file", help="file containing a 0x private key")
    sp.add_argument("--force-key", action="store_true", help="replace an existing key")
    sp.add_argument("--policy", help="policy YAML")
    sp.add_argument("--wifi-ssid")
    sp.add_argument("--wifi-pass")
    sp.add_argument("--hostname", help="mDNS hostname (default 'signer' -> signer.local)")
    sp.add_argument("--cert", help="server certificate PEM")
    sp.add_argument("--tls-key", help="server private key PEM")
    sp.add_argument("--api-token", help="bearer token (>= 32 chars); auto-generated if the device has none")
    sp.add_argument("--rotate-api-token", action="store_true", help="generate and set a new token")
    sp.set_defaults(fn=cmd_provision)

    sp = usb(sub.add_parser("wipe", help="erase all device storage"))
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=cmd_wipe)
    usb(sub.add_parser("reboot", help="leave provision mode")).set_defaults(fn=cmd_reboot)

    sp = sub.add_parser("gen-cert", help="create a P-256 TLS cert for <hostname>.local")
    sp.add_argument("--hostname", default="signer")
    sp.add_argument("--ip", action="append", help="extra IP SAN (repeatable)")
    sp.add_argument("--ca-dir", help="create/reuse a local CA in this dir (recommended)")
    sp.add_argument("--out-dir", default="certs")
    sp.set_defaults(fn=cmd_gen_cert)

    sp = sub.add_parser("compile-policy", help="validate a policy YAML and print canonical JSON")
    sp.add_argument("policy")
    sp.add_argument("-o", "--output")
    sp.set_defaults(fn=cmd_compile_policy)

    sp = sub.add_parser("test-policy", help="evaluate tx JSON (object or list) against a policy offline")
    sp.add_argument("policy")
    sp.add_argument("tx")
    sp.add_argument("--self-address", help="signer address used for {{self}} macros")
    sp.set_defaults(fn=cmd_test_policy)

    net(sub.add_parser("status", help="signer_status over HTTPS")).set_defaults(fn=cmd_status)
    sp = net(sub.add_parser("sign", help="eth_signTransaction for a JSON tx file"))
    sp.add_argument("tx")
    sp.set_defaults(fn=cmd_sign)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
