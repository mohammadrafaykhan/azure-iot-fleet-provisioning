"""Fleet PKI tool.

    python -m pki root                                  root CA (keep its key offline)
    python -m pki intermediate devices                  intermediate CA for the enrollment group
    python -m pki device press-01 press-02 ...          device identities signed by 'devices'
    python -m pki device press-01 --rotate              new key and certificate, same device id
    python -m pki check press-01 press-02 ...           verify each device chain
    python -m pki der certs/root-ca.cert.pem            base64 DER, as Azure Resource Manager expects

Output goes to ./certs (gitignored) unless --dir is given.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pki.authority import Pki, PkiError, certificate_der_base64


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pki", description="Fleet X.509 PKI (ECDSA P-256).")
    parser.add_argument("--dir", type=Path, default=Path("certs"), help="certificate directory")
    sub = parser.add_subparsers(dest="command", required=True)

    root = sub.add_parser("root", help="create the root CA")
    root.add_argument("--cn", default="Fleet Root CA")
    root.add_argument("--force", action="store_true")

    intermediate = sub.add_parser("intermediate", help="create an intermediate CA signed by the root")
    intermediate.add_argument("name")
    intermediate.add_argument("--cn")
    intermediate.add_argument("--force", action="store_true")

    device = sub.add_parser("device", help="issue device identity certificates")
    device.add_argument("device_ids", nargs="+")
    device.add_argument("--issuer", default="devices", help="intermediate CA name (default: devices)")
    mode = device.add_mutually_exclusive_group()
    mode.add_argument("--rotate", action="store_true", help="archive the current identity and reissue")
    mode.add_argument("--force", action="store_true")

    check = sub.add_parser("check", help="verify device chains against the root")
    check.add_argument("device_ids", nargs="+")

    der = sub.add_parser("der", help="print a certificate as single-line base64 DER")
    der.add_argument("pem", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pki = Pki(args.dir)
    try:
        if args.command == "root":
            print(f"root CA: {pki.create_root(args.cn, args.force)}")
            print("keep root-ca.key.pem offline; it is needed only to issue intermediates")
        elif args.command == "intermediate":
            cn = args.cn or f"Fleet {args.name.title()} CA"
            print(f"intermediate CA: {pki.create_intermediate(args.name, cn, args.force)}")
        elif args.command == "device":
            for device_id in args.device_ids:
                chain = pki.issue_device(device_id, args.issuer, rotate=args.rotate, force=args.force)
                print(f"{device_id}: {chain}")
        elif args.command == "check":
            for device_id in args.device_ids:
                leaf = pki.check_device(device_id)
                print(f"{device_id}: ok, expires {leaf.not_valid_after_utc:%Y-%m-%d}")
        else:
            print(certificate_der_base64(args.pem))
    except (PkiError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
