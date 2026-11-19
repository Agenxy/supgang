#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Offline, owner-held Ed25519 recovery key for supgang-sign/v1 anchors. Apache-2.0.

A recovery key is the break-glass partner of a non-exportable vault signing key:
a verifier trusts both, so losing the Mac that holds the vault key does not stop
signing. The key lives only in a passphrase-sealed file on removable media that
the owner keeps offline. Nothing here touches the network or the vault.

  generate --label NAME --out FILE   create a key; prints only the public key
  public   --key FILE                show the public key and fingerprint
  sign     --key FILE --context C --sha256 HEX
                                     sign exactly what `supgang sign` signs

The seed is sealed with a one-time pad from scrypt (fresh salt per file) and
authenticated with HMAC-SHA-256. The Ed25519 code follows RFC 8032 section 6 and
uses only the standard library so the repository gate can test it offline. It is
not constant-time: run it only on the owner's own computer.
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys

FORMAT = "supgang-recovery-key/v1"
SIGN_DOMAIN = b"supgang-sign/v1\0"
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024
MAX_KEY_FILE_BYTES = 4096
MIN_PASSPHRASE = 12
NAME = re.compile(r"[a-z0-9._-]{1,64}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# RFC 8032 section 6 reference arithmetic.
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 % P == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
assert _GX is not None
G = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def _add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    big_a = (a[1] - a[0]) * (b[1] - b[0]) % P
    big_b = (a[1] + a[0]) * (b[1] + b[0]) % P
    big_c = 2 * a[3] * b[3] * D % P
    big_d = 2 * a[2] * b[2] % P
    e, f, g, h = big_b - big_a, big_d - big_c, big_d + big_c, big_b + big_a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _compress(point: tuple[int, int, int, int]) -> bytes:
    z_inverse = pow(point[2], P - 2, P)
    x = point[0] * z_inverse % P
    y = point[1] * z_inverse % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _small_order(point: tuple[int, int, int, int]) -> bool:
    # Reject every point in the curve's eight-element torsion subgroup.
    return _equal(_mul(8, point), IDENTITY)


def _hash_scalar(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % Q


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    """Return the RFC 8032 public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    scalar, _ = _expand(seed)
    return _compress(_mul(scalar, G))


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the RFC 8032 Ed25519 signature of message."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    scalar, prefix = _expand(seed)
    public = _compress(_mul(scalar, G))
    nonce = _hash_scalar(prefix + message)
    encoded_r = _compress(_mul(nonce, G))
    challenge = _hash_scalar(encoded_r + public + message)
    s = (nonce + challenge * scalar) % Q
    return encoded_r + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Check an RFC 8032 Ed25519 signature."""
    if len(public) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public)
    point_r = _decompress(signature[:32])
    if point_a is None or point_r is None or _small_order(point_a) or _small_order(point_r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    challenge = _hash_scalar(signature[:32] + public + message)
    return _equal(_mul(s, G), _add(point_r, _mul(challenge, point_a)))


def fingerprint(public: bytes) -> str:
    """Return the supgang-sign fingerprint: lowercase hex SHA-256 of the raw key."""
    return hashlib.sha256(public).hexdigest()


def framed_message(context: str, digest: bytes) -> bytes:
    """Return exactly the bytes `supgang sign` signs."""
    if not NAME.match(context):
        raise ValueError("context must be 1-64 of a-z, 0-9, '.', '_' or '-'")
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    return SIGN_DOMAIN + context.encode("ascii") + b"\0" + digest


def _derive(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    material = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=64,
    )
    return material[:32], material[32:]


def _authenticated(label: str, public: bytes, salt: bytes, sealed: bytes) -> bytes:
    params = f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}".encode("ascii")
    return b"\0".join([FORMAT.encode("ascii"), label.encode("ascii"), params, public, salt, sealed])


def seal(label: str, seed: bytes, passphrase: str, salt: bytes) -> dict[str, object]:
    """Return the key-file object for seed under passphrase."""
    if not NAME.match(label):
        raise ValueError("label must be 1-64 of a-z, 0-9, '.', '_' or '-'")
    if len(seed) != 32 or len(salt) != 32:
        raise ValueError("seed and salt must be 32 bytes")
    pad, mac_key = _derive(passphrase, salt)
    sealed = bytes(a ^ b for a, b in zip(seed, pad, strict=True))
    public = public_key(seed)
    mac = hmac.new(mac_key, _authenticated(label, public, salt, sealed), hashlib.sha256).digest()
    return {
        "format": FORMAT,
        "label": label,
        "public_key": public.hex(),
        "fingerprint": fingerprint(public),
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex()},
        "sealed_seed": sealed.hex(),
        "mac": mac.hex(),
    }


def _hex_field(document: dict[str, object], name: str, length: int) -> bytes:
    value = document.get(name)
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length * 2}}}", value):
        raise ValueError(f"key file field {name} is malformed")
    return bytes.fromhex(value)


def parse(document: object) -> tuple[str, bytes, bytes, bytes, bytes]:
    """Validate a key-file object; return label, public key, salt, sealed seed and MAC."""
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise ValueError("not a supgang recovery key file")
    label = document.get("label")
    if not isinstance(label, str) or not NAME.match(label):
        raise ValueError("key file label is malformed")
    kdf = document.get("kdf")
    if not isinstance(kdf, dict) or {k: kdf.get(k) for k in ("name", "n", "r", "p")} != {
        "name": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }:
        raise ValueError("key file KDF parameters are not the fixed v1 parameters")
    salt = _hex_field(kdf, "salt", 32)
    public = _hex_field(document, "public_key", 32)
    if document.get("fingerprint") != fingerprint(public):
        raise ValueError("key file fingerprint does not match its public key")
    return label, public, salt, _hex_field(document, "sealed_seed", 32), _hex_field(document, "mac", 32)


def unseal(document: object, passphrase: str) -> tuple[bytes, bytes]:
    """Return (seed, public key) after authenticating the file under passphrase."""
    label, public, salt, sealed, mac = parse(document)
    pad, mac_key = _derive(passphrase, salt)
    expected = hmac.new(mac_key, _authenticated(label, public, salt, sealed), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("wrong passphrase or altered key file")
    seed = bytes(a ^ b for a, b in zip(sealed, pad, strict=True))
    if public_key(seed) != public:
        raise ValueError("key file seed does not match its public key")
    return seed, public


def _read(path: Path) -> object:
    with path.open("rb") as handle:
        data = handle.read(MAX_KEY_FILE_BYTES + 1)
    if len(data) > MAX_KEY_FILE_BYTES:
        raise ValueError("key file is larger than any v1 key file")
    return json.loads(data)


def _require_terminal() -> None:
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise SystemExit("refusing: the passphrase must be typed at a terminal by the owner")


def _generate(arguments: argparse.Namespace) -> int:
    _require_terminal()
    if not NAME.match(arguments.label):
        raise SystemExit("label must be 1-64 of a-z, 0-9, '.', '_' or '-'")
    passphrase = getpass.getpass("New passphrase (at least 12 characters): ")
    if len(passphrase) < MIN_PASSPHRASE:
        raise SystemExit("passphrase is shorter than 12 characters")
    if getpass.getpass("Repeat passphrase: ") != passphrase:
        raise SystemExit("passphrases differ; nothing was written")
    document = seal(arguments.label, os.urandom(32), passphrase, os.urandom(32))
    encoded = (json.dumps(document, indent=2) + "\n").encode("ascii")
    descriptor = os.open(arguments.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    parent = os.open(arguments.out.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    print(f"label        {document['label']}")
    print(f"public key   {document['public_key']}")
    print(f"fingerprint  {document['fingerprint']}")
    return 0


def _public(arguments: argparse.Namespace) -> int:
    _, public, _, _, _ = parse(_read(arguments.key))
    print(f"public key   {public.hex()}")
    print(f"fingerprint  {fingerprint(public)}")
    print("(unauthenticated until a passphrase is used; compare with the fingerprint recorded at creation)")
    return 0


def _sign(arguments: argparse.Namespace) -> int:
    digest_hex = arguments.sha256.lower()
    if not HEX64.match(digest_hex):
        raise SystemExit("--sha256 must be exactly 64 hexadecimal characters")
    message = framed_message(arguments.context, bytes.fromhex(digest_hex))
    document = _read(arguments.key)
    parse(document)
    _require_terminal()
    seed, public = unseal(document, getpass.getpass("Recovery key passphrase: "))
    signature = sign(seed, message)
    if not verify(public, message, signature):
        raise SystemExit("internal error: signature failed self-verification")
    output = {
        "schema": "supgang.recovery-signature/v1",
        "status": "ok",
        "signature": signature.hex(),
        "fingerprint": fingerprint(public),
        "context": arguments.context,
        "message_sha256": digest_hex,
        "public_key": public.hex(),
    }
    print(json.dumps(output, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", help="create a sealed recovery key file")
    generate.add_argument("--label", required=True)
    generate.add_argument("--out", required=True, type=Path)
    public = commands.add_parser("public", help="show a key file's public key and fingerprint")
    public.add_argument("--key", required=True, type=Path)
    signer = commands.add_parser("sign", help="sign a supgang-sign/v1 frame")
    signer.add_argument("--key", required=True, type=Path)
    signer.add_argument("--context", required=True)
    signer.add_argument("--sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        return {"generate": _generate, "public": _public, "sign": _sign}[arguments.command](arguments)
    except (OSError, ValueError) as error:
        print(f"recovery_key: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
