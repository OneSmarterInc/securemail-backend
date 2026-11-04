"""Explicitly regenerate public, synthetic OSM-v2 complete-envelope fixtures.

Run as `python -m scripts.generate_envelope_kats`. Never used by runtime code.
Review fixture diffs; normal tests only consume the frozen expected bytes.
"""

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.keyservice import protocol as p


def main():
    directory = Path(__file__).resolve().parents[1] / "backend/tests/vectors"
    source = json.loads((directory / "mlkem768.json").read_text())["vectors"][0]
    seed = bytes.fromhex(source["d"] + source["z"])
    raw = seed + bytes(range(32))
    pq, owner = p.private_keys(raw)
    kem = bytes.fromhex(source["ct"])
    shared = pq.decapsulate(kem)
    ephemeral = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    sx = ephemeral.exchange(owner.public_key())
    cases = []
    for index, plaintext in enumerate(
        (b"", b"Sara: synthetic confidential document", bytes(range(256)))
    ):
        context = (
            f"secure-mail:v1:organization=00000000-0000-4000-8000-000000000001:document=kat-{index}"
        )
        header = {
            "v": 2,
            "suite": p.SUITE,
            "key_id": "00000000-0000-4000-8000-000000000002",
            "kem": p.encode(kem),
            "ephemeral": p.encode(ephemeral.public_key().public_bytes_raw()),
        }
        nonce, content_nonce = (
            bytes(range(index, index + 12)),
            bytes(range(100 + index, 112 + index)),
        )
        dek = bytes(range(64 + index, 96 + index))
        kek = p.derive(shared, sx, header, context)
        wrapper = {
            **header,
            "wrap_nonce": p.encode(nonce),
            "key": p.encode(
                AESGCM(kek).encrypt(nonce, dek, p.canonical(header) + b"\0" + context.encode())
            ),
            "auth_v": 1,
        }
        wrapper["auth"] = p.encode(p.authenticate(wrapper, context, raw))
        envelope = {
            **wrapper,
            "nonce": p.encode(content_nonce),
            "data": p.encode(AESGCM(dek).encrypt(content_nonce, plaintext, context.encode())),
        }
        cases.append(
            {
                "name": f"complete-envelope-{index}",
                "context": context,
                "synthetic_recipient_material_hex": raw.hex(),
                "synthetic_ephemeral_scalar_hex": bytes(range(32, 64)).hex(),
                "plaintext_hex": plaintext.hex(),
                "expected_dek_hex": dek.hex(),
                "expected_wrap_key_hex": kek.hex(),
                "expected_pq_shared_hex": shared.hex(),
                "expected_x_shared_hex": sx.hex(),
                "envelope": envelope,
                "canonical_envelope_sha256": hashlib.sha256(p.canonical(envelope)).hexdigest(),
            }
        )
    output = {
        "notice": "PUBLIC SYNTHETIC TEST MATERIAL ONLY. Not independently verified by a separate team.",
        "suite": p.SUITE,
        "auth_v": 1,
        "primitive_vector_source": "mlkem768.json count " + source["count"],
        "vectors": cases,
    }
    (directory / "envelope_v2.json").write_text(
        json.dumps(output, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Wrote 3 public complete-envelope vectors; independent-team verification remains required."
    )


if __name__ == "__main__":
    main()
