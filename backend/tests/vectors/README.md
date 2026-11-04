# Public test vectors and provenance

`mlkem768.json` contains one selected entry (count 999) from PyCA's published ML-KEM-768 KAT file. The JSON records the exact upstream commit URL and SHA-256 of the complete source file. PyCA identifies the original KAT source as post-quantum-cryptography/KAT in its test-vector documentation. These are public synthetic keys, never production secrets.

Tests compare public-key derivation and both supplied decapsulation cases against the external expected bytes using Cryptography/OpenSSL and the separate kyber-py implementation. Additional fixed cases cover RFC 7748 section 6.1, RFC 5869 appendix A.1 and the zero-key/IV AES-256-GCM example. They are not a full ACVP validation suite.

Two-direction OSM-v2 wrapper interoperability uses a separately written test encoder/decoder, kyber-py 1.2.0 for ML-KEM and PyCryptodome 3.24.1 for X25519/HKDF/AES-GCM. Those dependencies live in `requirements-test.lock`, not the production dependency file. kyber-py is educational, non-constant-time and forbidden in runtime code. This is independent primitive implementation evidence, **not independently authored protocol review** or proof of hybrid-combiner security.

Sources: [PyCA test-vector provenance](https://github.com/pyca/cryptography/blob/main/docs/development/test-vectors.rst), [ML-KEM reference](https://github.com/GiacomoPope/kyber-py), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
