"""Fail-closed hybrid TLS using public Python 3.15 / OpenSSL 3.5 APIs."""

import ssl

GROUP = "X25519MLKEM768"


def configure(context: ssl.SSLContext, *, required: bool) -> ssl.SSLContext:
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if required:
        if not hasattr(context, "set_groups") or not hasattr(ssl.SSLSocket, "group"):
            raise ValueError("PQ transport requires Python 3.15+ with hybrid-capable OpenSSL.")
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_groups(GROUP)
        # No PSK-only resumption or early data in this profile.
        context.options |= ssl.OP_NO_TICKET
    return context


def verify(sock: ssl.SSLSocket, *, required: bool) -> None:
    if required and (
        sock.version() != "TLSv1.3"
        or not hasattr(sock, "group")
        or sock.group() != GROUP
        or sock.session_reused
    ):
        raise ssl.SSLError("Required hybrid TLS negotiation was not verified.")


def client_context(ca: str, cert: str, key: str, *, required: bool) -> ssl.SSLContext:
    if not ca or not cert or not key:
        raise ValueError("A trusted CA and dedicated client certificate/key are required.")
    context = ssl.create_default_context(cafile=ca)
    context.load_cert_chain(cert, key)
    return configure(context, required=required)
