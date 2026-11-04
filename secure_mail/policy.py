"""Apply only after sender authentication, using all envelope recipients.

Call once per outbound message with To, Cc and Bcc combined. Never trust a
user-supplied From header as authenticated_sender. This is not an SMTP gateway.
"""
from dataclasses import dataclass
import re

_NOPHI = re.compile(r'(?<![\w-])nophi(?![\w-])', re.IGNORECASE)
_ADDRESS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)", re.ASCII)

@dataclass(frozen=True)
class DeliveryDecision:
    protected: bool
    reason: str


def _domain(address: str) -> str:
    if not isinstance(address, str) or len(address) > 254:
        raise ValueError('Expected a single envelope mailbox address')
    match = _ADDRESS.fullmatch(address)
    if not match or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in match[1].split('.')):
        raise ValueError('Invalid envelope mailbox address')
    return match[1].lower()


def decide_delivery(*, authenticated_sender: str, recipients: list[str], subject: str,
                    secure_thread: bool = False, request_secure_information: bool = False,
                    company_domain: str = 'onesmarter.com', company_addresses: tuple[str, ...] = ()) -> DeliveryDecision:
    """Normal mail bypasses portal only; transport/storage encryption is separate.

Invalid inputs fail closed. Nophi is an explicit standalone subject word.
Secure requests and existing protected threads cannot be downgraded.
"""
    if secure_thread or request_secure_information:
        return DeliveryDecision(True, 'secure_conversation')
    if not isinstance(subject, str) or '\r' in subject or '\n' in subject:
        return DeliveryDecision(True, 'invalid_subject')
    if not isinstance(recipients, (list, tuple)) or not recipients:
        return DeliveryDecision(True, 'missing_recipients')
    try:
        domain = _domain('policy@' + company_domain)
        approved = {address.lower() for address in company_addresses}
        for address in approved:
            _domain(address)
        sender_domain = _domain(authenticated_sender)
        for recipient in recipients:
            _domain(recipient)
    except (ValueError, TypeError):
        return DeliveryDecision(True, 'invalid_address')
    if sender_domain != domain and authenticated_sender.lower() not in approved:
        return DeliveryDecision(True, 'sender_outside_company')
    if _NOPHI.search(subject):
        return DeliveryDecision(False, 'explicit_nophi_override')
    return DeliveryDecision(True, 'secure_default')
