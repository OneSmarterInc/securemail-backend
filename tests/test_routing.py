import unittest
from secure_mail import decide_delivery

class RoutingTests(unittest.TestCase):
    def route(self, **changes):
        args=dict(authenticated_sender='sender@onesmarter.com',recipients=['a@example.com'],subject='Hello')
        args.update(changes)
        return decide_delivery(**args)
    def test_external_default_protected(self):
        self.assertTrue(self.route().protected)
    def test_internal_only_protected(self):
        self.assertTrue(self.route(recipients=['a@OneSmarter.com','b@onesmarter.com']).protected)
    def test_mixed_and_lookalike_domains_protected(self):
        for recipient in ['b@example.com','b@onesmarter.com.evil.com','b@sub.onesmarter.com']:
            self.assertTrue(self.route(recipients=['a@onesmarter.com',recipient]).protected)
    def test_nophi_override(self):
        for subject in ['Nophi','[NOPHI] Documents','Update: nophi']:
            self.assertEqual(self.route(subject=subject).reason,'explicit_nophi_override')
    def test_partial_word_not_override(self):
        for subject in ['nonophi','Nophiology','no-nophi','Nophi_1']:
            self.assertTrue(self.route(subject=subject).protected)
    def test_secure_threads_never_downgrade(self):
        for flag in ['secure_thread','request_secure_information']:
            self.assertTrue(self.route(subject='Nophi',recipients=['a@onesmarter.com'],**{flag:True}).protected)
    def test_invalid_and_untrusted_sender_fail_closed(self):
        for change in [dict(recipients=[]),dict(recipients=['invalid']),dict(subject='Nophi\r\nBcc: x@evil.com'),dict(authenticated_sender='attacker@evil.com')]:
            args={'subject':'Nophi'};args.update(change)
            self.assertTrue(self.route(**args).protected)

