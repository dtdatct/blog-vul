"""Regression tests for the jwt_vul HMAC/public-key confusion.

Reported as Code Audit finding 575cf6bc (audit 3c539c16), assessed at
cac4f0a2: ``jwt_vul`` chose the verifier from the untrusted token header
(``core/lib/jwt_vul/api.py:147``) and passed the caller's key to it with no
family check, so the app's own *published* RSA public key PEM
(``blogapp/key/pub.key``, embedded in the token header by
``blogapp/views/login.py:30``) was accepted as an HS256 shared secret.

The suite is deliberately standalone - standard library ``unittest`` only, no
Django and no pytest - because this repository pins an old dependency set.
``collections.Mapping`` is shimmed for Python 3.10+, as in the assessment.

Run from the repository root::

    python3 tests/test_jwt_vul_key_algorithm_binding.py
"""
import base64
import collections
import collections.abc
import hashlib
import hmac
import inspect
import json
import os
import sys
import unittest

if not hasattr(collections, 'Mapping'):          # Python 3.10 and later
    collections.Mapping = collections.abc.Mapping

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.lib.jwt_vul import algorithms, api  # noqa: E402
from core.lib.jwt_vul.exceptions import InvalidTokenError  # noqa: E402

PUBLIC_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'pub.key')
PRIVATE_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'priv.pem')

# prepare_key rejects PEM material with TypeError; the algorithm allowlist and
# signature/claim failures raise InvalidTokenError (DecodeError) subclasses;
# unparseable key material raises ValueError from the crypto backend.
REJECTION_ERRORS = (InvalidTokenError, TypeError, ValueError)

ATTACKER_PAYLOAD = {'username': 'attacker', 'admin': True}


def _read(path):
    with open(path, 'r') as handle:
        return handle.read()


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).replace(b'=', b'')


def forge_token(secret, algorithm='HS256', payload=None, header=None):
    """Hand-build a token signing with *secret* verbatim, bypassing the library.

    Signing by hand is what an attacker does: the library's own ``prepare_key``
    is the control under test, so the forge must not go through it.
    """
    header = dict(header or {})
    header.setdefault('typ', 'JWT')
    header['alg'] = algorithm
    payload = ATTACKER_PAYLOAD if payload is None else payload
    secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
    signing_input = b'.'.join([
        _b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        _b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8')),
    ])
    signature = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return signing_input + b'.' + _b64url(signature)


class PublishedPublicKeyIsNotAnHmacSecret(unittest.TestCase):
    """The demonstrated path: HTTP-derived key material plus a header-driven alg."""

    @classmethod
    def setUpClass(cls):
        cls.public_pem = _read(PUBLIC_KEY_PATH)

    def test_hs256_signed_with_published_public_pem_is_rejected(self):
        token = forge_token(self.public_pem,
                            header={'publickey': self.public_pem})
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, self.public_pem)

    def test_hs256_signed_with_published_public_pem_is_rejected_with_pinned_alg(self):
        # Shape of the fixed consumer call: jwt_vul.decode(cookie, server_key,
        # algorithms=["RS256"]). An HS256 token must not pass an RS256 pin.
        token = forge_token(self.public_pem,
                            header={'publickey': self.public_pem})
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, self.public_pem, algorithms=['RS256'])

    def test_encoded_public_pem_with_surrounding_text_is_rejected(self):
        # app-level headers carry the PEM inline; surrounding text must not hide it.
        disguised = '{"publickey": "%s"}' % self.public_pem.replace('\n', '\\n')
        token = forge_token(disguised)
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, disguised)

    def test_openssh_public_key_line_is_rejected_as_hmac_secret(self):
        openssh = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDexample attacker@host'
        token = forge_token(openssh)
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, openssh)

    def test_rs256_header_with_symmetric_secret_is_rejected(self):
        # The reverse direction: an asymmetric family must not accept an
        # opaque shared secret. Without the cryptography package the RSA
        # algorithm is simply not registered, which is also a rejection.
        token = forge_token('opaque-shared-secret', algorithm='RS256')
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, 'opaque-shared-secret')

    def test_rs256_header_with_symmetric_secret_is_rejected_with_crypto(self):
        # Same direction with the RSA class registered, so the rejection comes
        # from the asymmetric prepare_key and not from a missing algorithm.
        if not algorithms.has_crypto:
            self.skipTest('cryptography is not importable')
        token = forge_token('opaque-shared-secret', algorithm='RS256')
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, 'opaque-shared-secret')

    def test_none_algorithm_behaviour_is_recorded_not_conflated(self):
        # The separately registered 'none' algorithm (finding 80d3426d) is NOT
        # this finding's root cause and is deliberately unchanged here; this
        # records the current behaviour so the two stay distinguishable.
        token = forge_token(b'', algorithm='none')
        self.assertEqual(api.decode(token, 'any-key'), ATTACKER_PAYLOAD)


class LegitimateFlowsStillWork(unittest.TestCase):
    """Negative controls: the repair must not break correct usage."""

    def test_opaque_hs256_secret_round_trip(self):
        secret = 'correct-horse-battery-staple-0123456789'
        payload = {'username': 'bob', 'admin': False}
        token = api.encode(payload, secret)
        self.assertEqual(api.decode(token, secret), payload)

    def test_opaque_hs256_secret_round_trip_with_pinned_algorithm(self):
        secret = 'correct-horse-battery-staple-0123456789'
        token = api.encode({'username': 'bob'}, secret)
        self.assertEqual(api.decode(token, secret, algorithms=['HS256']),
                         {'username': 'bob'})

    def test_allowlist_is_an_explicit_part_of_the_decode_signature(self):
        # Pre-fix, jwt_vul.decode has no ``algorithms`` parameter at all, so a
        # caller cannot pin the expected algorithm and this call raises
        # TypeError. The parameter is the control being added.
        self.assertIn('algorithms',
                      inspect.signature(api.decode).parameters)
        self.assertIn('algorithms',
                      inspect.signature(api.verify_signature).parameters)

    def test_algorithm_allowlist_may_be_a_single_string(self):
        secret = 'correct-horse-battery-staple-0123456789'
        token = api.encode({'username': 'bob'}, secret)
        self.assertEqual(api.decode(token, secret, algorithms='HS256'),
                         {'username': 'bob'})

    def test_algorithm_allowlist_rejects_a_different_header_alg(self):
        secret = 'correct-horse-battery-staple-0123456789'
        token = api.encode({'username': 'bob'}, secret)
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, secret, algorithms=['HS512'])

    def test_wrong_secret_is_still_rejected(self):
        token = api.encode({'username': 'bob'}, 'the-right-secret')
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, 'the-wrong-secret')

    def test_secret_that_merely_looks_base64_is_still_accepted(self):
        # A blanket "looks like a key file" heuristic would be a regression.
        secret = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnhRcsiWmBFpeSqgV'
        token = api.encode({'username': 'bob'}, secret)
        self.assertEqual(api.decode(token, secret), {'username': 'bob'})


@unittest.skipUnless(algorithms.has_crypto,
                     'cryptography is not importable, so the RSA classes are '
                     'not registered')
class AsymmetricFlows(unittest.TestCase):
    """RS256 behaviour, including the app's own login -> setting round trip."""

    @classmethod
    def setUpClass(cls):
        cls.public_pem = _read(PUBLIC_KEY_PATH)
        cls.private_pem = _read(PRIVATE_KEY_PATH)

    def test_legitimate_rs256_round_trip(self):
        payload = {'username': 'bob', 'admin': False}
        token = api.encode(payload, self.private_pem, algorithm='RS256')
        self.assertEqual(api.decode(token, self.public_pem), payload)

    def test_app_shaped_login_to_setting_round_trip(self):
        # login.py mints RS256 with the PEM embedded in the header; the fixed
        # setting.py verifies with the server-side key pinned to RS256.
        payload = {'username': 'bob', 'admin': False}
        token = api.encode(payload, self.private_pem, algorithm='RS256',
                           headers={'publickey': self.public_pem})
        self.assertEqual(
            api.decode(token, self.public_pem, algorithms=['RS256']), payload)

    def test_private_key_is_not_accepted_as_a_verification_key(self):
        token = api.encode({'username': 'bob'}, self.private_pem,
                           algorithm='RS256')
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, self.private_pem)

    def test_loaded_asymmetric_key_cannot_be_reused_for_a_foreign_family(self):
        key_object = algorithms.RSAAlgorithm(
            algorithms.hashes.SHA256()).prepare_key(self.public_pem)
        algorithms.check_key_algorithm_binding(key_object, 'RS256')
        with self.assertRaises(REJECTION_ERRORS):
            algorithms.check_key_algorithm_binding(key_object, 'HS256')

    def test_pem_text_is_still_refused_even_when_it_parses_as_a_key(self):
        # A private PEM parses successfully, so only the family check stands
        # between it and an HS256 verification attempt.
        token = forge_token(self.private_pem, header={'publickey': self.private_pem})
        with self.assertRaises(REJECTION_ERRORS):
            api.decode(token, self.private_pem)


if __name__ == '__main__':
    unittest.main(verbosity=2)
